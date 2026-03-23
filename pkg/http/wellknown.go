package http

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/containers/kubernetes-mcp-server/pkg/config"
)

const maxWellKnownResponseSize = 1 << 20 // 1 MB
const oidcConfigCacheTTL = 5 * time.Minute

var allowedResponseHeaders = map[string]bool{
	"Cache-Control": true,
	"Date":          true,
	"Etag":          true,
	"Expires":       true,
	"Last-Modified": true,
	"Pragma":        true,
}

const (
	oauthAuthorizationServerEndpoint = "/.well-known/oauth-authorization-server"
	oauthProtectedResourceEndpoint   = "/.well-known/oauth-protected-resource"
	openIDConfigurationEndpoint      = "/.well-known/openid-configuration"
)

var WellKnownEndpoints = []string{
	oauthAuthorizationServerEndpoint,
	oauthProtectedResourceEndpoint,
	openIDConfigurationEndpoint,
}

// WellKnownMetadataGenerator generates well-known metadata when the upstream
// authorization server doesn't provide certain endpoints.
// This allows supporting OIDC providers that only implement openid-configuration.
type WellKnownMetadataGenerator interface {
	// GenerateAuthorizationServerMetadata generates oauth-authorization-server metadata
	// from the openid-configuration. Returns nil if generation is not possible.
	GenerateAuthorizationServerMetadata(oidcConfig map[string]interface{}) map[string]interface{}

	// GenerateProtectedResourceMetadata generates oauth-protected-resource metadata (RFC 9728)
	// for the MCP server. The resourceURL is the canonical URL of the MCP server.
	GenerateProtectedResourceMetadata(oidcConfig map[string]interface{}, resourceURL, authorizationServerURL string) map[string]interface{}
}

// DefaultMetadataGenerator provides standard metadata generation for OIDC providers
// that only implement openid-configuration (e.g., Entra ID, Auth0, etc.)
type DefaultMetadataGenerator struct{}

// GenerateAuthorizationServerMetadata returns the openid-configuration as-is,
// since it contains the required OAuth 2.0 Authorization Server Metadata fields.
func (g *DefaultMetadataGenerator) GenerateAuthorizationServerMetadata(oidcConfig map[string]interface{}) map[string]interface{} {
	return oidcConfig
}

// GenerateProtectedResourceMetadata generates RFC 9728 compliant metadata
// for the MCP server acting as an OAuth 2.0 protected resource.
// - resourceURL is unused (kept for interface compatibility)
// - authorizationServerURL is the MCP server URL where OAuth metadata can be fetched
func (g *DefaultMetadataGenerator) GenerateProtectedResourceMetadata(oidcConfig map[string]interface{}, resourceURL, authorizationServerURL string) map[string]interface{} {
	metadata := map[string]interface{}{
		"authorization_servers": []string{authorizationServerURL},
	}

	// Copy relevant fields from openid-configuration
	if scopes, ok := oidcConfig["scopes_supported"]; ok {
		metadata["scopes_supported"] = scopes
	}
	if bearerMethods, ok := oidcConfig["token_endpoint_auth_methods_supported"]; ok {
		metadata["bearer_methods_supported"] = bearerMethods
	}

	return metadata
}

type WellKnown struct {
	authorizationUrl                 string
	scopesSupported                  []string
	disableDynamicClientRegistration bool
	httpClient                       *http.Client
	metadataGenerator                WellKnownMetadataGenerator
	// Cache for openid-configuration to avoid repeated fetches (TTL: oidcConfigCacheTTL)
	oidcConfigCache     map[string]interface{}
	oidcConfigCacheTime time.Time
	oidcConfigCacheLock sync.RWMutex
}

var _ http.Handler = &WellKnown{}

func WellKnownHandler(staticConfig *config.StaticConfig, httpClient *http.Client) http.Handler {
	return WellKnownHandlerWithGenerator(staticConfig, httpClient, &DefaultMetadataGenerator{})
}

// WellKnownHandlerWithGenerator creates a WellKnown handler with a custom metadata generator.
// This allows customizing how metadata is generated for different OIDC providers.
func WellKnownHandlerWithGenerator(staticConfig *config.StaticConfig, httpClient *http.Client, generator WellKnownMetadataGenerator) http.Handler {
	authorizationUrl := staticConfig.AuthorizationURL
	if authorizationUrl != "" && strings.HasSuffix(authorizationUrl, "/") {
		authorizationUrl = strings.TrimSuffix(authorizationUrl, "/")
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	if generator == nil {
		generator = &DefaultMetadataGenerator{}
	}
	return &WellKnown{
		authorizationUrl:                 authorizationUrl,
		disableDynamicClientRegistration: staticConfig.DisableDynamicClientRegistration,
		scopesSupported:                  staticConfig.OAuthScopes,
		httpClient:                       httpClient,
		metadataGenerator:                generator,
	}
}

func (w *WellKnown) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if w.authorizationUrl == "" {
		http.Error(writer, "Authorization URL is not configured", http.StatusNotFound)
		return
	}

	requestPath := request.URL.EscapedPath()

	// Validate the URL path to prevent path traversal
	upstreamURL, err := url.JoinPath(w.authorizationUrl, requestPath)
	if err != nil || !strings.HasPrefix(upstreamURL, w.authorizationUrl+"/") {
		http.Error(writer, "Invalid well-known path", http.StatusBadRequest)
		return
	}

	// Try direct proxy first (works for Keycloak and other providers that support all endpoints)
	resourceMetadata, respHeaders, err := w.fetchWellKnownEndpoint(request, upstreamURL)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}

	// If direct fetch returned nil (404), generate metadata using the configured generator.
	// This provides fallback support for OIDC providers that only implement openid-configuration.
	// Use prefix matching to handle paths like /.well-known/oauth-protected-resource/sse
	if resourceMetadata == nil {
		switch {
		case strings.HasPrefix(requestPath, oauthAuthorizationServerEndpoint):
			resourceMetadata, err = w.generateAuthorizationServerMetadata(request)
			if err != nil {
				http.Error(writer, err.Error(), http.StatusInternalServerError)
				return
			}
			respHeaders = nil
		case strings.HasPrefix(requestPath, oauthProtectedResourceEndpoint):
			resourceMetadata, err = w.generateProtectedResourceMetadata(request)
			if err != nil {
				http.Error(writer, err.Error(), http.StatusInternalServerError)
				return
			}
			respHeaders = nil
		}
		if resourceMetadata == nil {
			http.Error(writer, "Failed to fetch well-known metadata", http.StatusNotFound)
			return
		}
	}

	w.applyConfigOverrides(resourceMetadata)

	body, err := json.Marshal(resourceMetadata)
	if err != nil {
		http.Error(writer, "Failed to marshal response body: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Copy allowed headers from backend response if available
	for key, values := range respHeaders {
		if !allowedResponseHeaders[http.CanonicalHeaderKey(key)] {
			continue
		}
		for _, value := range values {
			writer.Header().Add(key, value)
		}
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
	withCORSHeaders(writer)
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(body)
}

// fetchWellKnownEndpoint fetches a well-known endpoint and returns the parsed JSON.
// Returns nil metadata if the endpoint returns 404 (to allow fallback).
func (w *WellKnown) fetchWellKnownEndpoint(request *http.Request, url string) (map[string]interface{}, http.Header, error) {
	req, err := http.NewRequest(request.Method, url, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create request: %w", err)
	}
	resp, err := w.httpClient.Do(req.WithContext(request.Context()))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to perform request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Return nil for 404 to trigger fallback
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil, nil
	}

	var resourceMetadata map[string]interface{}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxWellKnownResponseSize)).Decode(&resourceMetadata); err != nil {
		return nil, nil, fmt.Errorf("failed to read response body: %w", err)
	}

	return resourceMetadata, resp.Header, nil
}

// fetchOpenIDConfiguration fetches and caches the openid-configuration from the authorization server.
func (w *WellKnown) fetchOpenIDConfiguration(request *http.Request) (map[string]interface{}, error) {
	// Check cache first (with TTL)
	w.oidcConfigCacheLock.RLock()
	if w.oidcConfigCache != nil && time.Since(w.oidcConfigCacheTime) < oidcConfigCacheTTL {
		result := copyMap(w.oidcConfigCache)
		w.oidcConfigCacheLock.RUnlock()
		return result, nil
	}
	w.oidcConfigCacheLock.RUnlock()

	// Fetch openid-configuration
	oidcURL := w.authorizationUrl + openIDConfigurationEndpoint
	oidcConfig, _, err := w.fetchWellKnownEndpoint(request, oidcURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch openid-configuration: %w", err)
	}
	if oidcConfig == nil {
		return nil, nil
	}

	// Cache the result with timestamp
	w.oidcConfigCacheLock.Lock()
	w.oidcConfigCache = copyMap(oidcConfig)
	w.oidcConfigCacheTime = time.Now()
	w.oidcConfigCacheLock.Unlock()

	return oidcConfig, nil
}

// generateAuthorizationServerMetadata generates oauth-authorization-server metadata
// using the configured metadata generator and the fetched openid-configuration.
func (w *WellKnown) generateAuthorizationServerMetadata(request *http.Request) (map[string]interface{}, error) {
	oidcConfig, err := w.fetchOpenIDConfiguration(request)
	if err != nil {
		return nil, err
	}
	if oidcConfig == nil {
		return nil, nil
	}
	return w.metadataGenerator.GenerateAuthorizationServerMetadata(oidcConfig), nil
}

// generateProtectedResourceMetadata generates oauth-protected-resource metadata (RFC 9728)
// using the configured metadata generator.
func (w *WellKnown) generateProtectedResourceMetadata(request *http.Request) (map[string]interface{}, error) {
	oidcConfig, err := w.fetchOpenIDConfiguration(request)
	if err != nil {
		return nil, err
	}
	if oidcConfig == nil {
		return nil, nil
	}

	// MCP server URL - where OAuth metadata can be fetched
	mcpServerURL := w.buildResourceURL(request)
	return w.metadataGenerator.GenerateProtectedResourceMetadata(oidcConfig, "", mcpServerURL), nil
}

// buildResourceURL constructs the canonical resource URL from the incoming request.
func (w *WellKnown) buildResourceURL(request *http.Request) string {
	scheme := "https"
	if request.TLS == nil && !strings.HasPrefix(request.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "http"
	}
	host := request.Host
	if fwdHost := request.Header.Get("X-Forwarded-Host"); fwdHost != "" {
		host = fwdHost
	}
	return fmt.Sprintf("%s://%s", scheme, host)
}

// applyConfigOverrides applies server configuration overrides to the metadata.
func (w *WellKnown) applyConfigOverrides(resourceMetadata map[string]interface{}) {
	if w.disableDynamicClientRegistration {
		delete(resourceMetadata, "registration_endpoint")
		resourceMetadata["require_request_uri_registration"] = false
	}
	if len(w.scopesSupported) > 0 {
		resourceMetadata["scopes_supported"] = w.scopesSupported
	}
}

// copyMap creates a shallow copy of the map. Nested maps/slices share the same
// underlying data. This is acceptable for OIDC config which is read-only after fetch.
func copyMap(src map[string]interface{}) map[string]interface{} {
	dst := make(map[string]interface{}, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func withCORSHeaders(writer http.ResponseWriter) {
	writer.Header().Set("Access-Control-Allow-Origin", "*")
	writer.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
}
