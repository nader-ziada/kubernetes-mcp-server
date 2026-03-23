package kubernetes

import (
	"context"
	"net/http"
	"strings"

	"github.com/containers/kubernetes-mcp-server/pkg/api"
	"github.com/containers/kubernetes-mcp-server/pkg/tokenexchange"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"k8s.io/klog/v2"
)

func ExchangeTokenInContext(
	ctx context.Context,
	baseConfig api.BaseConfig,
	oidcProvider *oidc.Provider,
	httpClient *http.Client,
	provider Provider,
	target string,
) context.Context {
	auth, ok := ctx.Value(OAuthAuthorizationHeader).(string)
	if !ok || !strings.HasPrefix(auth, "Bearer ") {
		return ctx
	}
	subjectToken := strings.TrimPrefix(auth, "Bearer ")

	tep, ok := provider.(TokenExchangeProvider)
	if !ok {
		return stsExchangeTokenInContext(ctx, baseConfig, oidcProvider, httpClient, subjectToken)
	}

	exCfg := tep.GetTokenExchangeConfig(target)
	if exCfg == nil {
		return stsExchangeTokenInContext(ctx, baseConfig, oidcProvider, httpClient, subjectToken)
	}

	exchanger, ok := tokenexchange.GetTokenExchanger(tep.GetTokenExchangeStrategy())
	if !ok {
		klog.Warningf("token exchange strategy %q not found in registry", tep.GetTokenExchangeStrategy())
		return stsExchangeTokenInContext(ctx, baseConfig, oidcProvider, httpClient, subjectToken)
	}

	exchanged, err := exchanger.Exchange(ctx, exCfg, subjectToken)
	if err != nil {
		klog.Errorf("token exchange failed for target %q: %v", target, err)
		return ctx
	}
	return context.WithValue(ctx, OAuthAuthorizationHeader, "Bearer "+exchanged.AccessToken)
}

func stsExchangeTokenInContext(
	ctx context.Context,
	baseConfig api.BaseConfig,
	oidcProvider *oidc.Provider,
	httpClient *http.Client,
	token string,
) context.Context {
	// Determine cluster auth mode (explicit or auto-detected)
	mode := baseConfig.GetClusterAuthMode()
	if mode == "" {
		mode = detectClusterAuthMode(baseConfig)
	}

	switch mode {
	case api.ClusterAuthKubeconfig:
		// Use kubeconfig credentials, clear OAuth token
		return context.WithValue(ctx, OAuthAuthorizationHeader, "")

	case api.ClusterAuthPassthrough:
		// Pass through OAuth token, but exchange first if configured
		return passthroughWithOptionalExchange(ctx, baseConfig, oidcProvider, httpClient, token)

	default:
		// Unknown mode, pass through
		klog.Warningf("unknown cluster_auth_mode %q, passing through token", mode)
		return ctx
	}
}

// detectClusterAuthMode auto-detects the cluster auth mode based on config.
func detectClusterAuthMode(baseConfig api.BaseConfig) string {
	// If OAuth is required, default to passthrough
	if baseConfig.IsRequireOAuth() {
		return api.ClusterAuthPassthrough
	}
	// No OAuth required, use kubeconfig credentials
	return api.ClusterAuthKubeconfig
}

// passthroughWithOptionalExchange passes through the token, exchanging it first if configured.
func passthroughWithOptionalExchange(
	ctx context.Context,
	baseConfig api.BaseConfig,
	oidcProvider *oidc.Provider,
	httpClient *http.Client,
	token string,
) context.Context {
	// Check if a token exchange strategy is configured
	if strategy := baseConfig.GetStsStrategy(); strategy != "" {
		return strategyBasedTokenExchange(ctx, baseConfig, oidcProvider, httpClient, token, strategy)
	}

	// Check if built-in STS exchange is configured
	sts := NewFromConfig(baseConfig, oidcProvider)
	if sts.IsEnabled() {
		return builtinStsExchange(ctx, baseConfig, oidcProvider, httpClient, token)
	}

	// No exchange configured, pass through as-is
	return ctx
}

// builtinStsExchange performs the built-in RFC 8693 STS exchange.
func builtinStsExchange(
	ctx context.Context,
	baseConfig api.BaseConfig,
	oidcProvider *oidc.Provider,
	httpClient *http.Client,
	token string,
) context.Context {
	sts := NewFromConfig(baseConfig, oidcProvider)
	if !sts.IsEnabled() {
		klog.Warning("token-exchange mode configured but STS is not enabled, passing through token")
		return ctx
	}

	if httpClient != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)
	}

	exchangedToken, err := sts.ExternalAccountTokenExchange(ctx, &oauth2.Token{
		AccessToken: token,
		TokenType:   "Bearer",
	})
	if err != nil {
		klog.Errorf("token exchange failed: %v", err)
		return ctx
	}
	return context.WithValue(ctx, OAuthAuthorizationHeader, "Bearer "+exchangedToken.AccessToken)
}

func strategyBasedTokenExchange(
	ctx context.Context,
	baseConfig api.BaseConfig,
	oidcProvider *oidc.Provider,
	httpClient *http.Client,
	token string,
	strategy string,
) context.Context {
	exchanger, ok := tokenexchange.GetTokenExchanger(strategy)
	if !ok {
		klog.Warningf("token exchange strategy %q not found, passing through token", strategy)
		return ctx
	}

	// Build token URL from OIDC provider
	var tokenURL string
	if oidcProvider != nil {
		if endpoint := oidcProvider.Endpoint(); endpoint.TokenURL != "" {
			tokenURL = endpoint.TokenURL
		}
	}
	if tokenURL == "" {
		klog.Errorf("token exchange failed: no token URL available from OIDC provider")
		return ctx
	}

	cfg := &tokenexchange.TargetTokenExchangeConfig{
		TokenURL:     tokenURL,
		ClientID:     baseConfig.GetStsClientId(),
		ClientSecret: baseConfig.GetStsClientSecret(),
		Audience:     baseConfig.GetStsAudience(),
		Scopes:       baseConfig.GetStsScopes(),
		AuthStyle:    tokenexchange.AuthStyleParams,
	}

	if httpClient != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)
	}

	exchanged, err := exchanger.Exchange(ctx, cfg, token)
	if err != nil {
		klog.Errorf("token exchange failed with strategy %q: %v", strategy, err)
		return ctx
	}
	return context.WithValue(ctx, OAuthAuthorizationHeader, "Bearer "+exchanged.AccessToken)
}
