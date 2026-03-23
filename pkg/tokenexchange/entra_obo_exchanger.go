package tokenexchange

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/oauth2"
)

const (
	StrategyEntraOBO = "entra-obo"

	// Entra ID OBO-specific constants
	GrantTypeJWTBearer   = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	FormKeyAssertion     = "assertion"
	FormKeyRequestedUse  = "requested_token_use"
	RequestedTokenUseOBO = "on_behalf_of"
)

// entraOBOExchanger implements the Entra ID On-Behalf-Of flow.
// This is used when the MCP server needs to exchange a user's token for a token
// that can access downstream APIs (like Kubernetes) on behalf of that user.
//
// See: https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-on-behalf-of-flow
type entraOBOExchanger struct{}

var _ TokenExchanger = &entraOBOExchanger{}

func (e *entraOBOExchanger) Exchange(ctx context.Context, cfg *TargetTokenExchangeConfig, subjectToken string) (*oauth2.Token, error) {
	httpClient := http.DefaultClient
	if c, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok && c != nil {
		httpClient = c
	}

	data := url.Values{}
	data.Set(FormKeyGrantType, GrantTypeJWTBearer)
	data.Set(FormKeyAssertion, subjectToken)
	data.Set(FormKeyRequestedUse, RequestedTokenUseOBO)

	if cfg.Audience != "" {
		data.Set(FormKeyScope, cfg.Audience)
	}
	if len(cfg.Scopes) > 0 {
		data.Set(FormKeyScope, strings.Join(cfg.Scopes, " "))
	}

	headers := make(http.Header)
	injectClientAuth(cfg, data, headers)

	return doTokenExchange(ctx, httpClient, cfg.TokenURL, data, headers)
}
