package mcp

import (
	"bytes"
	"context"
	"fmt"
	"slices"

	internalk8s "github.com/containers/kubernetes-mcp-server/pkg/kubernetes"
	"github.com/containers/kubernetes-mcp-server/pkg/mcplog"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"k8s.io/klog/v2"
)

func authHeaderPropagationMiddleware(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		if req.GetExtra() != nil && req.GetExtra().Header != nil {
			// Get the standard Authorization header (OAuth compliant)
			authHeader := req.GetExtra().Header.Get(string(internalk8s.OAuthAuthorizationHeader))
			if authHeader != "" {
				return next(context.WithValue(ctx, internalk8s.OAuthAuthorizationHeader, authHeader), method, req)
			}

			// Fallback to custom header for backward compatibility
			customAuthHeader := req.GetExtra().Header.Get(string(internalk8s.CustomAuthorizationHeader))
			if customAuthHeader != "" {
				return next(context.WithValue(ctx, internalk8s.OAuthAuthorizationHeader, customAuthHeader), method, req)
			}
		}
		return next(ctx, method, req)
	}
}

func toolCallLoggingMiddleware(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		switch params := req.GetParams().(type) {
		case *mcp.CallToolParamsRaw:
			toolCallRequest, _ := GoSdkToolCallParamsToToolCallRequest(params)
			klog.V(5).Infof("mcp tool call: %s(%v)", toolCallRequest.Name, toolCallRequest.GetArguments())
			if req.GetExtra() != nil && req.GetExtra().Header != nil {
				buffer := bytes.NewBuffer(make([]byte, 0))
				if err := req.GetExtra().Header.WriteSubset(buffer, map[string]bool{"Authorization": true, "authorization": true}); err == nil {
					klog.V(7).Infof("mcp tool call headers: %s", buffer)
				}
			}
		}
		return next(ctx, method, req)
	}
}

func toolScopedAuthorizationMiddleware(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		scopes, ok := ctx.Value(TokenScopesContextKey).([]string)
		if !ok {
			klog.V(2).Infof("Authorization failed for %s: no scopes in context", method)
			mcplog.SendMCPLog(ctx, "error", "Authentication failed")
			return NewTextResult("", fmt.Errorf("authorization failed: Access denied: Tool '%s' requires scope 'mcp:%s' but no scope is available", method, method)), nil
		}
		if !slices.Contains(scopes, "mcp:"+method) && !slices.Contains(scopes, method) {
			klog.V(2).Infof("Authorization failed for %s: insufficient scopes (have: %v, need: mcp:%s)", method, scopes, method)
			mcplog.SendMCPLog(ctx, "error", "Insufficient permissions for this operation")
			return NewTextResult("", fmt.Errorf("authorization failed: Access denied: Tool '%s' requires scope 'mcp:%s' but only scopes %s are available", method, method, scopes)), nil
		}
		return next(ctx, method, req)
	}
}
