package mcplog

import (
	"context"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

// HandleK8sError sends appropriate MCP log messages based on Kubernetes API error types.
// operation should describe the operation (e.g., "pod access", "deployment deletion").
func HandleK8sError(ctx context.Context, err error, operation string) {
	if err == nil {
		return
	}

	if apierrors.IsNotFound(err) {
		SendMCPLog(ctx, "info", "Resource not found - it may not exist or may have been deleted")
	} else if apierrors.IsForbidden(err) {
		SendMCPLog(ctx, "error", "Permission denied - check RBAC permissions for "+operation)
	} else if apierrors.IsUnauthorized(err) {
		SendMCPLog(ctx, "error", "Authentication failed - check cluster credentials")
	} else if apierrors.IsAlreadyExists(err) {
		SendMCPLog(ctx, "warning", "Resource already exists")
	} else if apierrors.IsInvalid(err) {
		SendMCPLog(ctx, "error", "Invalid resource specification - check resource definition")
	} else if apierrors.IsBadRequest(err) {
		SendMCPLog(ctx, "error", "Invalid request - check parameters")
	} else if apierrors.IsConflict(err) {
		SendMCPLog(ctx, "error", "Resource conflict - resource may have been modified")
	} else if apierrors.IsTimeout(err) {
		SendMCPLog(ctx, "error", "Request timeout - cluster may be slow or overloaded")
	} else if apierrors.IsServerTimeout(err) {
		SendMCPLog(ctx, "error", "Server timeout - cluster may be slow or overloaded")
	} else if apierrors.IsServiceUnavailable(err) {
		SendMCPLog(ctx, "error", "Service unavailable - cluster may be unreachable")
	} else if apierrors.IsTooManyRequests(err) {
		SendMCPLog(ctx, "warning", "Rate limited - too many requests to the cluster")
	} else {
		SendMCPLog(ctx, "error", "Operation failed - cluster may be unreachable or experiencing issues")
	}
}
