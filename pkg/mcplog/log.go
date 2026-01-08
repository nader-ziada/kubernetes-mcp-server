package mcplog

import (
	"context"
	"regexp"

	"github.com/go-logr/logr"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"k8s.io/klog/v2"
)

// ContextKey is a type for context keys to avoid collisions
type ContextKey string

// MCPSessionContextKey is the context key for storing MCP ServerSession
const MCPSessionContextKey = ContextKey("mcp_session")

var (
	// mcpLogger is a dedicated named logger for MCP client-facing logs
	// This provides complete separation from server logs
	mcpLogger logr.Logger = klog.NewKlogr().WithName("mcp")

	// Patterns for redacting sensitive data from industry-standard secret detection tools
	sensitivePatterns = []*regexp.Regexp{
		// Generic JSON/YAML fields
		regexp.MustCompile(`("password"\s*:\s*)"[^"]*"`),
		regexp.MustCompile(`("token"\s*:\s*)"[^"]*"`),
		regexp.MustCompile(`("secret"\s*:\s*)"[^"]*"`),
		regexp.MustCompile(`("api[_-]?key"\s*:\s*)"[^"]*"`),
		regexp.MustCompile(`("access[_-]?key"\s*:\s*)"[^"]*"`),
		regexp.MustCompile(`("client[_-]?secret"\s*:\s*)"[^"]*"`),
		regexp.MustCompile(`("private[_-]?key"\s*:\s*)"[^"]*"`),
		// Authorization headers
		regexp.MustCompile(`(Bearer\s+)[A-Za-z0-9\-._~+/]+=*`),
		regexp.MustCompile(`(Basic\s+)[A-Za-z0-9+/]+=*`),
		// AWS credentials
		regexp.MustCompile(`(AKIA[0-9A-Z]{16})`),
		regexp.MustCompile(`(aws_secret_access_key\s*=\s*)([A-Za-z0-9/+=]{40})`),
		regexp.MustCompile(`(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`),
		// GitHub tokens
		regexp.MustCompile(`(ghp_[a-zA-Z0-9]{36})`),
		regexp.MustCompile(`(github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})`),
		// GitLab tokens
		regexp.MustCompile(`(glpat-[a-zA-Z0-9\-_]{20})`),
		// GCP
		regexp.MustCompile(`(AIza[0-9A-Za-z\-_]{35})`),
		// Azure
		regexp.MustCompile(`(AccountKey=[A-Za-z0-9+/]{88}==)`),
		// OpenAI / Anthropic
		regexp.MustCompile(`(sk-proj-[a-zA-Z0-9]{48})`),
		regexp.MustCompile(`(sk-ant-api03-[a-zA-Z0-9\-_]{95})`),
		// JWT tokens
		regexp.MustCompile(`(eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)`),
		// Private keys
		regexp.MustCompile(`(-----BEGIN[A-Z ]+PRIVATE KEY-----)`),
		regexp.MustCompile(`(-----BEGIN RSA PRIVATE KEY-----)`),
		regexp.MustCompile(`(-----BEGIN EC PRIVATE KEY-----)`),
		regexp.MustCompile(`(-----BEGIN OPENSSH PRIVATE KEY-----)`),
		regexp.MustCompile(`(-----BEGIN PGP PRIVATE KEY BLOCK-----)`),
		// Database connection strings
		regexp.MustCompile(`(postgres://[^:]+:)([^@]+)(@)`),
		regexp.MustCompile(`(mysql://[^:]+:)([^@]+)(@)`),
		regexp.MustCompile(`(mongodb(\+srv)?://[^:]+:)([^@]+)(@)`),
	}
)

func sanitizeMessage(msg string) string {
	// JSON/YAML field patterns (indices 0-6) - preserve field name
	for i := 0; i < 7 && i < len(sensitivePatterns); i++ {
		msg = sensitivePatterns[i].ReplaceAllString(msg, `$1"[REDACTED]"`)
	}

	// Authorization headers (indices 7-8) - preserve header type
	for i := 7; i < 9 && i < len(sensitivePatterns); i++ {
		msg = sensitivePatterns[i].ReplaceAllString(msg, `$1[REDACTED]`)
	}

	// Database connection strings (indices 25-27) - preserve URL structure
	if len(sensitivePatterns) > 27 {
		msg = sensitivePatterns[25].ReplaceAllString(msg, `$1[REDACTED]$3`) // PostgreSQL
		msg = sensitivePatterns[26].ReplaceAllString(msg, `$1[REDACTED]$3`) // MySQL
		msg = sensitivePatterns[27].ReplaceAllString(msg, `$1[REDACTED]$4`) // MongoDB
	}

	// All other patterns (AWS, GitHub, tokens, keys, etc.) - redact entire match
	for i := 9; i < len(sensitivePatterns); i++ {
		// Skip database patterns (already handled)
		if i >= 25 && i <= 27 {
			continue
		}
		msg = sensitivePatterns[i].ReplaceAllString(msg, `[REDACTED]`)
	}

	return msg
}

// SendMCPLog sends a log notification to the MCP client and server logs.
// Uses dedicated "mcp" named logger. Message is automatically sanitized.
// Level: "debug", "info", "notice", "warning", "error", "critical", "alert", "emergency"
func SendMCPLog(ctx context.Context, level, message string) {
	switch level {
	case "error", "critical", "alert", "emergency":
		mcpLogger.Error(nil, message)
	case "warning", "notice":
		mcpLogger.V(1).Info(message)
	default:
		mcpLogger.V(2).Info(message)
	}

	session, ok := ctx.Value(MCPSessionContextKey).(*mcp.ServerSession)
	if !ok || session == nil {
		return
	}

	message = sanitizeMessage(message)

	_ = session.Log(ctx, &mcp.LoggingMessageParams{
		Level:  mcp.LoggingLevel(level),
		Logger: "kubernetes-mcp-server",
		Data:   message,
	})
}
