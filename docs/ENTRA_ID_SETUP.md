# Microsoft Entra ID Setup for Kubernetes MCP Server

This guide shows you how to configure the Kubernetes MCP Server to use Microsoft Entra ID (formerly Azure AD) as the OIDC provider.

## Overview

Entra ID differs from Keycloak in that it only exposes the standard OpenID Connect discovery endpoint (`/.well-known/openid-configuration`) and does not implement the OAuth Authorization Server Metadata endpoints (`/.well-known/oauth-authorization-server`).

The MCP server automatically handles this by falling back to `openid-configuration` when the OAuth-specific endpoints return 404.

## Prerequisites

- Microsoft Entra ID admin access (Azure Portal)
- Kubernetes cluster configured with Entra ID as the OIDC provider
- `kubectl` CLI with cluster access

## Step 1: Register an App in Entra ID

### Create the App Registration

1. Go to **Azure Portal** → **Microsoft Entra ID** → **App registrations**
2. Click **New registration**
3. Fill in:
   - **Name:** `MCP Server` (or any name)
   - **Supported account types:** "Accounts in this organizational directory only"
   - **Redirect URI:** Leave blank for now
4. Click **Register**

### Note Your IDs

From the app's **Overview** page, copy:
- **Application (client) ID** → `CLIENT_ID`
- **Directory (tenant) ID** → `TENANT_ID`

### Create Client Secret

1. Go to **Certificates & secrets** (left sidebar)
2. Click **New client secret**
3. Add description and expiration
4. Click **Add**
5. **Copy the Value immediately** (only shown once) → `CLIENT_SECRET`

### Configure API Permissions

1. Go to **API permissions** (left sidebar)
2. Click **Add a permission** → **Microsoft Graph** → **Delegated permissions**
3. Add these permissions:
   - `openid`
   - `profile`
   - `email`
4. Click **Add permissions**
5. Click **Grant admin consent for [your org]**

### Configure Token Claims

1. Go to **Token configuration** (left sidebar)
2. Click **Add optional claim**
3. Select **ID** token type
4. Check these claims:
   - `email`
   - `preferred_username`
5. Click **Add**

### Add Redirect URI (Optional - for Testing)

If you plan to test with MCP Inspector:

1. Go to **Authentication** (left sidebar)
2. Under **Platform configurations**, click **Add a platform** → **Web**
3. Add redirect URI: `http://localhost:6274/oauth/callback`
4. Click **Configure**

## Step 2: Configure MCP Server

Create a configuration file (`config.toml`):

### Basic Configuration

Use this configuration when your Kubernetes cluster accepts Entra ID tokens directly (cluster OIDC is configured with the same Entra ID tenant):

```toml
require_oauth = true
oauth_audience = "<CLIENT_ID>"
oauth_scopes = ["openid", "profile", "email"]

# Entra ID uses v2.0 endpoints
authorization_url = "https://login.microsoftonline.com/<TENANT_ID>/v2.0"
```

Replace:
- `<CLIENT_ID>` with your Application (client) ID
- `<TENANT_ID>` with your Directory (tenant) ID

> **Note:** When `cluster_auth_mode` is not set, the server auto-detects:
> - If `require_oauth = true` → uses `passthrough`
> - Otherwise → uses `kubeconfig`
>
> In `passthrough` mode, if token exchange is configured (`token_exchange_strategy` or `sts_audience`), the token is exchanged before being passed to the cluster.

### With ServiceAccount Credentials

If your Kubernetes cluster doesn't accept Entra ID tokens on the API server, use this configuration:

```toml
require_oauth = true
oauth_audience = "<CLIENT_ID>"
oauth_scopes = ["openid", "profile", "email"]

authorization_url = "https://login.microsoftonline.com/<TENANT_ID>/v2.0"

# Use kubeconfig ServiceAccount credentials for cluster access
cluster_auth_mode = "kubeconfig"
kubeconfig = "/path/to/sa-kubeconfig"
```

This setup:
- **MCP clients authenticate via Entra ID** (OAuth required for MCP access)
- **Cluster access uses ServiceAccount token** (from kubeconfig)

#### Creating a ServiceAccount Kubeconfig

Your regular kubeconfig likely uses interactive login. Create a kubeconfig with a static ServiceAccount token:

```bash
# Create ServiceAccount
kubectl create sa mcp-server -n default

# Grant permissions (adjust role as needed)
kubectl create clusterrolebinding mcp-server-reader \
  --clusterrole=view \
  --serviceaccount=default:mcp-server

# Create long-lived token
kubectl create token mcp-server -n default --duration=8760h > /tmp/sa-token

# Create kubeconfig with static token
export SA_TOKEN=$(cat /tmp/sa-token)
export CLUSTER_URL=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
export CLUSTER_CA=$(kubectl config view --raw --minify -o jsonpath='{.clusters[0].cluster.certificate-authority-data}')

cat > /tmp/mcp-kubeconfig << EOF
apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority-data: ${CLUSTER_CA}
    server: ${CLUSTER_URL}
  name: cluster
contexts:
- context:
    cluster: cluster
    user: mcp-server
  name: mcp-context
current-context: mcp-context
users:
- name: mcp-server
  user:
    token: ${SA_TOKEN}
EOF
```

Then run:
```bash
./kubernetes-mcp-server --config config.toml
```

### With Token Exchange (On-Behalf-Of Flow)

If you have a downstream API that accepts Entra ID tokens and want to exchange the user's token, use the On-Behalf-Of (OBO) flow:

```toml
require_oauth = true
oauth_audience = "<CLIENT_ID>"
oauth_scopes = ["openid", "profile", "email"]

authorization_url = "https://login.microsoftonline.com/<TENANT_ID>/v2.0"

# Token exchange configuration (passthrough will use this automatically)
token_exchange_strategy = "entra-obo"
sts_client_id = "<CLIENT_ID>"
sts_client_secret = "<CLIENT_SECRET>"
sts_scopes = ["api://<DOWNSTREAM_API_APP_ID>/.default"]
```

Replace:
- `<CLIENT_ID>` with your Application (client) ID
- `<TENANT_ID>` with your Directory (tenant) ID
- `<CLIENT_SECRET>` with your client secret
- `<DOWNSTREAM_API_APP_ID>` with the App ID of the downstream API

**Note:** For OBO to work, you need to configure API permissions in Azure:
1. Go to your app registration → **API permissions**
2. Click **Add a permission** → **APIs my organization uses**
3. Select the downstream API app registration
4. Add the required delegated permissions

## Step 3: Run the MCP Server

```bash
./kubernetes-mcp-server --config config.toml
```

## Testing with MCP Inspector (Optional)

To test authentication with MCP Inspector:

1. Ensure redirect URI is configured (see Step 1)
2. Start MCP Inspector:
   ```bash
   npx @modelcontextprotocol/inspector@latest $(pwd)/kubernetes-mcp-server --config config.toml
   ```
3. In **Authentication** section:
   - Set **Client ID** to your `<CLIENT_ID>`
   - Set **Scope** to `openid profile email`
4. Click **Connect**
5. Login with your Entra ID credentials

## How It Works

### Client Registration

Entra ID doesn't support RFC 7591 Dynamic Client Registration - clients must be pre-registered in the Azure portal (as shown in Step 1 above).

Add redirect URIs in the Azure portal → Authentication for your MCP clients:
- `http://localhost:6274/oauth/callback` (MCP Inspector default)

### Well-Known Endpoint Fallback

The MCP server implements automatic fallback for OIDC providers that don't support all OAuth 2.0 well-known endpoints:

1. When a client requests `/.well-known/oauth-authorization-server`, the server first tries to proxy the request to Entra ID
2. Entra ID returns 404 (this endpoint doesn't exist)
3. The server automatically falls back to fetching `/.well-known/openid-configuration`
4. The openid-configuration response is returned, which contains all required OAuth metadata

This allows MCP clients to work with Entra ID without any special configuration.

## Troubleshooting

### "invalid_client" Error

Check that:
- You're using the correct client ID
- The redirect URI matches exactly what's configured in Entra ID
- The client secret is correct (if using confidential client flow)

### "AADSTS50011" Redirect URI Mismatch

The redirect URI in your request doesn't match Entra ID configuration:
1. Go to Azure Portal → App registrations → your app → Authentication
2. Add the exact redirect URI shown in the error message

### Token Validation Fails

Ensure your Kubernetes cluster is configured to trust Entra ID tokens:
- The OIDC issuer should be `https://login.microsoftonline.com/{tenant}/v2.0`
- The audience should match your client ID or application ID URI

### Well-Known Endpoint Returns 404

This is expected for `oauth-authorization-server` and `oauth-protected-resource` endpoints. The MCP server automatically handles this by falling back to `openid-configuration`.

## Differences from Keycloak

| Feature | Keycloak | Entra ID |
|---------|----------|----------|
| oauth-authorization-server endpoint | ✅ Supported | ❌ Not available |
| oauth-protected-resource endpoint | ✅ Supported | ❌ Not available |
| openid-configuration endpoint | ✅ Supported | ✅ Supported |
| Token Exchange (RFC 8693) | ✅ Supported | ❌ Use On-Behalf-Of flow |
| Dynamic Client Registration | ✅ Supported | ❌ Not available |

The MCP server handles these differences automatically through the well-known endpoint fallback mechanism.

## Quick Reference

| Item | Where to Find |
|------|---------------|
| Client ID | Azure Portal → App registrations → Overview → Application (client) ID |
| Tenant ID | Azure Portal → App registrations → Overview → Directory (tenant) ID |
| Client Secret | Azure Portal → App registrations → Certificates & secrets → Value column |
| Authorization URL | `https://login.microsoftonline.com/<TENANT_ID>/v2.0` |

## See Also

- [Entra ID OAuth 2.0 Documentation](https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow)
- [Keycloak OIDC Setup](KEYCLOAK_OIDC_SETUP.md) - Alternative OIDC provider setup
