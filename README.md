# OAuth 2.0 Authorization Code Flow for Service Account Automation

A PowerShell script that implements OAuth 2.0 Authorization Code Flow to obtain and store refresh tokens for automated Microsoft Graph API access using service accounts.

## 🎯 Purpose

This script solves a common automation challenge: **How to access Microsoft Graph API on behalf of a user without requiring interactive login every time.**

### The Problem
- You need delegated permissions (user context) to access Microsoft Graph
- Azure Runbooks, Functions, and Logic Apps can't prompt users for interactive login
- Access tokens expire after 1 hour

### The Solution
1. **Run this script once** (with user interaction) to get a refresh token
2. **Store the refresh token** securely in Azure Key Vault
3. **Automated consumers** use the refresh token to get fresh access tokens without user interaction
4. **Repeat every ~90 days** when refresh tokens expire

---

## 📋 Prerequisites

### 1. Azure Resources
- **Azure Key Vault** for storing credentials
- **App Registration** in Azure AD with required permissions
- **Service Account** with appropriate roles

### 2. Service Account Requirements
- **Email**: `<your-service-account>@<domain>.com`
- **Entra ID Role**: `Cloud Application Administrator` (for admin consent)
- **Azure RBAC Role**: `Key Vault Secrets Officer` (on your Key Vault)

### 3. PowerShell Modules
```powershell
Install-Module Az.Accounts -Scope CurrentUser
Install-Module Az.KeyVault -Scope CurrentUser
```

### 4. Key Vault Secret Structure
Store your app registration credentials in Key Vault:

**Secret Name**: `<your-app-registration-secret-name>`
- **ContentType**: Client ID (e.g., `c6d3ff2e-e348-463d-bc4d-0f61ee2a3331`)
- **SecretValue**: Client Secret

---

## 🚀 How It Works

### Architecture Overview

```
┌─────────────────────────────────────────────────┐
│         INITIAL SETUP (Every 90 Days)          │
│  Run locally with user interaction             │
├─────────────────────────────────────────────────┤
│  Get-AccessOnBehalfOfUser.ps1                  │
│  ↓                                              │
│  User authenticates → Get refresh token        │
│  ↓                                              │
│  Store in Key Vault                            │
└─────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────┐
│     AUTOMATION CONSUMERS (24/7)                 │
│  Azure Runbook / Function / Logic App          │
├─────────────────────────────────────────────────┤
│  1. Get refresh token from Key Vault           │
│  2. Exchange for access token (HTTP call)      │
│  3. Call Microsoft Graph API                   │
│  4. Repeat as needed                           │
└─────────────────────────────────────────────────┘
```

### OAuth 2.0 Flow Steps

**STEP 0**: Retrieve app registration credentials from Key Vault  
**STEP 1**: Open browser for user authentication (service account logs in)  
**STEP 2**: Exchange authorization code for access and refresh tokens  
**STEP 3**: Test access token by calling Microsoft Graph `/me` endpoint  
**STEP 4**: Store refresh token in Key Vault for automation consumers  

---

## 📝 Configuration

Before running the script, update these variables in **STEP 0**:

```powershell
$TenantId = "<your-tenant-id>"                          # Azure AD Tenant ID
$RedirectUri = "https://localhost"                      # OAuth redirect URI
$AppReg_VaultName = "<your-keyvault-name>"             # Key Vault name
$DevOpsAppReg_SecretName = "<your-app-reg-secret>"     # App registration secret name
$DevOpsRefreshToken_SecretName = "<your-refresh-token-secret>" # Refresh token secret name
```

### Microsoft Graph Scopes (Teams Chat)

The script requests these permissions:
- `offline_access` - Required to get refresh token
- `User.Read` - Read user profile
- `Chat.Create` - Create new chats
- `Chat.ReadWrite` - Read and write chat properties
- `ChatMember.ReadWrite` - Add/remove chat members ⚠️ **Requires admin consent**
- `ChatMessage.Read` - Read chat messages
- `ChatMessage.Send` - Send chat messages

---

## 🎬 Usage

### Initial Setup (Run Once Every 90 Days)

1. **Update configuration variables** in the script
2. **Run the script**:
   ```powershell
   .\Get-AccessOnBehalfOfUser.ps1
   ```
3. **Authenticate to Azure** when prompted (your admin account)
4. **Browser opens** for OAuth authentication
   - ⚠️ **Use your SERVICE ACCOUNT credentials**
   - Grant admin consent if prompted
5. **Copy the redirect URL** from browser address bar
6. **Paste the URL** into PowerShell prompt
7. **Refresh token stored** in Key Vault

### Expected Output

```
=== COMPLETE OAUTH 2.0 AUTHORIZATION CODE FLOW ===

[STEP 0] RETRIEVE NEEDED PARAMETERS
Connecting to Azure...
✓ App Registration: <name> retrieved successfully!

[STEP 1] REQUEST AUTHORIZATION
Opening browser for authentication...
IMPORTANT: Login with your SERVICE ACCOUNT credentials
✓ Authorization code received

[STEP 2] EXCHANGE CODE FOR TOKENS
✓ Token exchange successful
  Access Token Expires In: 5089 seconds
  Scopes Granted: offline_access User.Read Chat.Create...
✓ Refresh token received!

[STEP 3] TEST ACCESS TOKEN
✓ API Call Successful!
  Display Name: Service Account Name
  Email: svc.account@domain.com
  User ID: <guid>

[STEP 4] STORE REFRESH TOKEN
✓ Refresh token stored successfully!
  Location: <vault>/<secret-name>

=== SETUP COMPLETE ===
✓ You can now use the refresh token for automation (valid ~90 days)
```

---

## 🤖 Automation Consumer Example

After running the initial setup, use this code in your Azure Runbooks/Functions:

```powershell
# Configuration
$TenantId = "<your-tenant-id>"
$KeyVaultName = "<your-keyvault-name>"
$AppRegSecretName = "<your-app-reg-secret>"
$RefreshTokenSecretName = "<your-refresh-token-secret>"

# Get credentials from Key Vault (using Managed Identity)
$appReg = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $AppRegSecretName
$ClientId = $appReg.ContentType
$ClientSecret = $appReg.SecretValue | ConvertFrom-SecureString -AsPlainText

$refreshTokenSecret = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $RefreshTokenSecretName
$RefreshToken = $refreshTokenSecret.SecretValue | ConvertFrom-SecureString -AsPlainText

# Exchange refresh token for access token (simple HTTP - no MSAL needed)
$tokenBody = @{
    client_id     = $ClientId
    client_secret = $ClientSecret
    grant_type    = "refresh_token"
    refresh_token = $RefreshToken
    scope         = "https://graph.microsoft.com/.default"
}

$tokenEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
$tokenResponse = Invoke-RestMethod -Uri $tokenEndpoint -Method POST -Body $tokenBody -ContentType "application/x-www-form-urlencoded"

# Use access token for Graph API calls
$headers = @{ Authorization = "Bearer $($tokenResponse.access_token)" }
$chats = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/chats" -Headers $headers

Write-Output "Found $($chats.value.Count) chats"
```

---

## ⚠️ Important Notes

### Token Expiration
- **Access Token**: Valid for ~1 hour (request new from refresh token)
- **Refresh Token**: Valid for ~90 days (re-run this script after expiration)
- **Set a calendar reminder** to re-run the script before 90 days!

### Security Considerations
- **Treat refresh tokens like passwords** - they provide long-term access
- **Use Azure Key Vault** for secure storage (never store in code/files)
- **Service account only** - don't use personal accounts
- **Managed Identity** - use it in Azure automation for Key Vault access
- **Least privilege** - only grant necessary Graph API permissions

### Why Not Use MSAL?
- **MSAL is great for initial setup** but not ideal for Azure serverless consumers
- **MSAL uses local file cache** (doesn't work in stateless Functions/Runbooks)
- **Simple HTTP token exchange** works everywhere and is more efficient
- This script uses manual OAuth flow to understand the process better

---

## 🐛 Troubleshooting

### Error: `admin_consent_required`
**Solution**: Ensure service account has `Cloud Application Administrator` role in Entra ID

### Error: `Access denied to Key Vault`
**Solution**: Ensure service account has `Key Vault Secrets Officer` role on the Key Vault

### Error: `No refresh token received`
**Solution**: Ensure `offline_access` scope is included in app registration API permissions

### Error: `Refresh token expired`
**Solution**: Re-run this script (it's been ~90 days since last run)

### Error: `Authorization code not found`
**Solution**: Make sure you copy the **entire URL** from browser (including `https://localhost/?code=...`)

---

## 📚 Related Documentation

- [Microsoft Graph Chat API](https://learn.microsoft.com/en-us/graph/api/resources/chat)
- [OAuth 2.0 Authorization Code Flow](https://learn.microsoft.com/en-us/graph/auth-v2-user)
- [Azure Key Vault Secrets](https://learn.microsoft.com/en-us/azure/key-vault/secrets/)
- [Microsoft Graph Permissions Reference](https://learn.microsoft.com/en-us/graph/permissions-reference)

---

## 📄 License

MIT License - Feel free to use and modify for your needs

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

---

## ⭐ Acknowledgments

Built to solve real-world Azure automation challenges with Microsoft Graph API delegated permissions.