<#
.SYNOPSIS
    OAuth 2.0 Authorization Code Flow - Get Refresh Token for Service Account Automation
    
.DESCRIPTION
    This script obtains a refresh token on behalf of a service account user for Microsoft Graph API access.
    The refresh token is stored in Azure Key Vault and can be used by Azure automation consumers 
    (Runbooks, Functions, Logic Apps) to get access tokens without user interaction.
    
    IMPORTANT: This script must be re-run every ~90 days as refresh tokens expire.
    
.SCOPE & PERMISSIONS
    Microsoft Graph API Scopes (Teams Chat Operations):
    - offline_access              : Required to get refresh token
    - User.Read                   : Read user profile
    - Chat.Create                 : Create new chats
    - Chat.ReadWrite              : Read and write chat properties
    - ChatMember.ReadWrite        : Add/remove chat members (requires admin consent)
    - ChatMessage.Read            : Read chat messages
    - ChatMessage.Send            : Send chat messages
    
.PREREQUISITES
    1. SERVICE ACCOUNT REQUIREMENTS:
       - Service Account: <your-service-account>@<your-domain>.com
       - Entra ID Role: Cloud Application Administrator (for admin consent)
       - Azure RBAC Role: Key Vault Secrets Officer (on your Key Vault)
       
    2. AZURE POWERSHELL MODULES:
       Install-Module Az.Accounts -Scope CurrentUser
       Install-Module Az.KeyVault -Scope CurrentUser
       
    3. APP REGISTRATION:
       - Client ID and Secret must be stored in Key Vault
       - Secret Name: <your-app-registration-secret-name>
       - Client ID stored in: ContentType field
       - Client Secret stored in: SecretValue field
       
.AUTHENTICATION FLOW
    Step 0: Retrieve app registration credentials from Key Vault
    Step 1: Open browser for user authentication (use service account)
    Step 2: Exchange authorization code for access and refresh tokens
    Step 3: Test access token by calling Microsoft Graph /me endpoint
    Step 4: Store refresh token in Key Vault for automation consumers
    
.HOW TO USE
    1. Update configuration variables in STEP 0
    2. Ensure you have required Azure PowerShell modules installed
    3. Run the script: .\Get-AccessOnBehalfOfUser.ps1
    4. Authenticate with Azure when prompted (Connect-AzAccount)
    5. Browser will open for OAuth authentication
       → Use your service account credentials
       → Grant admin consent if prompted (Cloud App Admin role required)
    6. Copy the redirect URL from browser and paste into PowerShell prompt
    7. Script will store refresh token in Key Vault
    
.KEY VAULT STRUCTURE
    Key Vault Name: <your-keyvault-name>
    
    Secret: <your-app-registration-secret-name>
    ├─ ContentType  → Client ID
    └─ SecretValue  → Client Secret
    
    Secret: <your-refresh-token-secret-name>
    └─ SecretValue  → Refresh Token (valid ~90 days)
    
.NOTES
    File Name    : Get-AccessOnBehalfOfUser.ps1
    Author       : Darwin Galao
    Created      : September 26, 2025
    Version      : 1.0
    
    IMPORTANT REMINDERS:
    - Refresh tokens expire after ~90 days - set a calendar reminder!
    - Always use your service account for ALL authentication prompts
    - Service account must have Cloud Application Administrator role for admin consent
    - Service account must have Key Vault Secrets Officer role for token storage
    - Admin consent is required for ChatMember.ReadWrite scope
    
.EXAMPLE
    .\Get-AccessOnBehalfOfUser.ps1
    
    # Expected flow:
    # 1. Connects to Azure (use your admin account)
    # 2. Retrieves app registration from Key Vault
    # 3. Opens browser for OAuth (login as service account)
    # 4. You paste redirect URL
    # 5. Tests token with Graph API
    # 6. Stores refresh token in Key Vault
    
.AUTOMATION CONSUMERS
    After running this script, Azure automation consumers can use the refresh token:
    
    Example - Get Access Token in Azure Function/Runbook:
    
    # Get refresh token from Key Vault
    $refreshTokenSecret = Get-AzKeyVaultSecret -VaultName "<your-keyvault-name>" `
        -Name "<your-refresh-token-secret-name>"
    $refreshToken = $refreshTokenSecret.SecretValue | ConvertFrom-SecureString -AsPlainText
    
    # Exchange for access token
    $tokenBody = @{
        client_id     = $clientId
        client_secret = $clientSecret
        grant_type    = "refresh_token"
        refresh_token = $refreshToken
        scope         = "https://graph.microsoft.com/.default"
    }
    $tokenResponse = Invoke-RestMethod -Uri $tokenEndpoint -Method POST -Body $tokenBody
    
    # Use access token for Graph API calls
    $headers = @{ Authorization = "Bearer $($tokenResponse.access_token)" }
    Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/chats" -Headers $headers
    
.TROUBLESHOOTING
    Error: "admin_consent_required"
    → Solution: Ensure service account has Cloud Application Administrator role
    
    Error: "Access denied to Key Vault"
    → Solution: Ensure service account has Key Vault Secrets Officer role
    
    Error: "No refresh token received"
    → Solution: Ensure "offline_access" scope is included in app registration API permissions
    
    Error: "Refresh token expired"
    → Solution: Re-run this script (it's been ~90 days since last run)
    
.RELATED DOCUMENTATION
    Microsoft Graph Chat API: https://learn.microsoft.com/en-us/graph/api/resources/chat
    OAuth 2.0 Auth Code Flow: https://learn.microsoft.com/en-us/graph/auth-v2-user
    Azure Key Vault Secrets: https://learn.microsoft.com/en-us/azure/key-vault/secrets/
#>

Write-Host "`n=== COMPLETE OAUTH 2.0 AUTHORIZATION CODE FLOW ===" -ForegroundColor Cyan

# ============================================================================
# STEP 0: CONFIGURATION - UPDATE THESE VALUES
# ============================================================================
Write-Host "`n[STEP 0] RETRIEVE NEEDED PARAMETERS" -ForegroundColor Yellow

# ---------------------- CONFIGURATION SECTION - EDIT THESE ----------------------
$TenantId = "<your-tenant-id>"                          # Azure AD Tenant ID
$RedirectUri = "https://localhost"                      # OAuth redirect URI
$AppReg_VaultName = "<your-keyvault-name>"             # Key Vault name
$DevOpsAppReg_SecretName = "<your-app-reg-secret>"     # App registration secret name
$DevOpsRefreshToken_SecretName = "<your-refresh-token-secret>" # Refresh token secret name

# Microsoft Graph API Scopes
$Scopes = @(
    "offline_access",                                    # Required for refresh token
    "https://graph.microsoft.com/User.Read",
    "https://graph.microsoft.com/Chat.Create",
    "https://graph.microsoft.com/Chat.ReadWrite",
    "https://graph.microsoft.com/ChatMember.ReadWrite", # Requires admin consent
    "https://graph.microsoft.com/ChatMessage.Read",
    "https://graph.microsoft.com/ChatMessage.Send"
)
# --------------------------------------------------------------------------------

try {
    Write-Host "Connecting to Azure..." -ForegroundColor Green
    Connect-AzAccount

    Write-Host "Retrieving app registration from Key Vault: $AppReg_VaultName" -ForegroundColor Green
    
    # Get app registration details from Key Vault
    $SecretName_Object = Get-AzKeyVaultSecret -VaultName $AppReg_VaultName -Name $DevOpsAppReg_SecretName
    $SPName = $SecretName_Object.Name
    $ClientId = $SecretName_Object.ContentType          # Client ID stored in ContentType
    $ClientSecret = $SecretName_Object.SecretValue | ConvertFrom-SecureString -AsPlainText

    Write-Host "✓ App Registration: $SPName retrieved successfully!" -ForegroundColor Green
    
} catch {
    Write-Error "Failed to retrieve secrets from Key Vault: $AppReg_VaultName"
    Write-Error "Error details: $($_.Exception.Message)"
    exit
}

# ============================================================================
# STEP 1: REQUEST AUTHORIZATION
# ============================================================================
Write-Host "`n[STEP 1] REQUEST AUTHORIZATION" -ForegroundColor Yellow

# Generate random state for CSRF protection
$state = -join ((65..90) + (97..122) | Get-Random -Count 16 | ForEach-Object {[char]$_})

# Build authorization URL
$scopeString = $Scopes -join " "
$redirectUriEncoded = [System.Uri]::EscapeDataString($RedirectUri)
$scopeEncoded = [System.Uri]::EscapeDataString($scopeString)

$authUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/authorize?" +
    "client_id=$ClientId" +
    "&response_type=code" +
    "&redirect_uri=$redirectUriEncoded" +
    "&response_mode=query" +
    "&scope=$scopeEncoded" +
    "&state=$state"

Write-Host "Opening browser for authentication..." -ForegroundColor Green
Write-Host "IMPORTANT: Login with your SERVICE ACCOUNT credentials" -ForegroundColor Yellow
Start-Process $authUrl

Write-Host "`nAfter authenticating, paste the full redirect URL here:"
$redirectResponse = Read-Host "Redirect URL"

# Extract authorization code from redirect URL
if ($redirectResponse -match "code=([^&]+)") {
    $authorizationCode = $Matches[1]
    Write-Host "✓ Authorization code received" -ForegroundColor Green
} else {
    Write-Error "No authorization code found in redirect URL"
    exit
}

# ============================================================================
# STEP 2: EXCHANGE CODE FOR TOKENS
# ============================================================================
Write-Host "`n[STEP 2] EXCHANGE CODE FOR TOKENS" -ForegroundColor Yellow

$tokenRequestBody = @{
    client_id     = $ClientId
    scope         = $scopeString
    code          = $authorizationCode
    redirect_uri  = $RedirectUri
    grant_type    = "authorization_code"
}

if ($ClientSecret) {
    $tokenRequestBody.client_secret = $ClientSecret
}

$tokenEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"

try {
    $tokenResponse = Invoke-RestMethod `
        -Uri $tokenEndpoint `
        -Method POST `
        -Body $tokenRequestBody `
        -ContentType "application/x-www-form-urlencoded"
    
    Write-Host "✓ Token exchange successful" -ForegroundColor Green
    Write-Host "  Access Token Expires In: $($tokenResponse.expires_in) seconds" -ForegroundColor Cyan
    Write-Host "  Scopes Granted: $($tokenResponse.scope)" -ForegroundColor Cyan
    
    if ($tokenResponse.refresh_token) {
        Write-Host "✓ Refresh token received!" -ForegroundColor Green
        $refreshToken = $tokenResponse.refresh_token
        $accessToken = $tokenResponse.access_token
    } else {
        Write-Warning "No refresh token received - offline_access may not be granted"
        exit
    }
    
} catch {
    Write-Error "Token request failed: $($_.Exception.Message)"
    exit
}

# ============================================================================
# STEP 3: TEST ACCESS TOKEN (Call Microsoft Graph)
# ============================================================================
Write-Host "`n[STEP 3] TEST ACCESS TOKEN" -ForegroundColor Yellow

$headers = @{
    Authorization = "Bearer $accessToken"
}

try {
    Write-Host "Calling Microsoft Graph API (/me endpoint)..." -ForegroundColor Green
    $meResponse = Invoke-RestMethod `
        -Uri "https://graph.microsoft.com/v1.0/me" `
        -Headers $headers `
        -Method GET
    
    Write-Host "✓ API Call Successful!" -ForegroundColor Green
    Write-Host "  Display Name: $($meResponse.displayName)" -ForegroundColor Cyan
    Write-Host "  Email: $($meResponse.userPrincipalName)" -ForegroundColor Cyan
    Write-Host "  User ID: $($meResponse.id)" -ForegroundColor Cyan
    
} catch {
    Write-Error "API call failed: $($_.Exception.Message)"
    exit
}

# ============================================================================
# STEP 4: STORE REFRESH TOKEN IN KEY VAULT
# ============================================================================
Write-Host "`n[STEP 4] STORE REFRESH TOKEN" -ForegroundColor Yellow

try {
    Write-Host "Storing refresh token in Key Vault: $AppReg_VaultName" -ForegroundColor Green
    $SecretValue = ConvertTo-SecureString $refreshToken -AsPlainText -Force
    
    $result = Set-AzKeyVaultSecret `
        -VaultName $AppReg_VaultName `
        -Name $DevOpsRefreshToken_SecretName `
        -SecretValue $SecretValue
    
    Write-Host "✓ Refresh token stored successfully!" -ForegroundColor Green
    Write-Host "  Location: $AppReg_VaultName/$DevOpsRefreshToken_SecretName" -ForegroundColor Cyan
    Write-Host "  Version: $($result.Version)" -ForegroundColor Cyan
    
} catch {
    Write-Error "Failed to store refresh token: $($_.Exception.Message)"
    exit
}

Write-Host "`n=== SETUP COMPLETE ===" -ForegroundColor Cyan
Write-Host "✓ You can now use the refresh token for automation (valid ~90 days)" -ForegroundColor Green
Write-Host "`n REMINDER: Set a calendar alert to re-run this script in 90 days!" -ForegroundColor Yellow
Write-Host "   Always use your service account for authentication" -ForegroundColor Yellow