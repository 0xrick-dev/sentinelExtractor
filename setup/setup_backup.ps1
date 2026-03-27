# ---------------------------------------------------------------------------
# setup_backup.ps1
#
# Create an Azure AD App Registration with a client secret and assign the
# minimum RBAC roles required to run sentinel_extractor.py (backup).
#
# What this script does:
#   1. Creates an App Registration in Azure AD (or reuses an existing one).
#   2. Creates a client secret with a configurable expiry (default: 1 year).
#   3. Assigns "Reader" on each source resource group.
#   4. Assigns "Microsoft Sentinel Reader" on the Sentinel workspace.
#   5. Outputs the credentials needed for sentinel_extractor.py.
#
# Prerequisites:
#   - Azure CLI (az) installed and logged in
#   - Permissions to create App Registrations in the tenant
#   - Owner or User Access Administrator on the source resource group(s)
#
# Usage:
#   .\setup_backup.ps1
#   .\setup_backup.ps1 -AppName "SentinelBackup" -SubscriptionId <sub-id> `
#       -ResourceGroup <rg> -WorkspaceName <ws>
# ---------------------------------------------------------------------------

[CmdletBinding()]
param(
    [string]$AppName,
    [string]$SubscriptionId,
    [string]$ResourceGroup,
    [string]$WorkspaceName,
    [string]$LogicAppsRG,
    [string]$DcrRG,
    [string]$DceRG,
    [string]$WorkbooksRG,
    [string]$SecretExpiry
)

$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Write-Info {
    param([string]$Message)
    Write-Host "  $Message"
}

function Read-Value {
    param(
        [string]$Prompt,
        [string]$Default = ""
    )
    if ($Default) {
        $value = Read-Host "  $Prompt [$Default]"
        if ([string]::IsNullOrWhiteSpace($value)) { return $Default }
        return $value
    }
    else {
        return Read-Host "  $Prompt"
    }
}

function Read-Required {
    param([string]$Prompt)
    $value = ""
    while ([string]::IsNullOrWhiteSpace($value)) {
        $value = Read-Host "  $Prompt"
        if ([string]::IsNullOrWhiteSpace($value)) {
            Write-Host "  This field is required." -ForegroundColor Yellow
        }
    }
    return $value
}

# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------
function Test-Uuid {
    param([string]$Value, [string]$Label)
    if ($Value -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
        Write-Host "ERROR: Invalid $Label`: '$Value' is not a valid UUID." -ForegroundColor Red
        exit 1
    }
}

function Test-ResourceName {
    param([string]$Value, [string]$Label)
    if ($Value -notmatch '^[a-zA-Z0-9][a-zA-Z0-9._-]*$') {
        Write-Host "ERROR: Invalid $Label`: '$Value' must start with alphanumeric and contain only alphanumeric, '.', '_', or '-'." -ForegroundColor Red
        exit 1
    }
    if ($Value.Length -gt 90) {
        Write-Host "ERROR: Invalid $Label`: '$Value' exceeds 90 characters." -ForegroundColor Red
        exit 1
    }
}

# ---------------------------------------------------------------------------
# Verify Azure CLI
# ---------------------------------------------------------------------------
$azCmd = Get-Command az -ErrorAction SilentlyContinue
if (-not $azCmd) {
    Write-Host "ERROR: Azure CLI (az) is not installed. Install from https://aka.ms/install-azure-cli" -ForegroundColor Red
    exit 1
}

try {
    $accountJson = az account show --output json 2>$null | ConvertFrom-Json
}
catch {
    $accountJson = $null
}

if (-not $accountJson) {
    Write-Host "ERROR: Not logged in to Azure CLI. Run 'az login' first." -ForegroundColor Red
    exit 1
}

$TenantId = $accountJson.tenantId

# ---------------------------------------------------------------------------
# Collect configuration interactively
# ---------------------------------------------------------------------------
Write-Step "Sentinel Extractor — Backup App Registration Setup"
Write-Info "This script creates an App Registration and assigns read-only"
Write-Info "permissions for sentinel_extractor.py to back up your Sentinel workspace."

Write-Step "App Registration"
if ([string]::IsNullOrWhiteSpace($AppName))     { $AppName     = Read-Value "App Registration display name" "SentinelExtractor-Backup" }
if ([string]::IsNullOrWhiteSpace($SecretExpiry)) { $SecretExpiry = Read-Value "Client secret validity (years)" "1" }

Write-Step "Source Sentinel Workspace"
if ([string]::IsNullOrWhiteSpace($SubscriptionId)) { $SubscriptionId = Read-Required "Azure subscription ID" }
if ([string]::IsNullOrWhiteSpace($ResourceGroup))  { $ResourceGroup  = Read-Required "Sentinel workspace resource group" }
if ([string]::IsNullOrWhiteSpace($WorkspaceName))   { $WorkspaceName  = Read-Required "Log Analytics workspace name" }

Write-Step "Optional Resource Groups (press Enter to use the workspace RG)"
Write-Info "If these resources live in a different resource group, specify it."
Write-Info "Leave blank to use the workspace resource group: $ResourceGroup"
if ([string]::IsNullOrWhiteSpace($LogicAppsRG)) { $LogicAppsRG = Read-Value "Logic Apps resource group" "" }
if ([string]::IsNullOrWhiteSpace($DcrRG))       { $DcrRG       = Read-Value "DCR resource group" "" }
if ([string]::IsNullOrWhiteSpace($DceRG))       { $DceRG       = Read-Value "DCE resource group" "" }
if ([string]::IsNullOrWhiteSpace($WorkbooksRG)) { $WorkbooksRG = Read-Value "Workbooks resource group" $ResourceGroup }

# ---------------------------------------------------------------------------
# Validate inputs
# ---------------------------------------------------------------------------
Write-Step "Validating inputs..."
Test-Uuid -Value $SubscriptionId -Label "subscription ID"
Test-ResourceName -Value $ResourceGroup -Label "resource group"
Test-ResourceName -Value $WorkspaceName -Label "workspace name"
if (-not [string]::IsNullOrWhiteSpace($LogicAppsRG)) { Test-ResourceName -Value $LogicAppsRG -Label "Logic Apps resource group" }
if (-not [string]::IsNullOrWhiteSpace($DcrRG))       { Test-ResourceName -Value $DcrRG -Label "DCR resource group" }
if (-not [string]::IsNullOrWhiteSpace($DceRG))       { Test-ResourceName -Value $DceRG -Label "DCE resource group" }
if (-not [string]::IsNullOrWhiteSpace($WorkbooksRG)) { Test-ResourceName -Value $WorkbooksRG -Label "Workbooks resource group" }
Write-Info "All inputs valid."

# ---------------------------------------------------------------------------
# Set subscription context
# ---------------------------------------------------------------------------
Write-Step "Setting Azure CLI subscription..."
az account set --subscription "$SubscriptionId"
Write-Info "Subscription: $SubscriptionId"

# ---------------------------------------------------------------------------
# Validate workspace exists
# ---------------------------------------------------------------------------
Write-Step "Validating workspace..."
$wsCheck = az monitor log-analytics workspace show `
    --resource-group "$ResourceGroup" `
    --workspace-name "$WorkspaceName" `
    --query "id" --output tsv 2>$null

if ([string]::IsNullOrWhiteSpace($wsCheck)) {
    Write-Host "ERROR: Workspace '$WorkspaceName' not found in resource group '$ResourceGroup'." -ForegroundColor Red
    exit 1
}
Write-Info "Workspace found: $WorkspaceName"

# ---------------------------------------------------------------------------
# Create App Registration
# ---------------------------------------------------------------------------
Write-Step "Creating App Registration: $AppName"

$existingApp = az ad app list --display-name "$AppName" --query "[0].appId" --output tsv 2>$null

if (-not [string]::IsNullOrWhiteSpace($existingApp)) {
    Write-Host "  App Registration '$AppName' already exists (appId: $existingApp)." -ForegroundColor Yellow
    Write-Info "Reusing existing App Registration."
    $AppId = $existingApp
}
else {
    $AppId = az ad app create --display-name "$AppName" --query "appId" --output tsv
    Write-Info "App Registration created: $AppId"
}

# ---------------------------------------------------------------------------
# Ensure Service Principal exists
# ---------------------------------------------------------------------------
Write-Step "Ensuring Service Principal exists..."
$spObjectId = az ad sp show --id "$AppId" --query "id" --output tsv 2>$null

if ([string]::IsNullOrWhiteSpace($spObjectId)) {
    $spObjectId = az ad sp create --id "$AppId" --query "id" --output tsv
    Write-Info "Service Principal created: $spObjectId"
}
else {
    Write-Info "Service Principal already exists: $spObjectId"
}

# ---------------------------------------------------------------------------
# Create Client Secret
# ---------------------------------------------------------------------------
Write-Step "Creating client secret (valid for $SecretExpiry year(s))..."
$endDate = (Get-Date).AddYears([int]$SecretExpiry).ToString("yyyy-MM-ddTHH:mm:ssZ")

$secretJson = az ad app credential reset `
    --id "$AppId" `
    --append `
    --display-name "SentinelExtractor-Backup" `
    --end-date $endDate `
    --query "{password: password}" `
    --output json | ConvertFrom-Json

$ClientSecret = $secretJson.password
Write-Info "Client secret created."

# ---------------------------------------------------------------------------
# Assign RBAC roles
# ---------------------------------------------------------------------------
Write-Step "Assigning RBAC roles for backup (read-only)..."

$script:RoleWarnings = 0

function Assign-Role {
    param(
        [string]$Role,
        [string]$Scope,
        [string]$Label = ""
    )
    $msg = "  Assigning $Role"
    if ($Label) { $msg += " ($Label)" }
    Write-Host "$msg..."
    $result = az role assignment create `
        --assignee-object-id "$spObjectId" `
        --assignee-principal-type ServicePrincipal `
        --role "$Role" `
        --scope "$Scope" `
        --output none 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "    ✓ Assigned" -ForegroundColor Green
    }
    else {
        # Check if already assigned
        $existing = az role assignment list `
            --assignee "$spObjectId" `
            --role "$Role" `
            --scope "$Scope" `
            --query "length(@)" `
            --output tsv 2>$null
        if ($existing -gt 0) {
            Write-Host "    ✓ Already assigned" -ForegroundColor Green
        }
        else {
            Write-Host "    ✗ Failed — ensure you have Owner or User Access Administrator on this scope." -ForegroundColor Red
            $script:RoleWarnings++
        }
    }
}

# Core workspace RG: Reader + Microsoft Sentinel Reader
$wsScope = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup"
Assign-Role -Role "Reader" -Scope $wsScope -Label "workspace RG"
Assign-Role -Role "Microsoft Sentinel Reader" -Scope $wsScope -Label "workspace RG"

# Additional RGs (only if different from the workspace RG)
$assignedRGs = @($ResourceGroup)

function Add-RGReader {
    param(
        [string]$RG,
        [string]$Label
    )
    if (-not [string]::IsNullOrWhiteSpace($RG) -and $RG -notin $assignedRGs) {
        $scope = "/subscriptions/$SubscriptionId/resourceGroups/$RG"
        Assign-Role -Role "Reader" -Scope $scope -Label $Label
        $script:assignedRGs += $RG
    }
}

Add-RGReader -RG $LogicAppsRG -Label "Logic Apps RG"
Add-RGReader -RG $DcrRG       -Label "DCR RG"
Add-RGReader -RG $DceRG       -Label "DCE RG"
Add-RGReader -RG $WorkbooksRG -Label "Workbooks RG"

if ($script:RoleWarnings -gt 0) {
    Write-Host "  WARNING: $($script:RoleWarnings) role assignment(s) failed. See messages above." -ForegroundColor Yellow
}
else {
    Write-Host "  RBAC assignments complete." -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# Write credentials to file (not stdout) for security
# ---------------------------------------------------------------------------
Write-Step "Writing credentials..."
$envFile = ".env.sentinel-backup"
$envContent = @"
AZURE_TENANT_ID=$TenantId
AZURE_CLIENT_ID=$AppId
AZURE_CLIENT_SECRET=$ClientSecret
AZURE_SUBSCRIPTION_ID=$SubscriptionId
AZURE_RESOURCE_GROUP=$ResourceGroup
AZURE_WORKSPACE_NAME=$WorkspaceName
"@
if (-not [string]::IsNullOrWhiteSpace($LogicAppsRG)) {
    $envContent += "`nAZURE_LOGIC_APPS_RESOURCE_GROUP=$LogicAppsRG"
}
if (-not [string]::IsNullOrWhiteSpace($DcrRG)) {
    $envContent += "`nAZURE_DCR_RESOURCE_GROUP=$DcrRG"
}
if (-not [string]::IsNullOrWhiteSpace($DceRG)) {
    $envContent += "`nAZURE_DCE_RESOURCE_GROUP=$DceRG"
}
if (-not [string]::IsNullOrWhiteSpace($WorkbooksRG) -and $WorkbooksRG -ne $ResourceGroup) {
    $envContent += "`nAZURE_WORKBOOKS_RESOURCE_GROUP=$WorkbooksRG"
}
$envContent | Out-File -FilePath $envFile -Encoding utf8 -Force
# Restrict file permissions (owner-only on Unix-like; best-effort on Windows)
if ($IsLinux -or $IsMacOS) {
    chmod 600 $envFile 2>$null
}

Write-Step "Setup complete!"
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor White
Write-Host "║  App Registration Created                                  ║" -ForegroundColor White
Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor White
Write-Host "║  AZURE_TENANT_ID       = " -NoNewline -ForegroundColor White; Write-Host $TenantId -ForegroundColor Green
Write-Host "║  AZURE_CLIENT_ID       = " -NoNewline -ForegroundColor White; Write-Host $AppId -ForegroundColor Green
Write-Host "║  AZURE_CLIENT_SECRET   = " -NoNewline -ForegroundColor White; Write-Host "(written to $envFile)" -ForegroundColor Green
Write-Host "║  AZURE_SUBSCRIPTION_ID = " -NoNewline -ForegroundColor White; Write-Host $SubscriptionId -ForegroundColor Green
Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor White
Write-Host "║  AZURE_RESOURCE_GROUP  = " -NoNewline -ForegroundColor White; Write-Host $ResourceGroup -ForegroundColor Green
Write-Host "║  AZURE_WORKSPACE_NAME  = " -NoNewline -ForegroundColor White; Write-Host $WorkspaceName -ForegroundColor Green
if (-not [string]::IsNullOrWhiteSpace($LogicAppsRG)) {
    Write-Host "║  AZURE_LOGIC_APPS_RESOURCE_GROUP = " -NoNewline -ForegroundColor White; Write-Host $LogicAppsRG -ForegroundColor Green
}
if (-not [string]::IsNullOrWhiteSpace($DcrRG)) {
    Write-Host "║  AZURE_DCR_RESOURCE_GROUP        = " -NoNewline -ForegroundColor White; Write-Host $DcrRG -ForegroundColor Green
}
if (-not [string]::IsNullOrWhiteSpace($DceRG)) {
    Write-Host "║  AZURE_DCE_RESOURCE_GROUP        = " -NoNewline -ForegroundColor White; Write-Host $DceRG -ForegroundColor Green
}
if (-not [string]::IsNullOrWhiteSpace($WorkbooksRG) -and $WorkbooksRG -ne $ResourceGroup) {
    Write-Host "║  AZURE_WORKBOOKS_RESOURCE_GROUP  = " -NoNewline -ForegroundColor White; Write-Host $WorkbooksRG -ForegroundColor Green
}
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor White
Write-Host ""
Write-Host "  Credentials written to: $envFile" -ForegroundColor Green
Write-Host "⚠  The client secret is in $envFile — never commit this file to version control." -ForegroundColor Yellow
Write-Host "⚠  The secret cannot be retrieved from Azure later — keep the file safe." -ForegroundColor Yellow
Write-Host ""
Write-Host "  To use with sentinel_extractor.py, copy or rename the file:"
Write-Host "    Copy-Item $envFile .env"
Write-Host ""
