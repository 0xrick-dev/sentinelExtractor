<#
.SYNOPSIS
    Verifies what the Sentinel extractor's App Registration can actually see
    from the machine you're running on.

.DESCRIPTION
    Sentinel REST APIs (https://management.azure.com/...) are gated by
    Azure RBAC, NOT by Entra ID directory roles. "Global Reader" is an Entra
    directory role and grants access to Microsoft Graph (directory data),
    but it does NOT by itself grant access to Azure ARM / Sentinel /
    Log Analytics resources used by sentinel_extractor.py.

    For the extractor to succeed you typically need an Azure RBAC role like:
      - Reader                       (subscription / RG / workspace scope)
      - Microsoft Sentinel Reader    (workspace scope)
      - Log Analytics Reader         (workspace scope)
    assigned to the App Registration's Service Principal.

    This script does, against the App Registration:
      1. Acquires an ARM token (https://management.azure.com/.default)
      2. Decodes the token and prints the Service Principal object id (oid),
         tenant, app id, audience, roles claim, and expiry.
      3. Acquires a Microsoft Graph token and lists the directory roles
         currently assigned to that Service Principal (this is where you
         would see "Global Reader").
      4. Lists the Service Principal's Azure RBAC role assignments at the
         subscription scope (this is what the extractor actually needs).
      5. Performs a real ARM probe call against the Sentinel watchlists
         endpoint and reports the HTTP status (200 = good, 401 = token /
         auth, 403 = no RBAC, 404 = wrong RG/workspace name).

.PARAMETER TenantId
    Entra ID tenant ID (GUID).

.PARAMETER ClientId
    App Registration (application) ID.

.PARAMETER ClientSecret
    App Registration client secret value.

.PARAMETER SubscriptionId
    Subscription containing the Sentinel workspace.

.PARAMETER ResourceGroup
    Resource group containing the Sentinel workspace.

.PARAMETER WorkspaceName
    Log Analytics workspace name (the one Sentinel is enabled on).

.EXAMPLE
    # Reads from the same .env the extractor uses (recommended)
    .\check_app_permissions.ps1 -EnvFile ..\code\.env

.EXAMPLE
    .\check_app_permissions.ps1 `
        -TenantId   <guid> `
        -ClientId   <guid> `
        -ClientSecret <secret> `
        -SubscriptionId <guid> `
        -ResourceGroup  rg-sentinel `
        -WorkspaceName  ws-sentinel
#>
[CmdletBinding(DefaultParameterSetName = 'Explicit')]
param(
    [Parameter(ParameterSetName = 'EnvFile', Mandatory = $true)]
    [string] $EnvFile,

    [Parameter(ParameterSetName = 'Explicit', Mandatory = $true)]
    [string] $TenantId,

    [Parameter(ParameterSetName = 'Explicit', Mandatory = $true)]
    [string] $ClientId,

    [Parameter(ParameterSetName = 'Explicit', Mandatory = $true)]
    [string] $ClientSecret,

    [Parameter(ParameterSetName = 'Explicit', Mandatory = $true)]
    [string] $SubscriptionId,

    [Parameter(ParameterSetName = 'Explicit', Mandatory = $true)]
    [string] $ResourceGroup,

    [Parameter(ParameterSetName = 'Explicit', Mandatory = $true)]
    [string] $WorkspaceName
)

$ErrorActionPreference = 'Stop'

function Read-EnvFile {
    param([string] $Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Env file not found: $Path"
    }
    $map = @{}
    foreach ($line in Get-Content -LiteralPath $Path) {
        $trim = $line.Trim()
        if ($trim -eq '' -or $trim.StartsWith('#')) { continue }
        $eq = $trim.IndexOf('=')
        if ($eq -lt 1) { continue }
        $k = $trim.Substring(0, $eq).Trim()
        $v = $trim.Substring($eq + 1).Trim().Trim('"').Trim("'")
        $map[$k] = $v
    }
    return $map
}

if ($PSCmdlet.ParameterSetName -eq 'EnvFile') {
    $env_ = Read-EnvFile -Path $EnvFile
    $TenantId       = $env_['AZURE_TENANT_ID']
    $ClientId       = $env_['AZURE_CLIENT_ID']
    $ClientSecret   = $env_['AZURE_CLIENT_SECRET']
    $SubscriptionId = $env_['AZURE_SUBSCRIPTION_ID']
    $ResourceGroup  = $env_['AZURE_RESOURCE_GROUP']
    $WorkspaceName  = $env_['AZURE_WORKSPACE_NAME']
    foreach ($req in 'TenantId','ClientId','ClientSecret','SubscriptionId','ResourceGroup','WorkspaceName') {
        if (-not (Get-Variable -Name $req -ValueOnly)) {
            throw "Missing $req in env file $EnvFile"
        }
    }
}

function Write-Section($title) {
    Write-Host ''
    Write-Host ('=' * 72) -ForegroundColor Cyan
    Write-Host $title -ForegroundColor Cyan
    Write-Host ('=' * 72) -ForegroundColor Cyan
}

function Get-Token {
    param(
        [string] $Tenant,
        [string] $AppId,
        [string] $Secret,
        [string] $Scope
    )
    $body = @{
        grant_type    = 'client_credentials'
        client_id     = $AppId
        client_secret = $Secret
        scope         = $Scope
    }
    $resp = Invoke-RestMethod `
        -Method Post `
        -Uri    "https://login.microsoftonline.com/$Tenant/oauth2/v2.0/token" `
        -Body   $body `
        -ContentType 'application/x-www-form-urlencoded'
    return $resp
}

function Decode-JwtPayload {
    param([string] $Jwt)
    $parts = $Jwt.Split('.')
    if ($parts.Count -lt 2) { return $null }
    $p = $parts[1].Replace('-', '+').Replace('_', '/')
    switch ($p.Length % 4) { 2 { $p += '==' } 3 { $p += '=' } 1 { $p += '===' } }
    $bytes = [Convert]::FromBase64String($p)
    return ([Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json)
}

# ---------------------------------------------------------------------------
# 1. Acquire ARM token + decode
# ---------------------------------------------------------------------------
Write-Section '1. Acquire ARM token (https://management.azure.com/.default)'
try {
    $arm = Get-Token -Tenant $TenantId -AppId $ClientId -Secret $ClientSecret `
                     -Scope 'https://management.azure.com/.default'
    Write-Host "OK - token acquired. expires_in=$($arm.expires_in)s" -ForegroundColor Green
} catch {
    Write-Host "FAILED to acquire ARM token: $($_.Exception.Message)" -ForegroundColor Red
    throw
}

$claims = Decode-JwtPayload -Jwt $arm.access_token
$spOid = $claims.oid
$expUtc = ([DateTimeOffset]::FromUnixTimeSeconds([int64]$claims.exp)).UtcDateTime

[pscustomobject]@{
    Audience          = $claims.aud
    Tenant            = $claims.tid
    AppId             = $claims.appid
    ServicePrincipal  = $spOid
    AppIdAcr          = $claims.appidacr
    IdentityType      = if ($claims.idtyp) { $claims.idtyp } else { 'app' }
    ExpiresUtc        = $expUtc
    Roles             = ($claims.roles -join ', ')
} | Format-List

# ---------------------------------------------------------------------------
# 2. Microsoft Graph - directory roles assigned to this SP (Global Reader etc)
# ---------------------------------------------------------------------------
Write-Section '2. Entra directory roles assigned to this Service Principal'
try {
    $graph = Get-Token -Tenant $TenantId -AppId $ClientId -Secret $ClientSecret `
                       -Scope 'https://graph.microsoft.com/.default'
    $hdr = @{ Authorization = "Bearer $($graph.access_token)" }
    $uri = "https://graph.microsoft.com/v1.0/servicePrincipals/$spOid/transitiveMemberOf?`$select=id,displayName,roleTemplateId"
    $resp = Invoke-RestMethod -Method Get -Uri $uri -Headers $hdr
    if (-not $resp.value -or $resp.value.Count -eq 0) {
        Write-Host "No directory roles or group memberships visible to Graph." -ForegroundColor Yellow
        Write-Host "(Note: needs Application.Read.All / Directory.Read.All on the app to enumerate.)" -ForegroundColor DarkGray
    } else {
        $resp.value |
            Select-Object @{n='Type';e={ ($_.'@odata.type' -replace '#microsoft.graph.','') }},
                          displayName, roleTemplateId, id |
            Format-Table -AutoSize
    }
} catch {
    Write-Host "Could not enumerate directory roles via Graph: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "(This is non-fatal; ARM RBAC below is what the extractor really needs.)" -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# 3. Azure RBAC role assignments for this SP at the subscription scope
# ---------------------------------------------------------------------------
Write-Section '3. Azure RBAC role assignments for this SP (subscription scope)'
$armHdr = @{ Authorization = "Bearer $($arm.access_token)" }
try {
    $filter = "atScope() and assignedTo('$spOid')"
    $uri = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&`$filter=$([uri]::EscapeDataString($filter))"
    $assn = Invoke-RestMethod -Method Get -Uri $uri -Headers $armHdr
    if (-not $assn.value -or $assn.value.Count -eq 0) {
        Write-Host "NO Azure RBAC role assignments for this SP at or above this subscription." -ForegroundColor Red
        Write-Host "  -> This is almost certainly the cause of 401/403 against Sentinel APIs." -ForegroundColor Red
        Write-Host "  -> Assign 'Microsoft Sentinel Reader' (or 'Reader') to the SP at the workspace, RG, or subscription scope." -ForegroundColor Yellow
    } else {
        $rows = foreach ($a in $assn.value) {
            $roleId = ($a.properties.roleDefinitionId -split '/')[-1]
            $roleName = $null
            try {
                $rd = Invoke-RestMethod -Method Get -Headers $armHdr `
                    -Uri "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/roleDefinitions/$roleId`?api-version=2022-04-01"
                $roleName = $rd.properties.roleName
            } catch { $roleName = $roleId }
            [pscustomobject]@{
                Role       = $roleName
                Scope      = $a.properties.scope
                AssignedTo = $a.properties.principalId
            }
        }
        $rows | Format-Table -AutoSize
    }
} catch {
    Write-Host "Failed to query role assignments: $($_.Exception.Message)" -ForegroundColor Red
}

# ---------------------------------------------------------------------------
# 4. Real ARM probe: hit Sentinel watchlists endpoint
# ---------------------------------------------------------------------------
Write-Section '4. Probe Sentinel watchlists endpoint with this token'
$probeUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/watchlists?api-version=2025-07-01-preview"
Write-Host "GET $probeUri" -ForegroundColor DarkGray
try {
    $r = Invoke-WebRequest -Method Get -Uri $probeUri -Headers $armHdr -UseBasicParsing
    Write-Host "HTTP $($r.StatusCode) - watchlists endpoint reachable. Auth + RBAC look OK." -ForegroundColor Green
} catch {
    $resp = $_.Exception.Response
    if ($null -ne $resp) {
        $code = [int]$resp.StatusCode
        $reader = New-Object IO.StreamReader($resp.GetResponseStream())
        $body = $reader.ReadToEnd()
        Write-Host "HTTP $code" -ForegroundColor Red
        Write-Host $body -ForegroundColor DarkGray
        switch ($code) {
            401 { Write-Host "-> 401: token rejected. Likely an expired token, wrong tenant, or the SP secret is invalid." -ForegroundColor Yellow }
            403 { Write-Host "-> 403: authenticated but lacks RBAC. Add 'Microsoft Sentinel Reader' on the workspace." -ForegroundColor Yellow }
            404 { Write-Host "-> 404: subscription / resource group / workspace name is wrong, or workspace is in a different subscription." -ForegroundColor Yellow }
        }
    } else {
        Write-Host "Probe failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Section 'Done'
Write-Host "If section 3 was empty or section 4 returned 403, the App Registration"
Write-Host "is NOT recognized as authorized for Sentinel data plane regardless of"
Write-Host "any Entra 'Global Reader' role - assign an Azure RBAC role on the"
Write-Host "workspace (Microsoft Sentinel Reader is the least-privilege option for"
Write-Host "read-only export)."
