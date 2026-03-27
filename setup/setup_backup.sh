#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# setup_backup.sh
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
#   ./setup_backup.sh
#   ./setup_backup.sh --app-name "SentinelBackup" --subscription-id <sub-id> \
#       --resource-group <rg> --workspace-name <ws>
# ---------------------------------------------------------------------------

set -euo pipefail

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
cyan="\033[36m"
green="\033[32m"
yellow="\033[33m"
red="\033[31m"
bold="\033[1m"
reset="\033[0m"

step() {
    echo ""
    echo -e "${cyan}==> $1${reset}"
}

info() {
    echo -e "  $1"
}

error_exit() {
    echo -e "${red}ERROR: $1${reset}" >&2
    exit 1
}

read_value() {
    local prompt="$1"
    local default="${2:-}"
    local value
    if [ -n "$default" ]; then
        read -rp "  $prompt [$default]: " value
        echo "${value:-$default}"
    else
        read -rp "  $prompt: " value
        echo "$value"
    fi
}

read_required() {
    local prompt="$1"
    local value=""
    while [ -z "$value" ]; do
        read -rp "  $prompt: " value
        if [ -z "$value" ]; then
            echo -e "  ${yellow}This field is required.${reset}" >&2
        fi
    done
    echo "$value"
}

# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------
validate_uuid() {
    local value="$1"
    local label="$2"
    if [[ ! $value =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
        error_exit "Invalid $label: '$value' is not a valid UUID."
    fi
}

validate_resource_name() {
    local value="$1"
    local label="$2"
    if [[ ! $value =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]*$ ]]; then
        error_exit "Invalid $label: '$value' must start with alphanumeric and contain only alphanumeric, '.', '_', or '-'."
    fi
    if [[ ${#value} -gt 90 ]]; then
        error_exit "Invalid $label: '$value' exceeds 90 characters."
    fi
}

# ---------------------------------------------------------------------------
# Parse CLI arguments (all optional — interactive prompts fill gaps)
# ---------------------------------------------------------------------------
APP_NAME=""
SUBSCRIPTION_ID=""
RESOURCE_GROUP=""
WORKSPACE_NAME=""
LOGIC_APPS_RG=""
DCR_RG=""
DCE_RG=""
WORKBOOKS_RG=""
SECRET_EXPIRY=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --app-name)           APP_NAME="$2";         shift 2;;
        --subscription-id)    SUBSCRIPTION_ID="$2";  shift 2;;
        --resource-group)     RESOURCE_GROUP="$2";   shift 2;;
        --workspace-name)     WORKSPACE_NAME="$2";   shift 2;;
        --logic-apps-rg)      LOGIC_APPS_RG="$2";    shift 2;;
        --dcr-rg)             DCR_RG="$2";           shift 2;;
        --dce-rg)             DCE_RG="$2";           shift 2;;
        --workbooks-rg)       WORKBOOKS_RG="$2";     shift 2;;
        --secret-expiry)      SECRET_EXPIRY="$2";    shift 2;;
        -h|--help)
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --app-name NAME            App Registration display name"
            echo "  --subscription-id ID       Azure subscription ID"
            echo "  --resource-group RG        Sentinel workspace resource group"
            echo "  --workspace-name NAME      Log Analytics workspace name"
            echo "  --logic-apps-rg RG         Logic Apps resource group (optional)"
            echo "  --dcr-rg RG                DCR resource group (optional)"
            echo "  --dce-rg RG                DCE resource group (optional)"
            echo "  --workbooks-rg RG          Workbooks resource group (optional)"
            echo "  --secret-expiry YEARS      Client secret validity in years (default: 1)"
            echo "  -h, --help                 Show this help"
            exit 0;;
        *) error_exit "Unknown argument: $1";;
    esac
done

# ---------------------------------------------------------------------------
# Verify Azure CLI
# ---------------------------------------------------------------------------
if ! command -v az &>/dev/null; then
    error_exit "Azure CLI (az) is not installed. Install from https://aka.ms/install-azure-cli"
fi

ACCOUNT_JSON=$(az account show --output json 2>/dev/null || true)
if [ -z "$ACCOUNT_JSON" ] || [ "$ACCOUNT_JSON" = "null" ]; then
    error_exit "Not logged in to Azure CLI. Run 'az login' first."
fi

TENANT_ID=$(echo "$ACCOUNT_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['tenantId'])")

# ---------------------------------------------------------------------------
# Collect configuration interactively
# ---------------------------------------------------------------------------
step "Sentinel Extractor — Backup App Registration Setup"
echo "  This script creates an App Registration and assigns read-only"
echo "  permissions for sentinel_extractor.py to back up your Sentinel workspace."

step "App Registration"
[ -z "$APP_NAME" ] && APP_NAME=$(read_value "App Registration display name" "SentinelExtractor-Backup")
[ -z "$SECRET_EXPIRY" ] && SECRET_EXPIRY=$(read_value "Client secret validity (years)" "1")

step "Source Sentinel Workspace"
[ -z "$SUBSCRIPTION_ID" ] && SUBSCRIPTION_ID=$(read_required "Azure subscription ID")
[ -z "$RESOURCE_GROUP" ]  && RESOURCE_GROUP=$(read_required "Sentinel workspace resource group")
[ -z "$WORKSPACE_NAME" ]  && WORKSPACE_NAME=$(read_required "Log Analytics workspace name")

step "Optional Resource Groups (press Enter to use the workspace RG)"
echo "  If these resources live in a different resource group, specify it."
echo "  Leave blank to use the workspace resource group: ${RESOURCE_GROUP}"
[ -z "$LOGIC_APPS_RG" ] && LOGIC_APPS_RG=$(read_value "Logic Apps resource group" "")
[ -z "$DCR_RG" ]         && DCR_RG=$(read_value "DCR resource group" "")
[ -z "$DCE_RG" ]         && DCE_RG=$(read_value "DCE resource group" "")
[ -z "$WORKBOOKS_RG" ]   && WORKBOOKS_RG=$(read_value "Workbooks resource group" "$RESOURCE_GROUP")

# ---------------------------------------------------------------------------
# Validate inputs
# ---------------------------------------------------------------------------
step "Validating inputs..."
validate_uuid "$SUBSCRIPTION_ID" "subscription ID"
validate_resource_name "$RESOURCE_GROUP" "resource group"
validate_resource_name "$WORKSPACE_NAME" "workspace name"
[ -n "$LOGIC_APPS_RG" ] && validate_resource_name "$LOGIC_APPS_RG" "Logic Apps resource group"
[ -n "$DCR_RG" ]         && validate_resource_name "$DCR_RG" "DCR resource group"
[ -n "$DCE_RG" ]         && validate_resource_name "$DCE_RG" "DCE resource group"
[ -n "$WORKBOOKS_RG" ]   && validate_resource_name "$WORKBOOKS_RG" "Workbooks resource group"
info "All inputs valid."

# ---------------------------------------------------------------------------
# Set subscription context
# ---------------------------------------------------------------------------
step "Setting Azure CLI subscription..."
az account set --subscription "$SUBSCRIPTION_ID"
info "Subscription: $SUBSCRIPTION_ID"

# ---------------------------------------------------------------------------
# Validate workspace exists
# ---------------------------------------------------------------------------
step "Validating workspace..."
WS_CHECK=$(az monitor log-analytics workspace show \
    --resource-group "$RESOURCE_GROUP" \
    --workspace-name "$WORKSPACE_NAME" \
    --query "id" --output tsv 2>/dev/null || true)

if [ -z "$WS_CHECK" ]; then
    error_exit "Workspace '$WORKSPACE_NAME' not found in resource group '$RESOURCE_GROUP'."
fi
info "Workspace found: $WORKSPACE_NAME"

# ---------------------------------------------------------------------------
# Create App Registration
# ---------------------------------------------------------------------------
step "Creating App Registration: $APP_NAME"

EXISTING_APP=$(az ad app list --display-name "$APP_NAME" --query "[0].appId" --output tsv 2>/dev/null || true)
if [ -n "$EXISTING_APP" ]; then
    echo -e "  ${yellow}App Registration '$APP_NAME' already exists (appId: $EXISTING_APP).${reset}"
    echo "  Reusing existing App Registration."
    APP_ID="$EXISTING_APP"
else
    APP_ID=$(az ad app create --display-name "$APP_NAME" --query "appId" --output tsv)
    info "App Registration created: $APP_ID"
fi

# ---------------------------------------------------------------------------
# Ensure Service Principal exists
# ---------------------------------------------------------------------------
step "Ensuring Service Principal exists..."
SP_OBJECT_ID=$(az ad sp show --id "$APP_ID" --query "id" --output tsv 2>/dev/null || true)

if [ -z "$SP_OBJECT_ID" ]; then
    SP_OBJECT_ID=$(az ad sp create --id "$APP_ID" --query "id" --output tsv)
    info "Service Principal created: $SP_OBJECT_ID"
else
    info "Service Principal already exists: $SP_OBJECT_ID"
fi

# ---------------------------------------------------------------------------
# Create Client Secret
# ---------------------------------------------------------------------------
step "Creating client secret (valid for $SECRET_EXPIRY year(s))..."
END_DATE=$(date -v+"${SECRET_EXPIRY}y" "+%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || \
           date -d "+${SECRET_EXPIRY} years" "+%Y-%m-%dT%H:%M:%SZ" 2>/dev/null)

SECRET_JSON=$(az ad app credential reset \
    --id "$APP_ID" \
    --append \
    --display-name "SentinelExtractor-Backup" \
    --end-date "$END_DATE" \
    --query "{password: password}" \
    --output json)

CLIENT_SECRET=$(echo "$SECRET_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['password'])")
info "Client secret created."

# ---------------------------------------------------------------------------
# Assign RBAC roles
# ---------------------------------------------------------------------------
step "Assigning RBAC roles for backup (read-only)..."

ROLE_WARNINGS=0

assign_role() {
    local role="$1"
    local scope="$2"
    local label="${3:-}"
    echo -n "  Assigning ${role}"
    [ -n "$label" ] && echo -n " (${label})"
    echo "..."
    if az role assignment create \
        --assignee-object-id "$SP_OBJECT_ID" \
        --assignee-principal-type ServicePrincipal \
        --role "$role" \
        --scope "$scope" \
        --output none 2>/dev/null; then
        echo -e "    ${green}✓ Assigned${reset}"
    else
        # Check if the role is already assigned (idempotent)
        local existing
        existing=$(az role assignment list \
            --assignee "$SP_OBJECT_ID" \
            --role "$role" \
            --scope "$scope" \
            --query "length(@)" \
            --output tsv 2>/dev/null || echo "0")
        if [ "$existing" -gt 0 ] 2>/dev/null; then
            echo -e "    ${green}✓ Already assigned${reset}"
        else
            echo -e "    ${red}✗ Failed — ensure you have Owner or User Access Administrator on this scope.${reset}"
            ROLE_WARNINGS=$((ROLE_WARNINGS + 1))
        fi
    fi
}

# Core workspace RG: Reader + Microsoft Sentinel Reader
WS_SCOPE="/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP"
assign_role "Reader" "$WS_SCOPE" "workspace RG"
assign_role "Microsoft Sentinel Reader" "$WS_SCOPE" "workspace RG"

# Additional RGs (only if different from the workspace RG)
ASSIGNED_RGS=("$RESOURCE_GROUP")

add_rg_reader() {
    local rg="$1"
    local label="$2"
    if [ -n "$rg" ]; then
        # Check if already assigned (avoid duplicate)
        local already=false
        for assigned in "${ASSIGNED_RGS[@]}"; do
            if [ "$assigned" = "$rg" ]; then
                already=true
                break
            fi
        done
        if [ "$already" = false ]; then
            local scope="/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$rg"
            assign_role "Reader" "$scope" "$label"
            ASSIGNED_RGS+=("$rg")
        fi
    fi
}

add_rg_reader "$LOGIC_APPS_RG" "Logic Apps RG"
add_rg_reader "$DCR_RG" "DCR RG"
add_rg_reader "$DCE_RG" "DCE RG"
add_rg_reader "$WORKBOOKS_RG" "Workbooks RG"

if [ "$ROLE_WARNINGS" -gt 0 ]; then
    echo -e "  ${yellow}WARNING: $ROLE_WARNINGS role assignment(s) failed. See messages above.${reset}"
else
    echo -e "  ${green}RBAC assignments complete.${reset}"
fi

# ---------------------------------------------------------------------------
# Write credentials to file (not stdout) for security
# ---------------------------------------------------------------------------
step "Writing credentials..."
ENV_FILE=".env.sentinel-backup"
cat > "$ENV_FILE" << EOF
AZURE_TENANT_ID=$TENANT_ID
AZURE_CLIENT_ID=$APP_ID
AZURE_CLIENT_SECRET=$CLIENT_SECRET
AZURE_SUBSCRIPTION_ID=$SUBSCRIPTION_ID
AZURE_RESOURCE_GROUP=$RESOURCE_GROUP
AZURE_WORKSPACE_NAME=$WORKSPACE_NAME
EOF
[ -n "$LOGIC_APPS_RG" ] && echo "AZURE_LOGIC_APPS_RESOURCE_GROUP=$LOGIC_APPS_RG" >> "$ENV_FILE"
[ -n "$DCR_RG" ] && echo "AZURE_DCR_RESOURCE_GROUP=$DCR_RG" >> "$ENV_FILE"
[ -n "$DCE_RG" ] && echo "AZURE_DCE_RESOURCE_GROUP=$DCE_RG" >> "$ENV_FILE"
[ -n "$WORKBOOKS_RG" ] && [ "$WORKBOOKS_RG" != "$RESOURCE_GROUP" ] && echo "AZURE_WORKBOOKS_RESOURCE_GROUP=$WORKBOOKS_RG" >> "$ENV_FILE"
chmod 600 "$ENV_FILE"

step "Setup complete!"
echo ""
echo -e "${bold}╔══════════════════════════════════════════════════════════════╗${reset}"
echo -e "${bold}║  App Registration Created                                  ║${reset}"
echo -e "${bold}╠══════════════════════════════════════════════════════════════╣${reset}"
echo -e "${bold}║${reset}  AZURE_TENANT_ID       = ${green}${TENANT_ID}${reset}"
echo -e "${bold}║${reset}  AZURE_CLIENT_ID       = ${green}${APP_ID}${reset}"
echo -e "${bold}║${reset}  AZURE_CLIENT_SECRET   = ${green}(written to $ENV_FILE)${reset}"
echo -e "${bold}║${reset}  AZURE_SUBSCRIPTION_ID = ${green}${SUBSCRIPTION_ID}${reset}"
echo -e "${bold}╠══════════════════════════════════════════════════════════════╣${reset}"
echo -e "${bold}║${reset}  AZURE_RESOURCE_GROUP  = ${green}${RESOURCE_GROUP}${reset}"
echo -e "${bold}║${reset}  AZURE_WORKSPACE_NAME  = ${green}${WORKSPACE_NAME}${reset}"
if [ -n "$LOGIC_APPS_RG" ]; then
echo -e "${bold}║${reset}  AZURE_LOGIC_APPS_RESOURCE_GROUP = ${green}${LOGIC_APPS_RG}${reset}"
fi
if [ -n "$DCR_RG" ]; then
echo -e "${bold}║${reset}  AZURE_DCR_RESOURCE_GROUP        = ${green}${DCR_RG}${reset}"
fi
if [ -n "$DCE_RG" ]; then
echo -e "${bold}║${reset}  AZURE_DCE_RESOURCE_GROUP        = ${green}${DCE_RG}${reset}"
fi
if [ -n "$WORKBOOKS_RG" ] && [ "$WORKBOOKS_RG" != "$RESOURCE_GROUP" ]; then
echo -e "${bold}║${reset}  AZURE_WORKBOOKS_RESOURCE_GROUP  = ${green}${WORKBOOKS_RG}${reset}"
fi
echo -e "${bold}╚══════════════════════════════════════════════════════════════╝${reset}"
echo ""
echo -e "  Credentials written to: ${green}${ENV_FILE}${reset} (permissions: 0600)"
echo -e "${yellow}⚠  The client secret is in $ENV_FILE — never commit this file to version control.${reset}"
echo -e "${yellow}⚠  The secret cannot be retrieved from Azure later — keep the file safe.${reset}"
echo ""
echo "  To use with sentinel_extractor.py, copy or rename the file:"
echo "    cp $ENV_FILE .env"
echo ""
