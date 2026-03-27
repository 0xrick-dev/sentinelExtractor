# Sentinel Extractor & Restore

> **Disclaimer:** This is an open-source community project and is **not officially supported by Microsoft**. It is provided as-is under the [MIT License](LICENSE). Use at your own risk. For official Microsoft Sentinel tooling, refer to the [Microsoft Sentinel documentation](https://learn.microsoft.com/en-us/azure/sentinel/).

A set of Python tools for backing up and restoring Microsoft Sentinel and related Azure resource configurations to/from local JSON files. Can be run from the CLI, deployed as an Azure Function App for automated scheduled backups, or run as GitHub Actions workflows for fully automated daily backups and on-demand restoration.

- **`code/sentinel_extractor.py`** — Extracts the full configuration of a Sentinel workspace (alert rules, automation rules, data connectors, custom tables, workbooks, logic apps, and more) into per-resource JSON files.
- **`code/sentinel_restore.py`** — Restores configuration from those JSON backups into a target Sentinel workspace, supporting cross-environment migrations and disaster recovery.
- **`function_app/`** — Azure Function App that runs the extractor on a configurable timer schedule using Managed Identity, exporting backups to Azure Blob Storage or GitHub.

## Supported Resource Types

### Extraction

All of the following resource types are fully supported for extraction:

Alert Rules, Automation Rules, Summary Rules, Hunting Queries, Workspace Functions, Saved Queries, Data Collection Rules (DCRs), Data Collection Endpoints (DCEs), Workbooks, Logic Apps, Watchlists, Custom Tables, Table Retention, Content Packages, Data Connectors, Product Settings, IAM Role Assignments, and Threat Intelligence Indicators.

### Restoration

Restoration is supported for most of the above resource types. However, the following are **not yet implemented** for restore and are planned for future releases:

| Resource Type | Restore Status |
|---|---|
| IAM Role Assignments | :x: Not implemented — coming in a future release |

## Project Structure

```
.
├── code/                              # Shared Python source (CLI + Function App)
│   ├── sentinel_extractor.py
│   ├── sentinel_restore.py
│   └── requirements.txt               # CLI dependencies
├── function_app/                      # Azure Function App
│   ├── function_app.py                # Timer-triggered entry point
│   ├── host.json
│   ├── local.settings.json            # Local dev settings (template)
│   └── requirements.txt               # Function App dependencies
├── gh/                                # Generated GitHub Actions package (see github.md)
│   └── code/                          # Copied source for self-contained deployment
├── configure_function_app.ps1         # PowerShell — Function App config & deploy
├── configure_function_app.sh          # Bash — Function App config & deploy
├── configure_gh_workflow.ps1          # PowerShell — GitHub Actions workflow generator
├── configure_gh_workflow.sh           # Bash — GitHub Actions workflow generator
├── github.md                          # GitHub Actions deployment guide
├── .env.example
├── AGENT_INSTRUCTIONS_EXTRACTOR.md
├── AGENT_INSTRUCTIONS_RESTORE.md
├── CHANGELOG.md
├── LICENSE
└── README.md
```

## Prerequisites

- Python 3.8+
- **For CLI usage:** An Azure App Registration with client credentials (tenant ID, client ID, client secret), _or_ use `--use-managed-identity` in an Azure-hosted environment.
- **For Function App:** A deployed Azure Function App with a system-assigned Managed Identity enabled.
- A `.env` file (or CLI arguments) supplying the required configuration values.

### Authentication

The extractor supports two authentication methods:

| Method | When to use | Required config |
|---|---|---|
| **Client Credentials** (default) | CLI on any machine | `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` |
| **Managed Identity** | Azure Function App, Azure VM, Cloud Shell | `--use-managed-identity` flag or `USE_MANAGED_IDENTITY=true` |

### App Registration Permissions (Client Credentials)

The App Registration (service principal) must be granted Azure RBAC roles on the relevant resource groups and workspaces. The minimum required roles depend on whether you are extracting, restoring, or both.

#### Extraction (source workspace — read-only)

| Role | Scope | Purpose |
|---|---|---|
| **Reader** | Source workspace resource group | Read all Sentinel resources, tables, workspace functions, saved queries, DCEs, workbooks, IAM role assignments |
| **Microsoft Sentinel Reader** | Source workspace | Read alert rules, automation rules, hunting queries, watchlists, data connectors, content packages, product settings, threat intelligence indicators |
| **Reader** | Logic Apps resource group (if different) | Read Logic App workflow definitions |
| **Reader** | DCR resource group (if different) | Read Data Collection Rules |
| **Reader** | DCE resource group (if different) | Read Data Collection Endpoints |

#### Restoration (target workspace — read/write)

| Role | Scope | Purpose |
|---|---|---|
| **Contributor** | Target workspace resource group | Create/update custom tables, table retention, workspace functions, saved queries |
| **Microsoft Sentinel Contributor** | Target workspace | Create/update alert rules, automation rules, hunting queries, watchlists, data connectors, content packages, product settings, threat intelligence indicators |
| **Contributor** | Target Logic Apps resource group | Create/update Logic App workflows |
| **Contributor** | Target DCR resource group | Create/update Data Collection Rules |
| **Contributor** | Target DCE resource group | Create/update Data Collection Endpoints |
| **Contributor** | Target Workbooks resource group | Create/update workbooks |

> **Tip:** For a quick start, assign **Contributor** + **Microsoft Sentinel Contributor** at the subscription level. For production, scope roles to the specific resource groups used by each resource type.

### Install dependencies

For CLI usage:

```bash
pip install -r code/requirements.txt
```

For Function App development:

```bash
pip install -r function_app/requirements.txt
```

## Configuration

Both scripts read configuration from a `.env` file in the project root and/or CLI arguments. CLI arguments take precedence over `.env` values.

### Required `.env` variables

```dotenv
AZURE_TENANT_ID=<your-tenant-id>
AZURE_CLIENT_ID=<your-client-id>
AZURE_CLIENT_SECRET=<your-client-secret>
AZURE_SUBSCRIPTION_ID=<your-subscription-id>
AZURE_RESOURCE_GROUP=<sentinel-workspace-resource-group>
AZURE_WORKSPACE_NAME=<log-analytics-workspace-name>
```

> When using `--use-managed-identity`, the `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, and `AZURE_CLIENT_SECRET` variables are not required.

### Optional `.env` variables (extractor)

```dotenv
AZURE_LOGIC_APPS_RESOURCE_GROUP=<rg-for-logic-apps>
AZURE_DCR_RESOURCE_GROUP=<rg-for-dcrs>
AZURE_DCE_RESOURCE_GROUP=<rg-for-dces>
AZURE_WORKBOOKS_RESOURCE_GROUP=<rg-for-workbooks>
```

### Additional `.env` variables (restore)

```dotenv
AZURE_TARGET_SUBSCRIPTION_ID=<target-subscription-id>
AZURE_TARGET_RESOURCE_GROUP=<target-resource-group>
AZURE_TARGET_WORKSPACE_NAME=<target-workspace-name>
AZURE_BACKUP_SOURCE_DIR=./output/<subscription-id>/<workspace-name>
```

## Usage

### CLI — Extracting

Extract all supported resource types (default):

```bash
python code/sentinel_extractor.py
```

Extract using Managed Identity (in Azure-hosted environments):

```bash
python code/sentinel_extractor.py --use-managed-identity
```

Extract to a custom output directory:

```bash
python code/sentinel_extractor.py --output-dir ./my-backup
```

Skip specific resource types:

```bash
python code/sentinel_extractor.py --skip-alert-rules --skip-watchlists
```

Override `.env` values via CLI:

```bash
python code/sentinel_extractor.py --subscription-id <id> --workspace-name <name>
```

### CLI — Restoring

Restore all implemented resource types:

```bash
python code/sentinel_restore.py --restore-all
```

Restore only specific resource types:

```bash
python code/sentinel_restore.py --restore-alert-rules --restore-automation-rules
```

Generate new IDs to avoid 409 soft-delete conflicts:

```bash
python code/sentinel_restore.py --restore-alert-rules --generate-new-id
```

Specify the backup source directory:

```bash
python code/sentinel_restore.py --restore-all \
  --backup-source-dir ./output/e87ecc5c-.../my-workspace
```

> **Safety:** Nothing is restored unless at least one `--restore-*` flag (or `--restore-all`) is passed.

> **:warning: Important:** Always test the restore process on a **temporary or non-production Sentinel workspace** before restoring to a production environment. This ensures that the backup files are valid, the restore behaves as expected, and no unintended changes are made to your live configuration.

### Restore Guidelines

#### Available Restore Flags

| Flag | Resource Type | Status |
|---|---|---|
| `--restore-all` | All implemented resource types | — |
| `--restore-alert-rules` | Alert Rules | :white_check_mark: Implemented |
| `--restore-automation-rules` | Automation Rules | :white_check_mark: Implemented |
| `--restore-summary-rules` | Summary Rules | :white_check_mark: Implemented |
| `--restore-hunting` | Hunting Queries & Relations | :white_check_mark: Implemented |
| `--restore-workspace-functions` | Workspace Functions (parsers) | :white_check_mark: Implemented |
| `--restore-saved-queries` | Saved Queries | :x: Not yet implemented |
| `--restore-watchlists` | Watchlists | :x: Not yet implemented |
| `--restore-dcr` | Data Collection Rules | :white_check_mark: Implemented |
| `--restore-dce` | Data Collection Endpoints | :white_check_mark: Implemented |
| `--restore-workbooks` | Workbooks | :x: Not yet implemented |
| `--restore-logic-apps` | Logic Apps | :white_check_mark: Implemented |
| `--restore-custom-tables` | Custom Tables | :white_check_mark: Implemented |
| `--restore-table-retention` | Table Retention Settings | :white_check_mark: Implemented |
| `--restore-product-settings` | Product Settings | :white_check_mark: Implemented |
| `--restore-data-connectors` | Data Connectors | :white_check_mark: Implemented |
| `--restore-content-packages` | Content Packages (solutions) | :white_check_mark: Implemented |
| `--restore-threat-intelligence` | Threat Intelligence Indicators | :white_check_mark: Implemented |

#### Restore Phases

When using `--restore-all`, resources are restored in dependency order across two phases:

**Phase 1 — Prerequisites:**
Custom Tables, Table Retention, Content Packages, Data Connectors, Product Settings

**Phase 2 — Dependent Resources:**
Alert Rules, Automation Rules, Summary Rules, Hunting, Workspace Functions, DCRs, DCEs, Logic Apps, Threat Intelligence

This ordering ensures that dependent resources (e.g., alert rules referencing custom tables) find their prerequisites already in place.

#### Idempotency & Resource IDs

- **Without `--generate-new-id`** — the original resource ID from the backup is reused. Repeated runs are safe because the API performs a create-or-update (PUT).
- **With `--generate-new-id`** — a fresh UUID is generated for each resource, useful when Azure's soft-delete cooldown would cause a 409 conflict.
- **Built-in rules** (e.g., `BuiltInFusion`) are always restored with their original name, even when `--generate-new-id` is set.

#### 409 Soft-Delete Conflicts

Some Azure resources (Alert Rules, Summary Rules) enforce a soft-delete cooldown period. If you receive a 409 error with "recently deleted" in the message, use `--generate-new-id` to assign fresh GUIDs. The restore script automatically retries with new UUIDs up to 5 times when this flag is enabled.

#### Logic App Restore Modes

Logic Apps contain API connection references that require special handling depending on the restore scenario:

| Mode | CLI Flag | When to Use |
|---|---|---|
| **Same tenant** (default) | `--logic-app-mode same-tenant` | Restoring within the same tenant. Connection paths are rewritten to match the target subscription, resource group, and location. |
| **New environment** | `--logic-app-mode new-environment` | Restoring to a different tenant. All connection references are stripped; you must recreate them manually afterwards. |

#### Region Handling

- **DCRs and DCEs** are automatically created in the target resource group's region, regardless of the region in the backup.
- **Logic Apps** use `--target-location` to specify the target region when it differs from the source.

#### Per-Resource Error Handling

A failure on one resource never aborts the entire restore. Errors are logged and the next file is processed, ensuring maximum coverage even when individual resources encounter issues.

## Deployment Options

The extractor and restore tools support three deployment models:

| Method | Use Case | Guide |
|---|---|---|
| **CLI** | Ad-hoc extraction/restoration from any machine | This README (see [Usage](#usage) above) |
| **Azure Function App** | Automated scheduled backups on a configurable timer using Managed Identity | This README (see below) |
| **GitHub Actions** | Automated scheduled backups and on-demand restoration via CI/CD pipelines | [github.md](github.md) |

The **Azure Function App** and **GitHub Actions** deployment options are designed for **automated, schedule-based backups** — they run the extractor on a recurring timer (e.g., daily at 2 AM UTC) so that your Sentinel configuration is continuously backed up without manual intervention.

## GitHub Actions Deployment

The extractor and restore tools can be deployed as GitHub Actions workflows for fully automated daily backups and on-demand restoration. This approach uses an Azure App Registration with credentials stored securely in GitHub Environment secrets.

For full setup instructions, workflow details, cross-tenant restoration, and troubleshooting, see the **[GitHub Actions Deployment Guide](github.md)**.

## Function App Deployment

The Function App runs the extractor on a configurable timer schedule using Managed Identity. Backups can be exported to Azure Blob Storage or a GitHub repository.

### Prerequisites

1. An Azure Function App (Python, Linux) already deployed with:
   - **System-assigned Managed Identity** enabled
   - **Python 3.8+** runtime stack
2. Azure CLI (`az`) installed and authenticated

### Configuration & Packaging

Use the configuration script for your platform. The script will:
1. Prompt for your Sentinel workspace details and export target
2. Set the application settings on the Function App
3. Assign the required RBAC roles to the Managed Identity
4. Generate a ZIP deployment package

**PowerShell** (Windows, macOS, Linux):

```powershell
./configure_function_app.ps1 `
    -SubscriptionId "<func-app-subscription>" `
    -ResourceGroup "<func-app-rg>" `
    -FunctionAppName "<func-app-name>"
```

**Bash** (macOS, Linux, WSL):

```bash
./configure_function_app.sh \
    --subscription-id "<func-app-subscription>" \
    --resource-group "<func-app-rg>" \
    --function-app-name "<func-app-name>"
```

### Deploying the ZIP Package

After the script generates the ZIP file, deploy it using one of:

1. **Azure Portal:** Function App → Deployment Center → Upload ZIP
2. **Azure CLI:**

```bash
az functionapp deployment source config-zip \
    --name <func-app-name> \
    --resource-group <func-app-rg> \
    --src sentinel_extractor_funcapp_<timestamp>.zip
```

3. **Azure Functions Core Tools** (recommended for Flex Consumption plans):

```bash
# Stage the deployment package
STAGING=$(mktemp -d)
cp -R function_app/* "$STAGING/"
mkdir -p "$STAGING/code"
cp -R code/*.py "$STAGING/code/"
cp code/requirements.txt "$STAGING/code/"
rm -f "$STAGING/local.settings.json"
rm -rf "$STAGING/__pycache__" "$STAGING/code/__pycache__"

# Install dependencies locally (Flex Consumption does not support remote build)
pip install -r "$STAGING/requirements.txt" \
    --target "$STAGING/.python_packages/lib/site-packages" --quiet

cd "$STAGING"
func azure functionapp publish <func-app-name> --no-build
```

> **Note:** The configuration script offers to deploy automatically at the end. If you have Azure Functions Core Tools (`func`) installed, it will use `func azure functionapp publish`; otherwise it falls back to ZIP deploy via `az`.

### Manual Invocation

To trigger the backup function manually (outside the timer schedule):

```bash
curl -s -X POST "https://<func-app-name>.azurewebsites.net/admin/functions/sentinel_backup_timer" \
  -H "Content-Type: application/json" \
  -H "x-functions-key: $(az functionapp keys list --name <func-app-name> --resource-group <func-app-rg> --query masterKey -o tsv)" \
  -d '{"input": ""}'
```

### Validating GitHub Export

If using GitHub export, verify that the Function App's GitHub token (stored in Key Vault) has access to the target repository:

```bash
TOKEN=$(az keyvault secret show --vault-name <vault-name> --name <secret-name> --query value -o tsv)
curl -s -H "Authorization: Bearer $TOKEN" "https://api.github.com/repos/<owner>/<repo>"
```

The token must be a fine-grained PAT with **Contents: Read and write** and **Metadata: Read-only** permissions on the target repository.

### Identity-Based Storage Authentication

The Function App uses Managed Identity for all storage access — no connection strings or account keys are used. The configuration script automatically:

1. Sets `AzureWebJobsStorage__accountName` for the Functions runtime (replaces the `AzureWebJobsStorage` connection string)
2. Sets `AZURE_STORAGE_ACCOUNT_URL` for backup export (if using storage export)
3. Assigns the following RBAC roles to the Managed Identity:

| Role | Scope | Purpose |
|---|---|---|
| **Storage Blob Data Owner** | Runtime storage account | Functions runtime (leases, triggers, state) |
| **Storage Queue Data Contributor** | Runtime storage account | Functions runtime (queue triggers) |
| **Storage Table Data Contributor** | Runtime storage account | Functions runtime (timer state) |
| **Storage Blob Data Contributor** | Backup storage account | Upload backup archives (if using storage export) |

### Function App Settings

| Setting | Description | Default |
|---|---|---|
| `SCHEDULE` | NCRONTAB timer expression | `0 0 2 * * *` (daily 2 AM) |
| `AZURE_SUBSCRIPTION_ID` | Sentinel workspace subscription ID | — |
| `AZURE_RESOURCE_GROUP` | Sentinel workspace resource group | — |
| `AZURE_WORKSPACE_NAME` | Log Analytics workspace name | — |
| `AZURE_LOGIC_APPS_RESOURCE_GROUP` | Logic Apps resource group (optional) | — |
| `AZURE_DCR_RESOURCE_GROUP` | DCR resource group (optional) | — |
| `AZURE_DCE_RESOURCE_GROUP` | DCE resource group (optional) | — |
| `AZURE_WORKBOOKS_RESOURCE_GROUP` | Workbooks resource group (optional) | — |
| `EXPORT_TARGET` | `storage` or `github` | `storage` |
| `AZURE_STORAGE_ACCOUNT_URL` | Storage account URL (e.g. `https://myaccount.blob.core.windows.net`) | — |
| `AZURE_STORAGE_CONTAINER_NAME` | Blob container name | `sentinel-backup` |
| `KEYVAULT_URL` | Key Vault URL for secrets (required for GitHub export) | — |
| `KEYVAULT_GITHUB_TOKEN_SECRET` | Secret name in Key Vault holding the GitHub PAT | `github-token` |
| `GITHUB_REPO` | GitHub repo (`owner/repo`) | — |
| `GITHUB_BRANCH` | GitHub branch | `main` |

## Output Structure

The extractor produces the following directory layout:

```
output/
└── <subscription_id>/
    └── <workspace_name>/
        ├── AlertRules/
        ├── AutomationRules/
        ├── ContentPackages/
        ├── CustomTables/
        ├── DataCollectionEndpoints/
        ├── DataCollectionRules/
        ├── DataConnectors/
        ├── Hunting/
        ├── IAM/
        ├── LogicApps/
        ├── ProductSettings/
        ├── SavedQueries/
        ├── SummaryRules/
        ├── ThreatIntelligence/
        ├── Watchlists/
        ├── Workbooks/
        ├── WorkspaceFunctions/
        └── table_retention.json
```

Each resource is saved as a full-fidelity JSON document exactly as returned by the Azure REST API.

## Contributing & Feedback

This is an open-source project — contributions, bug reports, and feature requests are welcome!

- **Bug reports & feature requests:** Please submit them via [GitHub Issues](https://github.com/0xrick-dev/sentinelExtractor/issues) on the project repository.
- **Pull requests:** Contributions are appreciated. Please open an issue first to discuss the proposed change.

## License

This project is licensed under the [MIT License](LICENSE).
