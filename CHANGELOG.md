# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased] - 2026-03-27

### Added

- **Workbook Extraction Fix** — Fixed `extract_workbooks()` to correctly fetch workbooks from the Azure API. The `Microsoft.Insights/workbooks` List endpoint requires a `category` query parameter; without it, zero results are returned. The extractor now queries both `sentinel` and `workbook` categories. Additionally, the server-side `sourceId` filter was replaced with client-side case-insensitive filtering because Azure stores resource paths in lowercase.

- **Workbook Restore** — Implemented `restore_workbooks()` in `sentinel_restore.py`. Each workbook is restored via a single PUT to `Microsoft.Insights/workbooks/{name}`.
  - Strips server-managed properties (`timeModified`, `userId`, `revision`) from the PUT body.
  - Rewrites `properties.sourceId` to point to the target workspace.
  - Rewrites `fallbackResourceIds` inside `serializedData` (case-insensitive match) to reference the target workspace.
  - Auto-detects the target resource group's Azure region for the `location` field.
  - Preserves top-level `kind`, `tags`, and `identity` fields; sanitises `principalId`/`tenantId` for SystemAssigned identities.
  - Supports `--generate-new-id` for fresh GUID assignment.
  - Updated `README.md` to reflect Workbooks as implemented for both extraction and restore.

- **Watchlist Restore** — Implemented `restore_watchlists()` in `sentinel_restore.py`. Watchlists and all their items are restored in a single PUT request per watchlist by embedding the full item data as CSV/TSV in the `rawContent` property. This avoids per-item API calls and the throttling that comes with thousands of individual requests.
  - Automatically infers `contentType` (`text/csv` or `text/tsv`) from the source filename when missing from the backup.
  - Generates proper RFC 4180-compliant CSV using Python's `csv` module, correctly handling values that contain commas, quotes, or newlines.
  - Strips server-managed properties (`watchlistId`, `provisioningState`, `tenantId`, audit fields, etc.) from the PUT body.
  - Updated `README.md` to reflect Watchlists as implemented for restore.

---

## [Unreleased] - 2026-03-24

### Added

- **GitHub Actions Workflow Support** — The extractor and restore tools can now run as GitHub Actions workflows, enabling fully automated daily backups and on-demand restoration directly from a GitHub repository.
  - New `configure_gh_workflow.sh` (Bash) and `configure_gh_workflow.ps1` (PowerShell) configuration scripts that generate a self-contained `gh/` directory with all required files.
  - **Extraction workflow** (`sentinel-extract.yml`): scheduled daily extraction (configurable cron) plus manual `workflow_dispatch` trigger. Commits changed backup files back to the repository with change detection.
  - **Restore workflow** (`sentinel-restore.yml`): optional scheduled trigger plus manual `workflow_dispatch` with configurable inputs (target workspace override, restore flags, generate-new-id, logic-app-mode).
  - Credentials (`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`) stored in a named GitHub Environment with support for protection rules and approval gates.
  - Workspace configuration (subscription ID, resource group, workspace name, optional resource groups) injected directly into workflow YAML `env:` blocks at generation time.
  - Restore flag validation step prevents shell injection via `workflow_dispatch` inputs.
  - Configuration scripts copy `code/sentinel_extractor.py`, `code/sentinel_restore.py`, and `code/requirements.txt` into `gh/code/` to create a self-contained deployable package.
  - Optional `gh` CLI integration: when the GitHub CLI is detected, scripts offer to create the GitHub Environment and set secrets automatically.
  - New `github.md` deployment guide covering prerequisites, script usage, GitHub Environment setup, workflow details, cross-tenant restoration, and troubleshooting.

---

## [SECURITY] 2026-03-24 — GitHub Actions Expression Injection via workflow_dispatch Inputs

**Finding reference:** FINDING-004
**Severity fixed:** MEDIUM
**Files changed:**
- configure_gh_workflow.sh (restore workflow template)
- configure_gh_workflow.ps1 (restore workflow template)

**Change summary**
Moved all `${{ github.event.inputs.* }}` references from `run:` shell blocks into `env:` blocks in the generated restore workflow template. GitHub Actions interpolates `${{ }}` expressions before shell execution, so attacker-controlled `workflow_dispatch` inputs in `run:` blocks could execute arbitrary shell commands. Using `env:` blocks sets the values as environment variables before the shell runs, preventing injection.

**Before (vulnerable)**
```yaml
- name: Validate restore flags
  run: |
    FLAGS="${{ github.event.inputs.restore_flags || '--restore-all' }}"
    ...
- name: Run Sentinel Restore
  run: |
    FLAGS="${{ steps.validate.outputs.flags }}"
    if [ "${{ github.event.inputs.generate_new_id }}" = "true" ]; then
    ...
    LOGIC_MODE="${{ github.event.inputs.logic_app_mode }}"
```

**After (fixed)**
```yaml
- name: Validate restore flags
  env:
    RAW_FLAGS: ${{ github.event.inputs.restore_flags || '--restore-all' }}
  run: |
    if ! echo "$RAW_FLAGS" | grep -qE '^(--[a-z][-a-z]*( +|$))+$'; then
    ...
- name: Run Sentinel Restore
  env:
    RESTORE_FLAGS: ${{ steps.validate.outputs.flags }}
    GENERATE_NEW_ID: ${{ github.event.inputs.generate_new_id }}
    LOGIC_APP_MODE: ${{ github.event.inputs.logic_app_mode }}
  run: |
    FLAGS="$RESTORE_FLAGS"
    if [ "$GENERATE_NEW_ID" = "true" ]; then
    ...
```

**Verification**
Regenerate the `gh/` directory using either configuration script and inspect the restore workflow YAML. Confirm that no `${{ github.event.inputs.* }}` expressions appear directly inside `run:` blocks — they should only appear in `env:` blocks.

---

## [Unreleased] - 2026-03-21

### Changed

- **Identity-Based Storage Authentication** — The Function App now exclusively uses Managed Identity for all storage access. Connection string support has been removed from:
  - `function_app/function_app.py` — Storage export always uses `DefaultAzureCredential` + `AZURE_STORAGE_ACCOUNT_URL`.
  - `configure_function_app.sh` / `configure_function_app.ps1` — Removed the connection string option; scripts now prompt only for the storage account URL.
  - `function_app/local.settings.json` — Replaced `AZURE_STORAGE_CONNECTION_STRING` with `AZURE_STORAGE_ACCOUNT_URL`.
  - The `AZURE_STORAGE_CONNECTION_STRING` application setting is no longer used.

- **AzureWebJobsStorage Identity-Based Auth** — The Functions runtime storage (`AzureWebJobsStorage`) is now configured via `AzureWebJobsStorage__accountName` instead of a connection string. Configuration scripts:
  - Prompt for the Function App's internal storage account name.
  - Remove any legacy `AzureWebJobsStorage` connection string setting.
  - Assign `Storage Blob Data Owner`, `Storage Queue Data Contributor`, and `Storage Table Data Contributor` RBAC roles on the runtime storage account.

- **Configuration Scripts — Automated Deployment** — Both `configure_function_app.sh` and `configure_function_app.ps1` now offer to deploy the Function App immediately after generating the ZIP package. If Azure Functions Core Tools (`func`) is installed, deployment uses `func azure functionapp publish` (supports Flex Consumption with remote build); otherwise falls back to `az functionapp deployment source config-zip`.

- **Configuration Scripts — Backup Storage RBAC** — When using storage export with a separate backup storage account, the scripts now assign `Storage Blob Data Contributor` on that account (in addition to the runtime storage roles).

### Added

- **GitHub Export — Change Detection Seeding** — When `EXPORT_TARGET=github`, the Function App now downloads existing files from the GitHub repository into the temp directory before running the extraction. This allows the extractor's change detection (`save_json` / `.file_tracker.json`) to compare against the previous backup and only commit actual changes, rather than pushing all files on every run.

- **Export Error Logging** — Added `try/except` with `log.exception()` around both GitHub and storage export calls in the main timer function. Previously, export failures produced only a generic "Failed" message; now the full traceback and error details are logged.

- **`azure-storage-blob` Dependency** — Added `azure-storage-blob>=12.19.0,<13.0.0` to `function_app/requirements.txt` (was previously missing, causing `ImportError` at runtime when using storage export).

### Documentation

- **README.md** — Added sections for: Azure Functions Core Tools deployment, manual function invocation via curl, GitHub token validation, and identity-based storage authentication with RBAC role tables.
- **README.md** — Removed `AZURE_STORAGE_CONNECTION_STRING` from the Function App settings table; replaced with `AZURE_STORAGE_ACCOUNT_URL`.

---

## [SECURITY] 2026-03-21 — Client Secret CLI Exposure Warning

**Finding reference:** FINDING-001
**Severity fixed:** MEDIUM
**Files changed:**
- code/sentinel_extractor.py (--client-secret argument, resolve_config)
- code/sentinel_restore.py (--client-secret argument, resolve_config)

**Change summary**
Added a deprecation-style warning to the `--client-secret` CLI argument help text and a runtime `WARNING`-level log message when the secret is passed via the command line. This alerts users that the secret is visible in process listings and directs them to use the `AZURE_CLIENT_SECRET` environment variable or `.env` file instead.

**Before (vulnerable)**
```python
parser.add_argument("--client-secret", help="App registration client secret (overrides env)")
```

**After (fixed)**
```python
parser.add_argument(
    "--client-secret",
    help="App registration client secret (overrides env). "
         "WARNING: passing secrets via CLI arguments exposes them in process "
         "listings (ps). Prefer setting AZURE_CLIENT_SECRET in a .env file.",
)
# + runtime warning when --client-secret is provided
```

**Verification**
Run `python sentinel_extractor.py --help` and confirm the warning appears in the `--client-secret` help text. Pass `--client-secret test` and observe the WARNING log line.

---

## [SECURITY] 2026-03-21 — Mask Sensitive Input in Configuration Scripts

**Finding reference:** FINDING-002
**Severity fixed:** LOW
**Files changed:**
- configure_function_app.sh (read_secret helper, connection string prompt)
- configure_function_app.ps1 (Read-Host -MaskInput for connection string)

**Change summary**
Storage account connection string input is now masked (not echoed to the terminal) during interactive configuration. Bash uses `read -srp` via a new `read_secret` helper; PowerShell uses `Read-Host -MaskInput`.

**Before (vulnerable)**
```bash
STORAGE_CONN_STR=$(read_value "Storage account connection string")
```

**After (fixed)**
```bash
STORAGE_CONN_STR=$(read_secret "Storage account connection string")
```

**Verification**
Run the configuration script and choose storage export with a connection string. Confirm the typed characters are not echoed to screen.

---

## [SECURITY] 2026-03-21 — Pin Dependency Version Upper Bounds

**Finding reference:** FINDING-003
**Severity fixed:** LOW
**Files changed:**
- code/requirements.txt (all lines)
- function_app/requirements.txt (all lines)

**Change summary**
Added `<N.0.0` upper-bound constraints to all dependencies to prevent automatic installation of future major versions that could introduce breaking changes or vulnerabilities.

**Before (vulnerable)**
```
requests>=2.31.0
```

**After (fixed)**
```
requests>=2.31.0,<3.0.0
```

**Verification**
Run `pip install -r code/requirements.txt` and `pip install -r function_app/requirements.txt` to confirm dependencies resolve correctly within the constrained ranges.

---

## [Unreleased] - 2026-03-21

### Added

- **Azure Function App Support** — The extractor can now run as a timer-triggered Azure Function App with Managed Identity authentication, enabling fully automated scheduled backups without App Registration credentials.
  - New `function_app/` directory with `function_app.py` (timer trigger), `host.json`, `local.settings.json`, and a dedicated `requirements.txt`.
  - Timer schedule is configurable via the `SCHEDULE` application setting (NCRONTAB format).
  - Supports two export targets: **Azure Blob Storage** (ZIP archive) and **GitHub repository** (via GitHub API).
  - Uses `DefaultAzureCredential` (Managed Identity) — no App Registration needed when deployed in Azure.
  - GitHub PAT is stored securely in **Azure Key Vault** and retrieved at runtime via Managed Identity — no secrets in app settings or code.

- **Configuration Scripts** — Cross-platform scripts to configure and package the Function App:
  - `configure_function_app.ps1` (PowerShell — Windows, macOS, Linux)
  - `configure_function_app.sh` (Bash — macOS, Linux, WSL)
  - Both scripts: collect Sentinel workspace details, set Function App application settings, assign RBAC roles to Managed Identity, and generate a deployment ZIP package.
  - Scripts support configuring export to either GitHub repository or Azure Storage Account.

- **Managed Identity Authentication** (`sentinel_extractor.py`):
  - New `--use-managed-identity` CLI flag and `USE_MANAGED_IDENTITY` environment variable.
  - New `get_access_token_managed_identity()` function using `azure.identity.DefaultAzureCredential`.
  - When enabled, `--tenant-id`, `--client-id`, and `--client-secret` are no longer required.
  - Client credentials flow remains the default for CLI usage.

- **Programmatic API** (`sentinel_extractor.py`):
  - New `run_extraction(cfg_overrides)` function for programmatic invocation (used by the Function App).
  - Internal refactoring: extraction logic moved to `_run_all_extractions()` helper.

### Changed

- **Directory Structure** — Python scripts moved to `code/` subdirectory. `sentinel_extractor.py` and `sentinel_restore.py` are now at `code/sentinel_extractor.py` and `code/sentinel_restore.py`. The `code/` directory is shared between CLI and Function App usage (single source of truth).
  - `requirements.txt` for CLI usage is now at `code/requirements.txt`.
  - A separate `function_app/requirements.txt` includes Azure Functions and Azure Identity dependencies.

## [Unreleased] - 2026-03-19

### Added

- **Hunting Relations Backup** (`sentinel_extractor.py`):
  - `extract_hunting()` now fetches hunt relations for each hunt via `GET .../hunts/{huntId}/relations` (paginated, API version `2025-07-01-preview`).
  - Relations (linked saved searches / queries) are saved as a separate `{HuntName}_details.json` file alongside the hunt's main JSON file in the `Hunting/` folder.
  - Each saved search referenced by a relation is fetched via `GET .../savedSearches/{id}` (API version `2025-07-01`) and saved to `Hunting/HuntingQueries/`.
  - If a hunt has no relations, no details file or queries are saved.
  - Documentation updated: `AGENT_INSTRUCTIONS_EXTRACTOR.md` (§2, §6, §10).

- **Hunting Restore** (`sentinel_restore.py`):
  - `restore_hunting()` replaces the previous stub with a full implementation.
  - Restore order per hunt: (1) PUT the hunt, (2) PUT hunting queries from `HuntingQueries/` via `PUT .../savedSearches/{id}` (API version `2025-07-01`), (3) PUT hunt relations.
  - Each hunt JSON file is PUT to `{sentinel_base}/hunts/{huntId}` (API version `2025-07-01-preview`).
  - After each hunt is restored, its saved-search queries are restored from the `HuntingQueries/` subfolder before relations are created.
  - Relations are read from `{HuntName}_details.json` and PUT to `.../hunts/{huntId}/relations/{relationId}`.
  - The `relatedResourceId` in each relation is rewritten to reference the target workspace (subscription, resource group, and workspace name are replaced).
  - The `--generate-new-id` flag is intentionally ignored for hunting — see Fixed section below.
  - If a hunt PUT fails, its queries and relations are skipped.
  - Documentation updated: `AGENT_INSTRUCTIONS_RESTORE.md` (§2, §4, §6).

### Fixed

- **Hunting Restore: `--generate-new-id` no longer applies to hunts, relations, or queries** (`sentinel_restore.py`):
  - The `--generate-new-id` flag is now intentionally ignored for the entire hunting restore. Hunts, relations, and hunting queries always keep their original IDs because relations reference hunts and queries by ID — assigning new IDs would break those links.

- **Change Detection & Versioned Backups** (`sentinel_extractor.py`):
  - `save_json()` now compares new content against existing files on disk. Files are only written (and counted as saved) when content has actually changed.
  - A per-resource file tracker (`.file_tracker.json`) is persisted in the output root, recording each file's name and `lastModified` timestamp. This ensures stable filename mapping across runs even if a resource's display name changes.
  - When content has changed, the old file is moved to an `older_versions/` subfolder within the same resource folder, with a `_YYYYMMDD_HHMMSS` timestamp appended to the filename (e.g. `MyRule_20260319_143000.json`).
  - `extract_table_retention()` now also performs change detection and backup before overwriting `table_retention.json`.

- **Per-Run Log Files** (`sentinel_extractor.py`):
  - Each run creates a timestamped log file (`run_YYYYMMDD_HHMMSS.log`) in a `logs/` directory within the output root.
  - The log captures all saved/updated files, backup moves, errors, and the final summary.
  - At the end of the run, the log records either the total number of changes or that no changes were detected.

### Fixed

- **Restore dependency ordering** (`sentinel_restore.py`):
  - When using `--restore-all`, resources are now restored in two phases to respect dependencies. Phase 1 (prerequisites): Custom Tables, Table Retention, Content Packages, Data Connectors, Product Settings. Phase 2 (dependent): Alert Rules, Automation Rules, Summary Rules, DCRs, DCEs, Saved Queries, and all remaining resource types.
  - Previously, Alert Rules, DCRs, DCEs, Saved Queries, and Summary Rules could fail when restored before their prerequisite resources (Custom Tables, Content Packages, Data Connectors) were in place.
  - Documentation updated: `AGENT_INSTRUCTIONS_RESTORE.md` (new §9 — Restore Order & Dependencies).

## [Unreleased] - 2026-03-17

### Added

- **Threat Intelligence Indicators** — full extraction and restore support.
  - **Extractor** (`sentinel_extractor.py`):
    - New `extract_threat_intelligence()` function that first queries the indicator count via `POST .../threatIntelligence/main/count` and then lists all indicators via `GET .../threatIntelligence/main/indicators` (paginated). Each indicator is saved as a separate JSON file in the `ThreatIntelligence/` output folder.
    - New `--skip-threat-intelligence` CLI flag to opt out of extraction.
    - API version: `2025-07-01-preview`.
  - **Restore** (`sentinel_restore.py`):
    - New `restore_threat_intelligence()` function that reads indicator JSON files from the `ThreatIntelligence/` backup folder and creates each indicator via `POST .../threatIntelligence/main/createIndicator`.
    - Server-managed properties stripped before POST: `lastUpdatedTimeUtc`, `friendlyName`, `additionalData`, `parsedPattern`.
    - New `--restore-threat-intelligence` CLI flag (also included in `--restore-all`).
    - API version: `2025-07-01-preview`.
  - Documentation updated: `README.md`.
