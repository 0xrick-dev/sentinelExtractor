"""
AUTHOR: Predrag (Peter) Petrovic (ppetrovic@microsoft.com)
DESCRIPTION: Sentinel configuration restore proof of concept.

sentinel_restore.py
-------------------
Restore Microsoft Sentinel configuration from JSON backup files produced by
sentinel_extractor.py.

Usage:
    # Restore only automation rules
    python sentinel_restore.py --restore-automation-rules

    # Restore everything
    python sentinel_restore.py --restore-all

All options can be supplied via CLI arguments or the .env file (CLI takes
precedence).  Run with --help for the full list.

SAFETY: Nothing is restored unless you pass at least one --restore-* flag
(or --restore-all).  This prevents accidental overwrites.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import logging
import os
import re
import uuid
from pathlib import Path

import requests
from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MANAGEMENT_BASE = "https://management.azure.com"
AUTH_URL_TEMPLATE = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
SCOPE = "https://management.azure.com/.default"

WORKSPACE_BASE = (
    "{base}/subscriptions/{subscription_id}"
    "/resourceGroups/{resource_group}"
    "/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}"
)

# API versions used for PUT / create-or-update calls
API_VERSION_ALERT_RULES      = "2023-12-01-preview"
API_VERSION_AUTOMATION_RULES = "2025-01-01-preview"
API_VERSION_SUMMARY_RULES    = "2025-07-01"
API_VERSION_DCR              = "2024-03-11"
API_VERSION_DCE              = "2024-03-11"
API_VERSION_LOGIC_APPS       = "2019-05-01"
API_VERSION_WORKSPACE_FUNCTIONS = "2020-08-01"
API_VERSION_TABLES              = "2022-10-01"
API_VERSION_PRODUCT_SETTINGS    = "2025-07-01-preview"
API_VERSION_DATA_CONNECTORS     = "2025-07-01-preview"
API_VERSION_CONTENT_PACKAGES    = "2025-07-01-preview"
API_VERSION_HUNTING              = "2025-07-01-preview"
API_VERSION_HUNTING_QUERIES      = "2025-07-01"
API_VERSION_THREAT_INTELLIGENCE  = "2025-07-01-preview"
API_VERSION_WATCHLISTS           = "2025-07-01-preview"

# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

def get_access_token(tenant_id: str, client_id: str, client_secret: str) -> str:
    """Obtain a Bearer token via the client-credentials OAuth flow."""
    url = AUTH_URL_TEMPLATE.format(tenant_id=tenant_id)
    data = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": SCOPE,
    }
    resp = requests.post(url, data=data, timeout=30)
    resp.raise_for_status()
    return resp.json()["access_token"]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_json_files(folder: Path) -> list[tuple[Path, dict]]:
    """Return a list of (path, parsed_json) for every *.json file in *folder*."""
    results: list[tuple[Path, dict]] = []
    if not folder.is_dir():
        log.warning("Folder does not exist, skipping: %s", folder)
        return results
    for path in sorted(folder.glob("*.json")):
        try:
            with path.open(encoding="utf-8") as fh:
                results.append((path, json.load(fh)))
        except Exception as exc:  # noqa: BLE001
            log.warning("Could not read %s: %s — skipping", path.name, exc)
    return results

# ---------------------------------------------------------------------------
# Automation Rules
# ---------------------------------------------------------------------------

# Properties that are read-only / server-managed and must NOT be sent in PUT.
_AUTOMATION_RULE_STRIP_PROPS = {
    "createdTimeUtc",
    "lastModifiedTimeUtc",
    "createdBy",
    "lastModifiedBy",
}


def _build_automation_rule_body(backup: dict) -> dict:
    """
    Build the PUT request body from a backup JSON file.
    Keeps only writable properties; strips read-only server fields and
    top-level metadata (id, name, type, etag).
    """
    src_props: dict = backup.get("properties", {})
    clean_props = {k: v for k, v in src_props.items() if k not in _AUTOMATION_RULE_STRIP_PROPS}
    return {"properties": clean_props}


def restore_automation_rules(sentinel_base: str, headers: dict, input_root: Path, generate_new_id: bool = False) -> int:
    """
    Restore Automation Rules from the AutomationRules/ backup folder.

    Each JSON file is PUT to:
        PUT {sentinel_base}/automationRules/{ruleId}?api-version=...

    When generate_new_id=True a fresh GUID is used instead of the original.
    If the rule already exists it will be overwritten (idempotent).
    """
    folder = input_root / "AutomationRules"
    files = load_json_files(folder)
    if not files:
        log.info("No Automation Rule backup files found in: %s", folder)
        return 0

    log.info("Restoring %d Automation Rule(s) from: %s", len(files), folder)
    params = {"api-version": API_VERSION_AUTOMATION_RULES}
    restored = 0

    for path, backup in files:
        original_id: str = backup.get("name", "")
        display_name: str = backup.get("properties", {}).get("displayName", path.stem)

        if not original_id:
            log.warning("  Skipping %s — missing 'name' (rule ID) field.", path.name)
            continue

        rule_id = str(uuid.uuid4()) if generate_new_id else original_id
        if generate_new_id:
            log.info("  Restoring: %s  original id: %s  -> new id: %s", display_name, original_id, rule_id)
        else:
            log.info("  Restoring: %s  (id: %s)", display_name, rule_id)

        put_url = f"{sentinel_base}/automationRules/{rule_id}"
        body = _build_automation_rule_body(backup)

        try:
            resp = requests.put(put_url, headers=headers, params=params, json=body, timeout=30)
            resp.raise_for_status()
            status = "created" if resp.status_code == 201 else "updated"
            log.info("    -> %s (%d)", status, resp.status_code)
            restored += 1
        except requests.HTTPError as exc:
            err_msg = ""
            try:
                err_msg = exc.response.json().get("error", {}).get("message", "")
            except Exception:  # noqa: BLE001
                pass
            log.error(
                "    -> HTTP %d for '%s': %s%s",
                exc.response.status_code,
                display_name,
                exc,
                f" — {err_msg}" if err_msg else "",
            )
        except requests.RequestException as exc:
            log.error("    -> Request failed for '%s': %s", display_name, exc)

    return restored


# ---------------------------------------------------------------------------
# Restore stubs  (individual implementations added in later iterations)
# ---------------------------------------------------------------------------
# Alert Rules
# ---------------------------------------------------------------------------

# Properties that are read-only / server-managed and must NOT be sent in PUT.
_ALERT_RULE_STRIP_PROPS = {
    "lastModifiedUtc",
}


def _build_alert_rule_body(backup: dict) -> dict:
    """
    Build the PUT request body from a backup JSON file.

    The ``kind`` field (e.g. "Scheduled", "NRT", "Fusion") is top-level and
    required by the API.  Read-only properties are stripped from ``properties``.
    Top-level metadata (id, name, type, etag) is not forwarded.
    """
    kind: str = backup.get("kind", "")
    src_props: dict = backup.get("properties", {})
    clean_props = {k: v for k, v in src_props.items() if k not in _ALERT_RULE_STRIP_PROPS}
    body: dict = {"kind": kind, "properties": clean_props}
    return body


def restore_alert_rules(sentinel_base: str, headers: dict, input_root: Path, generate_new_id: bool = False) -> int:
    """
    Restore Alert Rules from the AlertRules/ backup folder.

    Each JSON file is PUT to:
        PUT {sentinel_base}/alertRules/{ruleId}?api-version=...

    When generate_new_id=True a fresh GUID is assigned to custom rules (GUID
    names) to avoid HTTP 409 soft-delete cooldown conflicts, and the PUT is
    retried with another new UUID if a 409 persists (up to 5 attempts).
    Built-in rules with non-GUID names (e.g. 'BuiltInFusion') always keep
    their original name regardless of this flag.
    """
    folder = input_root / "AlertRules"
    files = load_json_files(folder)
    if not files:
        log.info("No Alert Rule backup files found in: %s", folder)
        return 0

    log.info("Restoring %d Alert Rule(s) from: %s", len(files), folder)
    params = {"api-version": API_VERSION_ALERT_RULES}
    restored = 0

    for path, backup in files:
        original_id: str = backup.get("name", "")
        display_name: str = backup.get("properties", {}).get("displayName", path.stem)
        kind: str = backup.get("kind", "unknown")

        if not original_id:
            log.warning("  Skipping %s — missing 'name' (rule ID) field.", path.name)
            continue

        # For custom (GUID) rules: use original id or generate a new one.
        # Built-in rules (non-GUID names like 'BuiltInFusion') always keep their id.
        try:
            uuid.UUID(original_id)
            is_custom = True
        except ValueError:
            is_custom = False

        if is_custom and generate_new_id:
            rule_id = str(uuid.uuid4())
            log.info(
                "  Restoring: %s  (kind: %s)  original id: %s  -> new id: %s",
                display_name, kind, original_id, rule_id,
            )
        else:
            rule_id = original_id
            prefix = "  Restoring built-in:" if not is_custom else "  Restoring:"
            log.info("%s %s  (kind: %s, id: %s)", prefix, display_name, kind, rule_id)

        body = _build_alert_rule_body(backup)

        _MAX_UUID_RETRIES = 5
        for attempt in range(1, _MAX_UUID_RETRIES + 1):
            try:
                resp = requests.put(
                    f"{sentinel_base}/alertRules/{rule_id}",
                    headers=headers, params=params, json=body, timeout=30,
                )
                resp.raise_for_status()
                status = "created" if resp.status_code == 201 else "updated"
                log.info("    -> %s (%d) with id: %s", status, resp.status_code, rule_id)
                restored += 1
                break
            except requests.HTTPError as exc:
                err_msg = ""
                try:
                    err_body = exc.response.json().get("error", {})
                    err_msg = err_body.get("message", "")
                except Exception:  # noqa: BLE001
                    pass

                is_soft_delete_conflict = (
                    exc.response.status_code == 409
                    and "recently deleted" in err_msg.lower()
                )
                if is_soft_delete_conflict and generate_new_id and attempt < _MAX_UUID_RETRIES:
                    rule_id = str(uuid.uuid4())
                    log.warning(
                        "    -> 409 recently-deleted on attempt %d, retrying with new id: %s",
                        attempt, rule_id,
                    )
                    continue

                log.error(
                    "    -> HTTP %d for '%s' (attempt %d): %s%s",
                    exc.response.status_code,
                    display_name,
                    attempt,
                    exc,
                    f" — {err_msg}" if err_msg else "",
                )
                break
            except requests.RequestException as exc:
                log.error("    -> Request failed for '%s': %s", display_name, exc)
                break

    return restored


# ---------------------------------------------------------------------------
# Restore stubs  (individual implementations added in later iterations)
# ---------------------------------------------------------------------------

def _stub_not_implemented(label: str) -> int:
    log.info("%s restore: not yet implemented.", label)
    return 0

# ---------------------------------------------------------------------------
# Summary Rules
# ---------------------------------------------------------------------------

# Properties that are read-only / server-managed and must NOT be sent in PUT.
_SUMMARY_RULE_STRIP_PROPS = {
    "provisioningState",
    "isActive",
    "statusCode",
}


def _build_summary_rule_body(backup: dict) -> dict:
    """
    Build the PUT request body from a backup JSON file.
    Keeps only writable properties; strips provisioning/state fields and
    top-level metadata (id, name, systemData).
    """
    src_props: dict = backup.get("properties", {})
    clean_props = {k: v for k, v in src_props.items() if k not in _SUMMARY_RULE_STRIP_PROPS}
    return {"properties": clean_props}


def restore_summary_rules(workspace_base: str, headers: dict, input_root: Path, generate_new_id: bool = False) -> int:
    """
    Restore Summary Rules from the SummaryRules/ backup folder.

    Each JSON file is PUT to:
        PUT {workspace_base}/summaryLogs/{ruleId}?api-version=2025-07-01

    When generate_new_id=True a fresh GUID is generated for each rule and the
    PUT is retried with another UUID on 409 "recently deleted" (up to 5 times).
    """
    folder = input_root / "SummaryRules"
    files = load_json_files(folder)
    if not files:
        log.info("No Summary Rule backup files found in: %s", folder)
        return 0

    log.info("Restoring %d Summary Rule(s) from: %s", len(files), folder)
    params = {"api-version": API_VERSION_SUMMARY_RULES}
    restored = 0

    for path, backup in files:
        original_id: str = backup.get("name", "")
        display_name: str = backup.get("properties", {}).get("displayName", path.stem)

        if not original_id:
            log.warning("  Skipping %s — missing 'name' field.", path.name)
            continue

        # Always use a fresh GUID to avoid soft-delete 409.
        rule_id = str(uuid.uuid4()) if generate_new_id else original_id
        if generate_new_id:
            log.info(
                "  Restoring: %s  original id: %s  -> new id: %s",
                display_name, original_id, rule_id,
            )
        else:
            log.info("  Restoring: %s  (id: %s)", display_name, rule_id)

        body = _build_summary_rule_body(backup)

        _MAX_UUID_RETRIES = 5
        for attempt in range(1, _MAX_UUID_RETRIES + 1):
            try:
                resp = requests.put(
                    f"{workspace_base}/summaryLogs/{rule_id}",
                    headers=headers, params=params, json=body, timeout=30,
                )
                resp.raise_for_status()
                status = "created" if resp.status_code == 201 else "updated"
                log.info("    -> %s (%d) with id: %s", status, resp.status_code, rule_id)
                restored += 1
                break
            except requests.HTTPError as exc:
                err_msg = ""
                try:
                    err_msg = exc.response.json().get("error", {}).get("message", "")
                except Exception:  # noqa: BLE001
                    pass
                is_soft_delete_conflict = (
                    exc.response.status_code == 409
                    and "recently deleted" in err_msg.lower()
                )
                if is_soft_delete_conflict and generate_new_id and attempt < _MAX_UUID_RETRIES:
                    rule_id = str(uuid.uuid4())
                    log.warning(
                        "    -> 409 recently-deleted on attempt %d, retrying with new id: %s",
                        attempt, rule_id,
                    )
                    continue
                log.error(
                    "    -> HTTP %d for '%s' (attempt %d): %s%s",
                    exc.response.status_code, display_name, attempt, exc,
                    f" — {err_msg}" if err_msg else "",
                )
                break
            except requests.RequestException as exc:
                log.error("    -> Request failed for '%s': %s", display_name, exc)
                break

    return restored


# Properties that are read-only / server-managed and must NOT be sent in the hunt PUT.
_HUNTING_STRIP_PROPS: set[str] = set()

# Properties that are read-only in hunt relation responses.
_HUNT_RELATION_STRIP_PROPS = {
    "relatedResourceName",
    "relatedResourceType",
}


def _build_hunting_body(backup: dict) -> dict:
    """Build the PUT request body for a hunt.

    Keeps ``properties`` as-is (no server-managed fields to strip).
    """
    src_props: dict = backup.get("properties", {})
    clean_props = {k: v for k, v in src_props.items() if k not in _HUNTING_STRIP_PROPS}
    return {"properties": clean_props}


def _rewrite_related_resource_id(related_resource_id: str, target_workspace_arm_path: str) -> str:
    """Rewrite a relatedResourceId to point to the target workspace.

    Extracts the sub-resource portion after ``/workspaces/<name>/`` and
    prepends the target workspace ARM path.
    """
    match = re.search(r"/workspaces/[^/]+/(.*)", related_resource_id, re.IGNORECASE)
    if match:
        sub_resource = match.group(1)
        return f"{target_workspace_arm_path}/{sub_resource}"
    return related_resource_id


def restore_hunting(
    sentinel_base: str,
    workspace_base: str,
    headers: dict,
    input_root: Path,
    generate_new_id: bool = False,
) -> int:
    """Restore Hunts, their saved-search queries, and relations from the Hunting/ backup folder.

    Restore order per hunt:
        1. PUT the hunt itself to ``{sentinel_base}/hunts/{huntId}``
        2. PUT each hunting query (saved search) from ``HuntingQueries/`` to
           ``{workspace_base}/savedSearches/{id}``
        3. PUT each hunt relation to ``{sentinel_base}/hunts/{huntId}/relations/{relationId}``

    The ``relatedResourceId`` in each relation is rewritten to reference
    the target workspace.

    **Note:** The ``generate_new_id`` flag is accepted for interface
    consistency but is intentionally ignored.  Hunts, relations, and
    queries always keep their original IDs because relations reference
    hunts and queries by ID — assigning new IDs would break those links.
    """
    folder = input_root / "Hunting"
    all_files = load_json_files(folder)
    if not all_files:
        log.info("No Hunting backup files found in: %s", folder)
        return 0

    # Separate hunt files from details files
    hunt_files = [(p, d) for p, d in all_files if not p.stem.endswith("_details")]
    details_map: dict[str, tuple[Path, dict]] = {
        p.stem: (p, d) for p, d in all_files if p.stem.endswith("_details")
    }

    # Load hunting queries from HuntingQueries/ subfolder
    queries_folder = folder / "HuntingQueries"
    query_files = load_json_files(queries_folder)
    # Index queries by their original saved-search ID (name field)
    query_map: dict[str, tuple[Path, dict]] = {}
    for qpath, qdata in query_files:
        q_id = qdata.get("name", "")
        if q_id:
            query_map[q_id] = (qpath, qdata)

    if not hunt_files:
        log.info("No Hunt backup files found in: %s", folder)
        return 0

    log.info("Restoring %d Hunt(s) from: %s", len(hunt_files), folder)
    if query_map:
        log.info("Found %d hunting quer(ies) to restore.", len(query_map))
    params = {"api-version": API_VERSION_HUNTING}
    # ARM path for the target workspace (without https://management.azure.com)
    target_ws_arm = workspace_base.replace(MANAGEMENT_BASE, "")
    restored = 0

    for path, backup in hunt_files:
        original_id: str = backup.get("name", "")
        display_name: str = backup.get("properties", {}).get("displayName", path.stem)

        if not original_id:
            log.warning("  Skipping %s — missing 'name' field.", path.name)
            continue

        # Always use the original hunt ID — generate_new_id is intentionally
        # ignored for hunts, relations, and queries because relations reference
        # the hunt and query IDs; changing them would break the links.
        hunt_id = original_id
        log.info("  Restoring hunt: %s  (id: %s)", display_name, hunt_id)

        put_url = f"{sentinel_base}/hunts/{hunt_id}"
        body = _build_hunting_body(backup)

        try:
            resp = requests.put(put_url, headers=headers, params=params, json=body, timeout=30)
            resp.raise_for_status()
            status = "created" if resp.status_code == 201 else "updated"
            log.info("    -> %s (%d)", status, resp.status_code)
            restored += 1
        except requests.HTTPError as exc:
            err_msg = ""
            try:
                err_msg = exc.response.json().get("error", {}).get("message", "")
            except Exception:  # noqa: BLE001
                pass
            log.error(
                "    -> HTTP %d for '%s': %s%s",
                exc.response.status_code, display_name, exc,
                f" — {err_msg}" if err_msg else "",
            )
            continue
        except requests.RequestException as exc:
            log.error("    -> Request failed for '%s': %s", display_name, exc)
            continue

        # Load relations for this hunt
        details_key = f"{path.stem}_details"
        details_entry = details_map.get(details_key)
        relations = details_entry[1].get("value", []) if details_entry else []

        # Step 2: Restore hunting queries (saved searches) referenced by relations
        if relations and query_map:
            query_params = {"api-version": API_VERSION_HUNTING_QUERIES}
            restored_query_ids: set[str] = set()
            for relation in relations:
                rel_props = relation.get("properties", {})
                related_id = rel_props.get("relatedResourceId", "")
                if not related_id:
                    continue
                ss_id = related_id.rsplit("/", 1)[-1]
                if ss_id in restored_query_ids:
                    continue  # already restored this query
                if ss_id not in query_map:
                    continue  # no backup for this query
                _, q_backup = query_map[ss_id]
                q_display = (
                    q_backup.get("properties", {}).get("displayName")
                    or ss_id
                )
                log.info("    Restoring hunting query: %s  (id: %s)", q_display, ss_id)
                q_props = dict(q_backup.get("properties", {}))
                q_body = {"properties": q_props}
                q_url = f"{workspace_base}/savedSearches/{ss_id}"
                try:
                    resp = requests.put(q_url, headers=headers, params=query_params, json=q_body, timeout=30)
                    resp.raise_for_status()
                    log.info("      -> query restored (%d)", resp.status_code)
                    restored_query_ids.add(ss_id)
                except requests.HTTPError as exc:
                    err_msg = ""
                    try:
                        err_msg = exc.response.json().get("error", {}).get("message", "")
                    except Exception:  # noqa: BLE001
                        pass
                    log.error(
                        "      -> HTTP %d for query '%s': %s%s",
                        exc.response.status_code, q_display, exc,
                        f" — {err_msg}" if err_msg else "",
                    )
                except requests.RequestException as exc:
                    log.error("      -> Request failed for query '%s': %s", q_display, exc)

        # Step 3: Restore hunt relations
        if not relations:
            continue

        log.info("    Restoring %d relation(s) for hunt '%s' …", len(relations), display_name)
        for relation in relations:
            try:
                relation_id: str = relation.get("name", "")
                if not relation_id:
                    log.warning("      Skipping relation — missing 'name' field.")
                    continue

                rel_props = relation.get("properties", {})
                related_resource_id = rel_props.get("relatedResourceId", "")
                if not related_resource_id:
                    log.warning("      Skipping relation %s — missing relatedResourceId.", relation_id)
                    continue

                # Rewrite the relatedResourceId to point to the target workspace
                new_related_id = _rewrite_related_resource_id(related_resource_id, target_ws_arm)

                rel_body = {
                    "properties": {
                        "relatedResourceId": new_related_id,
                    }
                }

                rel_url = f"{sentinel_base}/hunts/{hunt_id}/relations/{relation_id}"
                resp = requests.put(rel_url, headers=headers, params=params, json=rel_body, timeout=30)
                resp.raise_for_status()
                log.info("      -> relation %s restored (%d)", relation_id, resp.status_code)
            except requests.HTTPError as exc:
                err_msg = ""
                try:
                    err_msg = exc.response.json().get("error", {}).get("message", "")
                except Exception:  # noqa: BLE001
                    pass
                log.error(
                    "      -> HTTP %d for relation %s: %s%s",
                    exc.response.status_code, relation.get("name", "?"), exc,
                    f" — {err_msg}" if err_msg else "",
                )
            except requests.RequestException as exc:
                log.error("      -> Request failed for relation %s: %s", relation.get("name", "?"), exc)

    return restored


# ---------------------------------------------------------------------------
# Workspace Functions
# ---------------------------------------------------------------------------


def _build_workspace_function_body(backup: dict) -> dict:
    """Build the PUT request body for a workspace function (saved search with functionAlias).

    The savedSearches API expects ``properties`` with ``category``, ``displayName``,
    ``query``, ``functionAlias``, and optionally ``version``, ``functionParameters``,
    and ``tags``.  No server-managed fields need stripping — all properties in the
    backup are writable.
    """
    src_props: dict = backup.get("properties", {})
    return {"properties": dict(src_props)}


def restore_workspace_functions(
    workspace_base: str,
    headers: dict,
    input_root: Path,
    generate_new_id: bool = False,
) -> int:
    """Restore Workspace Functions from the WorkspaceFunctions/ backup folder.

    Each JSON file is PUT to:
        PUT {workspace_base}/savedSearches/{id}?api-version=2020-08-01

    Workspace functions use their original saved-search ID. The generate_new_id
    flag is accepted for interface consistency but the original name is always used.
    """
    folder = input_root / "WorkspaceFunctions"
    files = load_json_files(folder)
    if not files:
        log.info("No Workspace Function backup files found in: %s", folder)
        return 0

    log.info("Restoring %d Workspace Function(s) from: %s", len(files), folder)
    params = {"api-version": API_VERSION_WORKSPACE_FUNCTIONS}
    restored = 0

    for path, backup in files:
        original_id: str = backup.get("name", "")
        display_name: str = (
            backup.get("properties", {}).get("displayName")
            or backup.get("properties", {}).get("functionAlias")
            or original_id
            or path.stem
        )

        if not original_id:
            log.warning("  Skipping %s \u2014 missing 'name' field.", path.name)
            continue

        log.info("  Restoring: %s  (id: %s)", display_name, original_id)

        put_url = f"{workspace_base}/savedSearches/{original_id}"
        body = _build_workspace_function_body(backup)

        try:
            resp = requests.put(put_url, headers=headers, params=params, json=body, timeout=30)
            resp.raise_for_status()
            status = "created" if resp.status_code == 201 else "updated"
            log.info("    -> %s (%d) with id: %s", status, resp.status_code, original_id)
            restored += 1
        except requests.HTTPError as exc:
            err_msg = ""
            try:
                err_msg = exc.response.json().get("error", {}).get("message", "")
            except Exception:  # noqa: BLE001
                pass
            log.error(
                "    -> HTTP %d for '%s': %s%s",
                exc.response.status_code,
                display_name,
                exc,
                f" \u2014 {err_msg}" if err_msg else "",
            )
        except requests.RequestException as exc:
            log.error("    -> Request failed for '%s': %s", display_name, exc)

    return restored


def restore_saved_queries(workspace_base: str, headers: dict, input_root: Path) -> int:
    return _stub_not_implemented("Saved Queries")


# ---------------------------------------------------------------------------
# Watchlists
# ---------------------------------------------------------------------------

# Watchlist properties that are read-only / server-managed and must NOT be sent in PUT.
_WATCHLIST_STRIP_PROPS = {
    "watchlistId",
    "provisioningState",
    "sasUri",
    "watchlistCategory",
    "watchlistKind",
    "tenantId",
    "created",
    "updated",
    "createdBy",
    "updatedBy",
    "isDeleted",
    "uploadStatus",
}

# Watchlist item properties that are read-only / server-managed.
_WATCHLIST_ITEM_STRIP_PROPS = {
    "watchlistItemId",
    "watchlistItemType",
    "tenantId",
    "created",
    "updated",
    "createdBy",
    "updatedBy",
    "isDeleted",
}


def _build_watchlist_body(backup: dict, items: list | None = None) -> dict:
    """Build the PUT request body for a watchlist.

    Keeps writable properties (displayName, itemsSearchKey, provider, source,
    sourceType, description, labels, defaultDuration, numberOfLinesToSkip,
    watchlistAlias, watchlistType).  Strips server-managed fields.

    The API requires ``contentType`` to be non-empty.  If missing from the
    backup, it is inferred from the ``source`` filename extension (``.tsv``
    → ``text/tsv``, everything else → ``text/csv``).

    When ``sourceType`` is ``"Local"`` and ``rawContent`` is absent (which is
    the case for backups — the extractor doesn't save raw CSV), a full CSV/TSV
    is generated from all watchlist items' ``itemsKeyValue`` data so the entire
    watchlist (container + items) is uploaded in a single PUT request.
    """
    src_props: dict = backup.get("properties", {})
    clean_props = {k: v for k, v in src_props.items() if k not in _WATCHLIST_STRIP_PROPS}

    # Ensure contentType is present — the API rejects an empty value.
    if not clean_props.get("contentType"):
        source: str = clean_props.get("source", "")
        clean_props["contentType"] = (
            "text/tsv" if source.lower().endswith(".tsv") else "text/csv"
        )

    # When sourceType is "Local" the API demands rawContent.  Build full
    # CSV/TSV from all items so everything is uploaded in one request.
    if (
        clean_props.get("sourceType", "").lower() == "local"
        and not clean_props.get("rawContent")
        and items
    ):
        # Derive column headers from the first item's keys
        first_kv = items[0].get("properties", {}).get("itemsKeyValue", {})
        header_keys = list(first_kv.keys())
        if not header_keys:
            search_key = clean_props.get("itemsSearchKey", "")
            if search_key:
                header_keys = [search_key]
        if header_keys:
            is_tsv = "tsv" in clean_props.get("contentType", "")
            buf = io.StringIO()
            writer = csv.writer(
                buf,
                delimiter="\t" if is_tsv else ",",
                quoting=csv.QUOTE_MINIMAL,
                lineterminator="\n",
            )
            writer.writerow(header_keys)
            for item in items:
                kv = item.get("properties", {}).get("itemsKeyValue", {})
                writer.writerow([str(kv.get(k, "")) for k in header_keys])
            clean_props["rawContent"] = buf.getvalue().rstrip("\n")

    return {"properties": clean_props}


def restore_watchlists(sentinel_base: str, headers: dict, input_root: Path, generate_new_id: bool = False) -> int:
    """Restore Watchlists and their items from the Watchlists/ backup folder.

    All items are embedded as CSV/TSV in the ``rawContent`` property of the
    watchlist PUT request so the entire watchlist is uploaded in a single call.
    This avoids per-item API requests and the throttling that comes with them.

    PUT ``{sentinel_base}/watchlists/{watchlistAlias}``

    Watchlists use human-readable aliases (not GUIDs) as their identifier,
    so ``generate_new_id`` has no effect.
    """
    folder = input_root / "Watchlists"
    files = load_json_files(folder)
    if not files:
        log.info("No Watchlist backup files found in: %s", folder)
        return 0

    log.info("Restoring %d Watchlist(s) from: %s", len(files), folder)
    params = {"api-version": API_VERSION_WATCHLISTS}
    restored = 0

    for path, backup in files:
        props = backup.get("properties", {})
        watchlist_alias: str = props.get("watchlistAlias") or backup.get("name", "")
        display_name: str = props.get("displayName") or watchlist_alias or path.stem

        if not watchlist_alias:
            log.warning("  Skipping %s \u2014 missing watchlist alias.", path.name)
            continue

        items: list = backup.get("watchlistItems", [])
        log.info(
            "  Restoring watchlist: %s  (alias: %s, %d items)",
            display_name, watchlist_alias, len(items),
        )

        put_url = f"{sentinel_base}/watchlists/{watchlist_alias}"
        body = _build_watchlist_body(backup, items=items)

        try:
            resp = requests.put(put_url, headers=headers, params=params, json=body, timeout=120)
            resp.raise_for_status()
            status = "created" if resp.status_code == 201 else "updated"
            log.info("    -> watchlist %s (%d) with %d items", status, resp.status_code, len(items))
            restored += 1
        except requests.HTTPError as exc:
            err_msg = ""
            try:
                err_msg = exc.response.json().get("error", {}).get("message", "")
            except Exception:  # noqa: BLE001
                pass
            log.error(
                "    -> HTTP %d for watchlist '%s': %s%s",
                exc.response.status_code, display_name, exc,
                f" \u2014 {err_msg}" if err_msg else "",
            )
        except requests.RequestException as exc:
            log.error("    -> Request failed for watchlist '%s': %s", display_name, exc)

    return restored

    return restored


# ---------------------------------------------------------------------------
# Data Collection Rules
# ---------------------------------------------------------------------------

# Properties that are read-only / server-managed and must NOT be sent in PUT.
_DCR_STRIP_PROPS = {
    "immutableId",
    "endpoints",
    "provisioningState",
    "metadata",
}


def _build_dcr_body(backup: dict, target_location: str = "", target_workspace_resource_id: str = "") -> dict:
    """Build the PUT request body for a Data Collection Rule.

    Preserves top-level ``location``, ``kind``, ``tags``, and ``identity``
    fields required/accepted by the API.  Strips server-managed properties.
    When *target_location* is provided it overrides the backup's location.
    When *target_workspace_resource_id* is provided, all
    ``destinations.logAnalytics[].workspaceResourceId`` entries are rewritten
    to point to the target workspace.
    """
    src_props: dict = backup.get("properties", {})
    clean_props = {k: v for k, v in src_props.items() if k not in _DCR_STRIP_PROPS}

    # Rewrite workspace references in logAnalytics destinations
    if target_workspace_resource_id:
        la_dests = clean_props.get("destinations", {}).get("logAnalytics", [])
        for dest in la_dests:
            dest["workspaceResourceId"] = target_workspace_resource_id
            # Remove workspaceId (GUID) — Azure will resolve it from the resource ID
            dest.pop("workspaceId", None)

    body: dict = {"properties": clean_props}
    # location is required by the API — use target if specified
    if target_location:
        body["location"] = target_location
    elif backup.get("location"):
        body["location"] = backup["location"]
    # Optional top-level fields
    for field in ("kind", "tags", "identity"):
        if backup.get(field):
            body[field] = backup[field]
    return body


def restore_dcrs(
    subscription_id: str,
    resource_group: str,
    headers: dict,
    input_root: Path,
    generate_new_id: bool = False,
    target_workspace_resource_id: str = "",
) -> int:
    """Restore Data Collection Rules from the DataCollectionRules/ backup folder.

    Each JSON file is PUT to:
        PUT /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Insights/dataCollectionRules/{name}

    DCRs use human-readable names (not GUIDs), so the original name is always
    used regardless of the generate_new_id flag.

    The DCR is created in the target resource group's region (auto-detected
    from Azure) rather than the backup's original region.  When
    *target_workspace_resource_id* is provided, Log Analytics destination
    references are rewritten to point to the target workspace.
    """
    # Auto-detect the resource group's region so the DCR lands in the correct location.
    target_location = ""
    try:
        target_location = _get_resource_group_location(subscription_id, resource_group, headers)
        log.info("  Auto-detected resource group location for DCRs: %s", target_location)
    except requests.RequestException as exc:
        log.warning(
            "  Could not auto-detect resource group location: %s — "
            "falling back to backup location.",
            exc,
        )

    folder = input_root / "DataCollectionRules"
    files = load_json_files(folder)
    if not files:
        log.info("No DCR backup files found in: %s", folder)
        return 0

    log.info("Restoring %d DCR(s) from: %s", len(files), folder)
    params = {"api-version": API_VERSION_DCR}
    restored = 0

    for path, backup in files:
        original_id: str = backup.get("name", "")
        display_name: str = original_id or path.stem

        if not original_id:
            log.warning("  Skipping %s \u2014 missing 'name' field.", path.name)
            continue

        # DCRs use human-readable names, not GUIDs \u2014 always use the original name.
        dcr_name = original_id
        log.info("  Restoring DCR: %s", display_name)

        put_url = (
            f"{MANAGEMENT_BASE}/subscriptions/{subscription_id}"
            f"/resourceGroups/{resource_group}"
            f"/providers/Microsoft.Insights/dataCollectionRules/{dcr_name}"
        )
        body = _build_dcr_body(backup, target_location=target_location, target_workspace_resource_id=target_workspace_resource_id)

        try:
            resp = requests.put(put_url, headers=headers, params=params, json=body, timeout=30)
            resp.raise_for_status()
            status = "created" if resp.status_code == 201 else "updated"
            log.info("    -> %s (%d) with name: %s", status, resp.status_code, dcr_name)
            restored += 1
        except requests.HTTPError as exc:
            err_msg = ""
            try:
                err_msg = exc.response.json().get("error", {}).get("message", "")
            except Exception:  # noqa: BLE001
                pass
            log.error(
                "    -> HTTP %d for '%s': %s%s",
                exc.response.status_code,
                display_name,
                exc,
                f" \u2014 {err_msg}" if err_msg else "",
            )
        except requests.RequestException as exc:
            log.error("    -> Request failed for '%s': %s", display_name, exc)

    return restored


# ---------------------------------------------------------------------------
# Data Collection Endpoints
# ---------------------------------------------------------------------------

# Properties that are read-only / server-managed and must NOT be sent in PUT.
_DCE_STRIP_PROPS = {
    "immutableId",
    "configurationAccess",
    "logsIngestion",
    "metricsIngestion",
    "provisioningState",
    "failoverConfiguration",
    "metadata",
}


def _build_dce_body(backup: dict, target_location: str = "") -> dict:
    """Build the PUT request body for a Data Collection Endpoint.

    Preserves top-level ``location``, ``kind``, ``tags``, and ``identity``
    fields required/accepted by the API.  Strips server-managed properties.
    When *target_location* is provided it overrides the backup's location.
    """
    src_props: dict = backup.get("properties", {})
    clean_props = {k: v for k, v in src_props.items() if k not in _DCE_STRIP_PROPS}
    body: dict = {"properties": clean_props}
    # location is required by the API — use target if specified
    if target_location:
        body["location"] = target_location
    elif backup.get("location"):
        body["location"] = backup["location"]
    # Optional top-level fields
    for field in ("kind", "tags", "identity"):
        if backup.get(field):
            body[field] = backup[field]
    return body


def restore_dces(
    subscription_id: str,
    resource_group: str,
    headers: dict,
    input_root: Path,
    generate_new_id: bool = False,
) -> int:
    """Restore Data Collection Endpoints from the DataCollectionEndpoints/ backup folder.

    Each JSON file is PUT to:
        PUT /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Insights/dataCollectionEndpoints/{name}

    DCEs use human-readable names (not GUIDs), so the original name is always
    used regardless of the generate_new_id flag.

    The DCE is created in the target resource group's region (auto-detected
    from Azure) rather than the backup's original region.
    """
    # Auto-detect the resource group's region so the DCE lands in the correct location.
    target_location = ""
    try:
        target_location = _get_resource_group_location(subscription_id, resource_group, headers)
        log.info("  Auto-detected resource group location for DCEs: %s", target_location)
    except requests.RequestException as exc:
        log.warning(
            "  Could not auto-detect resource group location: %s — "
            "falling back to backup location.",
            exc,
        )

    folder = input_root / "DataCollectionEndpoints"
    files = load_json_files(folder)
    if not files:
        log.info("No DCE backup files found in: %s", folder)
        return 0

    log.info("Restoring %d DCE(s) from: %s", len(files), folder)
    params = {"api-version": API_VERSION_DCE}
    restored = 0

    for path, backup in files:
        original_id: str = backup.get("name", "")
        display_name: str = original_id or path.stem

        if not original_id:
            log.warning("  Skipping %s — missing 'name' field.", path.name)
            continue

        # DCEs use human-readable names, not GUIDs — always use the original name.
        dce_name = original_id
        log.info("  Restoring DCE: %s", display_name)

        put_url = (
            f"{MANAGEMENT_BASE}/subscriptions/{subscription_id}"
            f"/resourceGroups/{resource_group}"
            f"/providers/Microsoft.Insights/dataCollectionEndpoints/{dce_name}"
        )
        body = _build_dce_body(backup, target_location=target_location)

        try:
            resp = requests.put(put_url, headers=headers, params=params, json=body, timeout=30)
            resp.raise_for_status()
            status = "created" if resp.status_code == 201 else "updated"
            log.info("    -> %s (%d) with name: %s", status, resp.status_code, dce_name)
            restored += 1
        except requests.HTTPError as exc:
            err_msg = ""
            try:
                err_msg = exc.response.json().get("error", {}).get("message", "")
            except Exception:  # noqa: BLE001
                pass
            log.error(
                "    -> HTTP %d for '%s': %s%s",
                exc.response.status_code,
                display_name,
                exc,
                f" — {err_msg}" if err_msg else "",
            )
        except requests.RequestException as exc:
            log.error("    -> Request failed for '%s': %s", display_name, exc)

    return restored


# Properties that are read-only / server-managed and must NOT be sent in PUT.
_WORKBOOK_STRIP_PROPS = {
    "timeModified",
    "userId",
    "revision",
}

API_VERSION_WORKBOOKS = "2021-08-01"


def _build_workbook_body(
    backup: dict,
    target_location: str = "",
    target_source_id: str = "",
) -> dict:
    """Build the PUT request body for a Workbook.

    Preserves top-level ``location``, ``kind``, ``tags``, and ``identity``
    fields required/accepted by the API.  Strips server-managed properties.

    When *target_source_id* is provided it replaces the backup's
    ``properties.sourceId`` and rewrites ``fallbackResourceIds`` inside
    ``serializedData`` so the workbook is linked to the target workspace.
    """
    src_props: dict = backup.get("properties", {})
    clean_props = {k: v for k, v in src_props.items() if k not in _WORKBOOK_STRIP_PROPS}

    # Rewrite sourceId to point to the target workspace
    original_source_id = src_props.get("sourceId", "")
    if target_source_id:
        clean_props["sourceId"] = target_source_id

    # Rewrite fallbackResourceIds inside serializedData
    serialized = clean_props.get("serializedData", "")
    if serialized and target_source_id and original_source_id:
        try:
            sd = json.loads(serialized)
            fallback_ids = sd.get("fallbackResourceIds")
            if isinstance(fallback_ids, list):
                sd["fallbackResourceIds"] = [
                    target_source_id if fid.lower() == original_source_id.lower() else fid
                    for fid in fallback_ids
                ]
                clean_props["serializedData"] = json.dumps(sd, ensure_ascii=False)
        except (json.JSONDecodeError, TypeError):
            pass  # leave serializedData as-is if it can't be parsed

    body: dict = {"properties": clean_props}

    # location is required by the API — use target if specified
    if target_location:
        body["location"] = target_location
    elif backup.get("location"):
        body["location"] = backup["location"]

    # Optional top-level fields
    for field in ("kind", "tags"):
        if backup.get(field):
            body[field] = backup[field]

    # Identity handling (same pattern as Logic Apps)
    if backup.get("identity"):
        identity = dict(backup["identity"])
        if identity.get("type", "").lower() in ("systemassigned", "systemassigned,userassigned"):
            identity.pop("principalId", None)
            identity.pop("tenantId", None)
        body["identity"] = identity

    return body


def restore_workbooks(
    subscription_id: str,
    resource_group: str,
    headers: dict,
    input_root: Path,
    generate_new_id: bool = False,
    target_source_id: str = "",
) -> int:
    """Restore Workbooks from the Workbooks/ backup folder.

    Each JSON file is PUT to:
        PUT /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Insights/workbooks/{name}

    When *target_source_id* is provided, ``properties.sourceId`` and
    ``fallbackResourceIds`` inside ``serializedData`` are rewritten to
    point to the target workspace.

    When *generate_new_id* is True a fresh GUID is used instead of the
    original workbook name.
    """
    # Auto-detect the resource group's region.
    target_location = ""
    try:
        target_location = _get_resource_group_location(subscription_id, resource_group, headers)
        log.info("  Auto-detected resource group location for Workbooks: %s", target_location)
    except requests.RequestException as exc:
        log.warning(
            "  Could not auto-detect resource group location: %s — "
            "falling back to backup location.",
            exc,
        )

    folder = input_root / "Workbooks"
    files = load_json_files(folder)
    if not files:
        log.info("No Workbook backup files found in: %s", folder)
        return 0

    log.info("Restoring %d Workbook(s) from: %s", len(files), folder)
    params = {"api-version": API_VERSION_WORKBOOKS}
    restored = 0

    for path, backup in files:
        original_id: str = backup.get("name", "")
        display_name: str = (
            backup.get("properties", {}).get("displayName")
            or original_id
            or path.stem
        )

        if not original_id:
            log.warning("  Skipping %s — missing 'name' field.", path.name)
            continue

        wb_name = str(uuid.uuid4()) if generate_new_id else original_id
        if generate_new_id:
            log.info("  Restoring: %s  original id: %s  -> new id: %s", display_name, original_id, wb_name)
        else:
            log.info("  Restoring: %s  (id: %s)", display_name, wb_name)

        put_url = (
            f"{MANAGEMENT_BASE}/subscriptions/{subscription_id}"
            f"/resourceGroups/{resource_group}"
            f"/providers/Microsoft.Insights/workbooks/{wb_name}"
        )
        body = _build_workbook_body(
            backup,
            target_location=target_location,
            target_source_id=target_source_id,
        )

        try:
            resp = requests.put(put_url, headers=headers, params=params, json=body, timeout=60)
            resp.raise_for_status()
            status = "created" if resp.status_code == 201 else "updated"
            log.info("    -> %s (%d)", status, resp.status_code)
            restored += 1
        except requests.HTTPError as exc:
            err_msg = ""
            try:
                err_msg = exc.response.json().get("error", {}).get("message", "")
            except Exception:  # noqa: BLE001
                pass
            log.error(
                "    -> HTTP %d for '%s': %s%s",
                exc.response.status_code,
                display_name,
                exc,
                f" — {err_msg}" if err_msg else "",
            )
        except requests.RequestException as exc:
            log.error("    -> Request failed for '%s': %s", display_name, exc)

    return restored


# ---------------------------------------------------------------------------
# Logic Apps
# ---------------------------------------------------------------------------

# Properties that are read-only / server-managed and must NOT be sent in PUT.
_LOGIC_APP_STRIP_PROPS = {
    "provisioningState",
    "createdTime",
    "changedTime",
    "version",
    "accessEndpoint",
    "endpointsConfiguration",
}


# Valid values for --logic-app-mode
LOGIC_APP_MODE_SAME_TENANT     = "same-tenant"
LOGIC_APP_MODE_NEW_ENVIRONMENT = "new-environment"
LOGIC_APP_MODES = (LOGIC_APP_MODE_SAME_TENANT, LOGIC_APP_MODE_NEW_ENVIRONMENT)


def _build_logic_app_body(
    backup: dict,
    target_subscription_id: str = "",
    target_resource_group: str = "",
    target_location: str = "",
    logic_app_mode: str = LOGIC_APP_MODE_SAME_TENANT,
) -> dict:
    """Build the PUT request body for a Logic App workflow.

    Preserves top-level ``location``, ``tags``, and ``identity`` fields
    required/accepted by the API.  Strips server-managed properties.

    Behaviour depends on *logic_app_mode*:

    ``same-tenant``  (default)
        API-connection references (``$connections``) are rewritten to match
        *target_subscription_id*, *target_resource_group*, and
        *target_location* so the Logic App can use the same connections that
        already exist in the same tenant.

    ``new-environment``
        The Logic App is created **without connections**.  The ``$connections``
        parameter block and all ``definition.parameters.$connections`` entries
        are removed.  After deploy you must manually create the API
        connections in the target resource group and then wire them up in the
        Logic App designer.
    """
    src_props: dict = backup.get("properties", {})
    clean_props = {k: v for k, v in src_props.items() if k not in _LOGIC_APP_STRIP_PROPS}

    if logic_app_mode == LOGIC_APP_MODE_NEW_ENVIRONMENT:
        # Strip all connection references — they can't exist in the new env.
        clean_props.pop("parameters", None)
        defn = clean_props.get("definition", {})
        defn_params = defn.get("parameters", {})
        defn_params.pop("$connections", None)
    else:
        # same-tenant: rewrite connection paths to the target sub/RG/region
        if target_subscription_id or target_resource_group or target_location:
            _rewrite_connections(
                clean_props,
                target_subscription_id=target_subscription_id,
                target_resource_group=target_resource_group,
                target_location=target_location,
            )

    body: dict = {"properties": clean_props}

    # location is required by the API — use target if specified
    if target_location:
        body["location"] = target_location
    elif backup.get("location"):
        body["location"] = backup["location"]

    # Optional top-level fields
    if backup.get("tags"):
        body["tags"] = backup["tags"]
    if backup.get("identity"):
        identity = dict(backup["identity"])
        # Azure rejects principalId / tenantId for SystemAssigned; it
        # generates new values on its own.
        if identity.get("type", "").lower() in ("systemassigned", "systemassigned,userassigned"):
            identity.pop("principalId", None)
            identity.pop("tenantId", None)
        body["identity"] = identity

    return body


_SUBSCRIPTION_RE = re.compile(
    r"/subscriptions/[0-9a-fA-F-]+/"
)
_RG_RE = re.compile(
    r"/resourceGroups/[^/]+/"
)
_MANAGED_API_LOCATION_RE = re.compile(
    r"(/providers/Microsoft\.Web/locations/)([^/]+)(/managedApis/)"
)


def _rewrite_connections(
    props: dict,
    *,
    target_subscription_id: str,
    target_resource_group: str,
    target_location: str,
) -> None:
    """In-place rewrite of ``$connections`` parameter values.

    Updates subscription, resource-group, and managedApi location segments
    inside every connection entry so they point to the target environment.
    """
    connections: dict = (
        props.get("parameters", {})
        .get("$connections", {})
        .get("value", {})
    )
    if not connections:
        return

    for _conn_name, conn in connections.items():
        # Rewrite managedApi id  (contains region)
        api_id: str = conn.get("id", "")
        if api_id:
            if target_subscription_id:
                api_id = _SUBSCRIPTION_RE.sub(
                    f"/subscriptions/{target_subscription_id}/", api_id, count=1
                )
            if target_location:
                api_id = _MANAGED_API_LOCATION_RE.sub(
                    rf"\g<1>{target_location}\g<3>", api_id,
                )
            conn["id"] = api_id

        # Rewrite connectionId  (contains subscription + resource group)
        cid: str = conn.get("connectionId", "")
        if cid:
            if target_subscription_id:
                cid = _SUBSCRIPTION_RE.sub(
                    f"/subscriptions/{target_subscription_id}/", cid, count=1
                )
            if target_resource_group:
                cid = _RG_RE.sub(
                    f"/resourceGroups/{target_resource_group}/", cid, count=1
                )
            conn["connectionId"] = cid


def _get_resource_group_location(
    subscription_id: str, resource_group: str, headers: dict,
) -> str:
    """Return the Azure region of a resource group (e.g. 'westeurope')."""
    url = (
        f"{MANAGEMENT_BASE}/subscriptions/{subscription_id}"
        f"/resourcegroups/{resource_group}"
    )
    resp = requests.get(url, headers=headers, params={"api-version": "2021-04-01"}, timeout=30)
    resp.raise_for_status()
    return resp.json().get("location", "")


def restore_logic_apps(
    subscription_id: str,
    resource_group: str,
    headers: dict,
    input_root: Path,
    generate_new_id: bool = False,
    target_location: str = "",
    logic_app_mode: str = LOGIC_APP_MODE_SAME_TENANT,
) -> int:
    """Restore Logic Apps from the LogicApps/ backup folder.

    Each JSON file is PUT to:
        PUT /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Logic/workflows/{name}

    Logic Apps use human-readable names (not GUIDs), so the original name is
    always used regardless of the generate_new_id flag.

    *logic_app_mode* controls connection handling:

    - ``same-tenant``:  connections are rewritten to match the target
      subscription / resource-group / location (the connections must already
      exist in the target).
    - ``new-environment``:  connections are stripped entirely; the Logic App
      is created without them so you can create and wire connections manually
      after deploy.  When no ``--target-location`` is provided, the resource
      group's region is auto-detected so the Logic App is always created in
      the same region as its resource group.
    """
    # In new-environment mode, auto-detect the RG region when no explicit
    # --target-location was provided so the Logic App lands in the correct
    # region.
    if logic_app_mode == LOGIC_APP_MODE_NEW_ENVIRONMENT and not target_location:
        try:
            target_location = _get_resource_group_location(subscription_id, resource_group, headers)
            log.info("  Auto-detected resource group location: %s", target_location)
        except requests.RequestException as exc:
            log.warning(
                "  Could not auto-detect resource group location: %s — "
                "falling back to backup location. Use --target-location to set explicitly.",
                exc,
            )

    folder = input_root / "LogicApps"
    files = load_json_files(folder)
    if not files:
        log.info("No Logic App backup files found in: %s", folder)
        return 0

    log.info("Restoring %d Logic App(s) from: %s", len(files), folder)
    params = {"api-version": API_VERSION_LOGIC_APPS}
    restored = 0

    for path, backup in files:
        original_id: str = backup.get("name", "")
        display_name: str = original_id or path.stem

        if not original_id:
            log.warning("  Skipping %s \u2014 missing 'name' field.", path.name)
            continue

        # Logic Apps use human-readable names, not GUIDs.
        app_name = original_id
        log.info("  Restoring Logic App: %s", display_name)

        put_url = (
            f"{MANAGEMENT_BASE}/subscriptions/{subscription_id}"
            f"/resourceGroups/{resource_group}"
            f"/providers/Microsoft.Logic/workflows/{app_name}"
        )
        body = _build_logic_app_body(
            backup,
            target_subscription_id=subscription_id,
            target_resource_group=resource_group,
            target_location=target_location,
            logic_app_mode=logic_app_mode,
        )

        try:
            resp = requests.put(put_url, headers=headers, params=params, json=body, timeout=30)
            resp.raise_for_status()
            status = "created" if resp.status_code == 201 else "updated"
            log.info("    -> %s (%d) with name: %s", status, resp.status_code, app_name)
            restored += 1
        except requests.HTTPError as exc:
            err_msg = ""
            try:
                err_msg = exc.response.json().get("error", {}).get("message", "")
            except Exception:  # noqa: BLE001
                pass
            log.error(
                "    -> HTTP %d for '%s': %s%s",
                exc.response.status_code,
                display_name,
                exc,
                f" \u2014 {err_msg}" if err_msg else "",
            )
        except requests.RequestException as exc:
            log.error("    -> Request failed for '%s': %s", display_name, exc)

    return restored

# ---------------------------------------------------------------------------
# Custom Tables
# ---------------------------------------------------------------------------

# Properties that are read-only / server-managed and must NOT be sent in PUT.
_TABLE_STRIP_PROPS = {
    "provisioningState",
    "lastPlanModifiedDate",
    "archiveRetentionInDays",
}

# Columns created / managed by the system — never include in PUT.
_TABLE_SYSTEM_COLUMNS = {
    "TenantId",
    "Type",
    "_ResourceId",
    "MG",
    "ManagementGroupName",
    "SourceSystem",
    "Computer",
    "RawData",
}


def _build_custom_table_body(backup: dict) -> dict:
    """Build the PUT body for a custom table from a backup JSON.

    Keeps the schema (custom columns + their types), retention settings,
    and plan.  Strips read-only server fields and system-managed columns.
    """
    src_props: dict = backup.get("properties", {})
    clean_props: dict = {}

    # Schema — keep only custom columns
    schema = src_props.get("schema", {})
    if schema:
        src_columns = schema.get("columns", [])
        custom_columns = [
            col for col in src_columns
            if col.get("name") not in _TABLE_SYSTEM_COLUMNS
            and not col.get("name", "").startswith("_")
            and not col.get("isDefaultDisplay", False)
            and not col.get("isHidden", False)
        ]
        clean_props["schema"] = {
            "name": schema.get("name", ""),
            "columns": custom_columns,
        }

    # Retention
    if "retentionInDays" in src_props:
        clean_props["retentionInDays"] = src_props["retentionInDays"]
    if "totalRetentionInDays" in src_props:
        clean_props["totalRetentionInDays"] = src_props["totalRetentionInDays"]

    # Plan (Analytics / Basic)
    if "plan" in src_props:
        clean_props["plan"] = src_props["plan"]

    return {"properties": clean_props}


def restore_custom_tables(workspace_base: str, headers: dict, input_root: Path) -> int:
    """Restore custom tables from the CustomTables/ backup folder.

    Each table is PUT to:
        PUT {workspace_base}/tables/{tableName}?api-version=...
    """
    folder = input_root / "CustomTables"
    files = load_json_files(folder)
    if not files:
        log.info("No Custom Table backup files found in: %s", folder)
        return 0

    log.info("Restoring %d Custom Table(s) from: %s", len(files), folder)
    params = {"api-version": API_VERSION_TABLES}
    restored = 0

    for path, backup in files:
        table_name: str = backup.get("name", "")
        display_name: str = table_name or path.stem

        if not table_name:
            log.warning("  Skipping %s — missing 'name' field.", path.name)
            continue

        log.info("  Restoring custom table: %s", display_name)

        put_url = f"{workspace_base}/tables/{table_name}"
        body = _build_custom_table_body(backup)

        try:
            resp = requests.put(put_url, headers=headers, params=params, json=body, timeout=60)
            resp.raise_for_status()
            status = "created" if resp.status_code == 201 else "updated"
            log.info("    -> %s (%d)", status, resp.status_code)
            restored += 1
        except requests.HTTPError as exc:
            err_msg = ""
            try:
                err_msg = exc.response.json().get("error", {}).get("message", "")
            except Exception:  # noqa: BLE001
                pass
            log.error(
                "    -> HTTP %d for '%s': %s%s",
                exc.response.status_code,
                display_name,
                exc,
                f" — {err_msg}" if err_msg else "",
            )
        except requests.RequestException as exc:
            log.error("    -> Request failed for '%s': %s", display_name, exc)

    return restored

# ---------------------------------------------------------------------------
# Table Retention
# ---------------------------------------------------------------------------


def restore_table_retention(workspace_base: str, headers: dict, input_root: Path) -> int:
    """Restore table retention settings from table_retention.json.

    Each table entry is PATCHed via PUT to:
        PUT {workspace_base}/tables/{tableName}?api-version=...
    with only the retention and plan properties.
    """
    retention_file = input_root / "table_retention.json"
    if not retention_file.is_file():
        log.info("No table_retention.json found in: %s", input_root)
        return 0

    try:
        with retention_file.open(encoding="utf-8") as fh:
            entries = json.load(fh)
    except Exception as exc:  # noqa: BLE001
        log.error("Could not read %s: %s", retention_file, exc)
        return 0

    if not isinstance(entries, list):
        log.error("table_retention.json must contain a JSON array.")
        return 0

    log.info("Restoring retention settings for %d table(s) from: %s", len(entries), retention_file)
    params = {"api-version": API_VERSION_TABLES}
    restored = 0

    for entry in entries:
        table_name: str = entry.get("name", "")
        if not table_name:
            continue

        # Build minimal body with only retention/plan properties
        props: dict = {}
        if entry.get("retentionInDays") is not None:
            props["retentionInDays"] = entry["retentionInDays"]
        if entry.get("totalRetentionInDays") is not None:
            props["totalRetentionInDays"] = entry["totalRetentionInDays"]
        if entry.get("plan") is not None:
            props["plan"] = entry["plan"]

        if not props:
            log.debug("  Skipping %s — no retention properties to set.", table_name)
            continue

        log.info("  Restoring retention for table: %s", table_name)

        put_url = f"{workspace_base}/tables/{table_name}"
        body = {"properties": props}

        try:
            resp = requests.put(put_url, headers=headers, params=params, json=body, timeout=60)
            resp.raise_for_status()
            log.info("    -> updated (%d)", resp.status_code)
            restored += 1
        except requests.HTTPError as exc:
            err_msg = ""
            try:
                err_msg = exc.response.json().get("error", {}).get("message", "")
            except Exception:  # noqa: BLE001
                pass
            log.error(
                "    -> HTTP %d for '%s': %s%s",
                exc.response.status_code,
                table_name,
                exc,
                f" — {err_msg}" if err_msg else "",
            )
        except requests.RequestException as exc:
            log.error("    -> Request failed for '%s': %s", table_name, exc)

    return restored

# ---------------------------------------------------------------------------
# Product Settings
# ---------------------------------------------------------------------------


def _build_product_setting_body(backup: dict) -> dict:
    """Build the PUT body for a product setting.

    The settings API requires ``kind`` (top-level) and ``properties``.
    The ``etag`` is optional but included when present — it allows the
    API to detect concurrent updates.
    """
    body: dict = {}
    if backup.get("kind"):
        body["kind"] = backup["kind"]
    if backup.get("etag"):
        body["etag"] = backup["etag"]
    body["properties"] = dict(backup.get("properties", {}))
    return body


def restore_product_settings(sentinel_base: str, headers: dict, input_root: Path) -> int:
    """Restore product settings from the ProductSettings/ backup folder.

    Each JSON file is PUT to:
        PUT {sentinel_base}/settings/{settingName}?api-version=...
    """
    folder = input_root / "ProductSettings"
    files = load_json_files(folder)
    if not files:
        log.info("No Product Setting backup files found in: %s", folder)
        return 0

    log.info("Restoring %d Product Setting(s) from: %s", len(files), folder)
    params = {"api-version": API_VERSION_PRODUCT_SETTINGS}
    restored = 0

    for path, backup in files:
        setting_name: str = backup.get("name", "")
        kind: str = backup.get("kind", "Unknown")
        display_name: str = setting_name or kind or path.stem

        if not setting_name:
            log.warning("  Skipping %s \u2014 missing 'name' field.", path.name)
            continue

        log.info("  Restoring product setting [kind=%s]: %s", kind, display_name)

        put_url = f"{sentinel_base}/settings/{setting_name}"
        body = _build_product_setting_body(backup)

        try:
            resp = requests.put(put_url, headers=headers, params=params, json=body, timeout=30)
            resp.raise_for_status()
            log.info("    -> updated (%d)", resp.status_code)
            restored += 1
        except requests.HTTPError as exc:
            err_msg = ""
            try:
                err_msg = exc.response.json().get("error", {}).get("message", "")
            except Exception:  # noqa: BLE001
                pass
            log.error(
                "    -> HTTP %d for '%s': %s%s",
                exc.response.status_code,
                display_name,
                exc,
                f" \u2014 {err_msg}" if err_msg else "",
            )
        except requests.RequestException as exc:
            log.error("    -> Request failed for '%s': %s", display_name, exc)

    return restored

# ---------------------------------------------------------------------------
# Data Connectors
# ---------------------------------------------------------------------------

# Properties that are read-only / server-managed and must NOT be sent in PUT.
_DATA_CONNECTOR_STRIP_PROPS = {
    "lastModifiedUtc",
}


def _build_data_connector_body(backup: dict) -> dict:
    """Build the PUT body for a data connector.

    The API requires ``kind`` (top-level) and ``properties``.
    Server-managed properties are stripped.
    """
    src_props: dict = backup.get("properties", {})
    clean_props = {k: v for k, v in src_props.items() if k not in _DATA_CONNECTOR_STRIP_PROPS}
    body: dict = {"properties": clean_props}
    if backup.get("kind"):
        body["kind"] = backup["kind"]
    if backup.get("etag"):
        body["etag"] = backup["etag"]
    return body


def restore_data_connectors(sentinel_base: str, headers: dict, input_root: Path, generate_new_id: bool = False) -> int:
    """Restore data connectors from the DataConnectors/ backup folder.

    Each JSON file is PUT to:
        PUT {sentinel_base}/dataConnectors/{connectorId}?api-version=...
    """
    folder = input_root / "DataConnectors"
    files = load_json_files(folder)
    if not files:
        log.info("No Data Connector backup files found in: %s", folder)
        return 0

    log.info("Restoring %d Data Connector(s) from: %s", len(files), folder)
    params = {"api-version": API_VERSION_DATA_CONNECTORS}
    restored = 0

    for path, backup in files:
        original_id: str = backup.get("name", "")
        kind: str = backup.get("kind", "Unknown")
        display_name: str = (
            backup.get("properties", {}).get("connectorUiConfig", {}).get("title")
            or original_id
            or path.stem
        )

        if not original_id:
            log.warning("  Skipping %s \u2014 missing 'name' field.", path.name)
            continue

        connector_id = str(uuid.uuid4()) if generate_new_id else original_id
        if generate_new_id:
            log.info("  Restoring [kind=%s]: %s  original id: %s  -> new id: %s", kind, display_name, original_id, connector_id)
        else:
            log.info("  Restoring [kind=%s]: %s  (id: %s)", kind, display_name, connector_id)

        put_url = f"{sentinel_base}/dataConnectors/{connector_id}"
        body = _build_data_connector_body(backup)

        try:
            resp = requests.put(put_url, headers=headers, params=params, json=body, timeout=30)
            resp.raise_for_status()
            status = "created" if resp.status_code == 201 else "updated"
            log.info("    -> %s (%d)", status, resp.status_code)
            restored += 1
        except requests.HTTPError as exc:
            err_msg = ""
            try:
                err_msg = exc.response.json().get("error", {}).get("message", "")
            except Exception:  # noqa: BLE001
                pass
            log.error(
                "    -> HTTP %d for '%s': %s%s",
                exc.response.status_code,
                display_name,
                exc,
                f" \u2014 {err_msg}" if err_msg else "",
            )
        except requests.RequestException as exc:
            log.error("    -> Request failed for '%s': %s", display_name, exc)

    return restored

# ---------------------------------------------------------------------------
# Content Packages
# ---------------------------------------------------------------------------


def restore_content_packages(sentinel_base: str, headers: dict, input_root: Path) -> int:
    """Restore (install) content packages from the ContentPackages/ backup folder.

    Each JSON file triggers a POST to:
        POST {sentinel_base}/contentPackages/{packageId}/install?api-version=...

    This installs one package at a time. The API is idempotent \u2014 re-installing
    an already-installed package simply updates it.
    """
    folder = input_root / "ContentPackages"
    files = load_json_files(folder)
    if not files:
        log.info("No Content Package backup files found in: %s", folder)
        return 0

    log.info("Installing %d Content Package(s) from: %s", len(files), folder)
    params = {"api-version": API_VERSION_CONTENT_PACKAGES}
    restored = 0

    for path, backup in files:
        package_id: str = backup.get("name", "")
        display_name: str = (
            backup.get("properties", {}).get("displayName")
            or package_id
            or path.stem
        )

        if not package_id:
            log.warning("  Skipping %s \u2014 missing 'name' (package ID) field.", path.name)
            continue

        log.info("  Installing content package: %s  (id: %s)", display_name, package_id)

        post_url = f"{sentinel_base}/contentPackages/{package_id}/install"
        # The install endpoint accepts the package resource body
        body: dict = {}
        if backup.get("properties"):
            body["properties"] = dict(backup["properties"])

        try:
            resp = requests.post(post_url, headers=headers, params=params, json=body, timeout=60)
            resp.raise_for_status()
            log.info("    -> installed (%d)", resp.status_code)
            restored += 1
        except requests.HTTPError as exc:
            err_msg = ""
            try:
                err_msg = exc.response.json().get("error", {}).get("message", "")
            except Exception:  # noqa: BLE001
                pass
            log.error(
                "    -> HTTP %d for '%s': %s%s",
                exc.response.status_code,
                display_name,
                exc,
                f" \u2014 {err_msg}" if err_msg else "",
            )
        except requests.RequestException as exc:
            log.error("    -> Request failed for '%s': %s", display_name, exc)

    return restored

# ---------------------------------------------------------------------------
# Threat Intelligence Indicators
# ---------------------------------------------------------------------------

# Properties that are read-only / server-managed and must NOT be sent in POST.
_TI_INDICATOR_STRIP_PROPS = {
    "lastUpdatedTimeUtc",
    "friendlyName",
    "additionalData",
    "parsedPattern",
}


def _build_ti_indicator_body(backup: dict) -> dict:
    """Build the POST request body for a threat intelligence indicator.

    The createIndicator API requires ``kind`` (top-level, always ``"indicator"``)
    and ``properties``.  Server-managed properties are stripped.
    """
    src_props: dict = backup.get("properties", {})
    clean_props = {k: v for k, v in src_props.items() if k not in _TI_INDICATOR_STRIP_PROPS}
    return {"kind": "indicator", "properties": clean_props}


def restore_threat_intelligence(sentinel_base: str, headers: dict, input_root: Path) -> int:
    """Restore threat intelligence indicators from the ThreatIntelligence/ backup folder.

    Each JSON file is POSTed to:
        POST {sentinel_base}/threatIntelligence/main/createIndicator?api-version=...

    The createIndicator endpoint always creates a new indicator with a server-
    assigned ID.  The ``--generate-new-id`` flag has no effect.
    """
    folder = input_root / "ThreatIntelligence"
    files = load_json_files(folder)
    if not files:
        log.info("No Threat Intelligence backup files found in: %s", folder)
        return 0

    log.info("Restoring %d Threat Intelligence indicator(s) from: %s", len(files), folder)
    params = {"api-version": API_VERSION_THREAT_INTELLIGENCE}
    restored = 0

    for path, backup in files:
        original_id: str = backup.get("name", "")
        display_name: str = (
            backup.get("properties", {}).get("displayName")
            or original_id
            or path.stem
        )

        log.info("  Restoring TI indicator: %s", display_name)

        post_url = f"{sentinel_base}/threatIntelligence/main/createIndicator"
        body = _build_ti_indicator_body(backup)

        try:
            resp = requests.post(post_url, headers=headers, params=params, json=body, timeout=30)
            resp.raise_for_status()
            status = "created" if resp.status_code == 201 else "uploaded"
            log.info("    -> %s (%d)", status, resp.status_code)
            restored += 1
        except requests.HTTPError as exc:
            err_msg = ""
            try:
                err_msg = exc.response.json().get("error", {}).get("message", "")
            except Exception:  # noqa: BLE001
                pass
            log.error(
                "    -> HTTP %d for '%s': %s%s",
                exc.response.status_code,
                display_name,
                exc,
                f" \u2014 {err_msg}" if err_msg else "",
            )
        except requests.RequestException as exc:
            log.error("    -> Request failed for '%s': %s", display_name, exc)

    return restored

# ---------------------------------------------------------------------------
# CLI / config
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Restore Microsoft Sentinel configuration from JSON backup files "
            "produced by sentinel_extractor.py.\n\n"
            "SAFETY: Nothing is restored unless you pass at least one "
            "--restore-* flag (or --restore-all)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # ── Authentication ──────────────────────────────────────────────────────
    auth = parser.add_argument_group("Authentication")
    auth.add_argument("--tenant-id", help="Azure AD tenant ID (overrides env AZURE_TENANT_ID)")
    auth.add_argument("--client-id", help="App registration client ID (overrides env AZURE_CLIENT_ID)")
    auth.add_argument("--client-secret", help="App registration client secret (overrides env AZURE_CLIENT_SECRET)")

    # ── Target workspace ────────────────────────────────────────────────────
    target = parser.add_argument_group("Target workspace (where content will be restored)")
    target.add_argument(
        "--target-subscription-id",
        help="Target Azure subscription ID (overrides env AZURE_TARGET_SUBSCRIPTION_ID)",
    )
    target.add_argument(
        "--target-resource-group",
        help="Target resource group (overrides env AZURE_TARGET_RESOURCE_GROUP)",
    )
    target.add_argument(
        "--target-workspace-name",
        help="Target Log Analytics workspace name (overrides env AZURE_TARGET_WORKSPACE_NAME)",
    )
    target.add_argument(
        "--target-logic-apps-resource-group",
        help="Target RG for Logic Apps (overrides env AZURE_TARGET_LOGIC_APPS_RESOURCE_GROUP)",
    )
    target.add_argument(
        "--target-dcr-resource-group",
        help="Target RG for DCRs (overrides env AZURE_TARGET_DCR_RESOURCE_GROUP)",
    )
    target.add_argument(
        "--target-dce-resource-group",
        help="Target RG for DCEs (overrides env AZURE_TARGET_DCE_RESOURCE_GROUP)",
    )
    target.add_argument(
        "--target-workbooks-resource-group",
        help="Target RG for Workbooks (overrides env AZURE_TARGET_WORKBOOKS_RESOURCE_GROUP)",
    )
    target.add_argument(
        "--target-location",
        help=(
            "Target Azure region for Logic Apps, e.g. 'westeurope'. "
            "When set, overrides the location and rewrites API-connection references "
            "in the backup to point to the target region. "
            "(overrides env AZURE_TARGET_LOCATION)"
        ),
    )

    # ── Backup source ───────────────────────────────────────────────────────
    src = parser.add_argument_group("Backup source")
    src.add_argument(
        "--backup-source-dir",
        help=(
            "Path to the workspace backup folder produced by sentinel_extractor.py. "
            "This is the folder that directly contains AlertRules/, AutomationRules/, etc. "
            "Example: ./output/<subscription-id>/<workspace-name> "
            "(overrides env AZURE_BACKUP_SOURCE_DIR)"
        ),
    )

    # ── What to restore (opt-in) ────────────────────────────────────────────
    what = parser.add_argument_group(
        "What to restore",
        "Pass one or more --restore-* flags to select content types. "
        "Use --restore-all to restore every implemented resource type.",
    )
    what.add_argument("--restore-all", action="store_true", help="Restore all implemented resource types")
    what.add_argument("--restore-alert-rules", action="store_true", help="Restore Alert Rules")
    what.add_argument("--restore-automation-rules", action="store_true", help="Restore Automation Rules")
    what.add_argument("--restore-summary-rules", action="store_true", help="Restore Summary Rules")
    what.add_argument("--restore-hunting", action="store_true", help="Restore Hunting queries")
    what.add_argument("--restore-workspace-functions", action="store_true", help="Restore Workspace Functions (parsers)")
    what.add_argument("--restore-saved-queries", action="store_true", help="Restore Saved Queries")
    what.add_argument("--restore-watchlists", action="store_true", help="Restore Watchlists")
    what.add_argument("--restore-dcr", action="store_true", help="Restore Data Collection Rules")
    what.add_argument("--restore-dce", action="store_true", help="Restore Data Collection Endpoints")
    what.add_argument("--restore-workbooks", action="store_true", help="Restore Workbooks")
    what.add_argument("--restore-logic-apps", action="store_true", help="Restore Logic Apps")
    what.add_argument("--restore-custom-tables", action="store_true", help="Restore Custom Tables")
    what.add_argument("--restore-table-retention", action="store_true", help="Restore table retention settings")
    what.add_argument("--restore-product-settings", action="store_true", help="Restore product settings")
    what.add_argument("--restore-data-connectors", action="store_true", help="Restore Data Connectors")
    what.add_argument("--restore-content-packages", action="store_true", help="Restore (install) Content Packages")
    what.add_argument("--restore-threat-intelligence", action="store_true", help="Restore Threat Intelligence indicators")

    # ── Logic App restore mode ──────────────────────────────────────────────
    parser.add_argument(
        "--logic-app-mode",
        choices=("same-tenant", "new-environment"),
        default="same-tenant",
        help=(
            "Controls how API connections are handled during Logic App restore. "
            "'same-tenant' (default): rewrites connection references to the target "
            "subscription/resource-group/location — connections must already exist "
            "in the target. "
            "'new-environment': strips all connection references so the Logic App "
            "is created without them; you must manually create and configure the "
            "API connections afterwards. Use this when restoring to a different "
            "tenant or a region where the original connections do not exist. "
            "(overrides env AZURE_LOGIC_APP_MODE)"
        ),
    )

    parser.add_argument(
        "--generate-new-id",
        action="store_true",
        help=(
            "Generate a fresh GUID for each restored resource instead of reusing "
            "the original ID from the backup file. "
            "Use this when the target workspace previously held the same rules and "
            "Azure's soft-delete cooldown would cause a 409 conflict."
        ),
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser.parse_args()


def resolve_config(args: argparse.Namespace) -> dict:
    """Merge CLI arguments and .env variables; CLI takes precedence."""
    load_dotenv()

    def require(arg_val, env_key: str, label: str) -> str:
        value = arg_val or os.getenv(env_key, "")
        if not value:
            raise ValueError(
                f"Required value '{label}' is missing. "
                f"Set it via CLI argument or the {env_key} environment variable."
            )
        return value

    def optional(arg_val, env_key: str, fallback_env_key: str = "") -> str:
        value = arg_val or os.getenv(env_key, "")
        if not value and fallback_env_key:
            value = os.getenv(fallback_env_key, "")
        return value

    return {
        # Auth
        "tenant_id":     require(args.tenant_id,     "AZURE_TENANT_ID",     "tenant-id"),
        "client_id":     require(args.client_id,     "AZURE_CLIENT_ID",     "client-id"),
        "client_secret": require(args.client_secret, "AZURE_CLIENT_SECRET", "client-secret"),

        # Target workspace (required)
        "target_subscription_id": require(
            args.target_subscription_id,
            "AZURE_TARGET_SUBSCRIPTION_ID",
            "target-subscription-id",
        ),
        "target_resource_group": require(
            args.target_resource_group,
            "AZURE_TARGET_RESOURCE_GROUP",
            "target-resource-group",
        ),
        "target_workspace_name": require(
            args.target_workspace_name,
            "AZURE_TARGET_WORKSPACE_NAME",
            "target-workspace-name",
        ),

        # Backup source directory (required)
        "backup_source_dir": require(
            args.backup_source_dir,
            "AZURE_BACKUP_SOURCE_DIR",
            "backup-source-dir",
        ),

        # Optional target resource groups
        "target_logic_apps_rg": optional(
            args.target_logic_apps_resource_group,
            "AZURE_TARGET_LOGIC_APPS_RESOURCE_GROUP",
        ),
        "target_dcr_rg": optional(
            args.target_dcr_resource_group,
            "AZURE_TARGET_DCR_RESOURCE_GROUP",
        ),
        "target_dce_rg": optional(
            args.target_dce_resource_group,
            "AZURE_TARGET_DCE_RESOURCE_GROUP",
        ),
        "target_workbooks_rg": optional(
            args.target_workbooks_resource_group,
            "AZURE_TARGET_WORKBOOKS_RESOURCE_GROUP",
            # Fall back to the main target RG (same pattern as extractor)
            "AZURE_TARGET_RESOURCE_GROUP",
        ),
        "target_location": optional(
            args.target_location,
            "AZURE_TARGET_LOCATION",
        ),
        "logic_app_mode": optional(
            args.logic_app_mode,
            "AZURE_LOGIC_APP_MODE",
        ) or LOGIC_APP_MODE_SAME_TENANT,
    }

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _wants(args: argparse.Namespace, flag: str) -> bool:
    """Return True when --restore-all or the specific --restore-<flag> is set."""
    return args.restore_all or getattr(args, f"restore_{flag.replace('-', '_')}")


def main() -> None:
    args = parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    # Guard: require at least one --restore-* flag
    restore_flags = [
        "alert_rules", "automation_rules", "summary_rules", "hunting",
        "workspace_functions", "saved_queries", "watchlists",
        "dcr", "dce", "workbooks", "logic_apps", "custom_tables",
        "table_retention", "product_settings", "data_connectors",
        "content_packages", "threat_intelligence",
    ]
    if not args.restore_all and not any(getattr(args, f"restore_{f}") for f in restore_flags):
        log.error(
            "Nothing to restore. Pass at least one --restore-* flag or use --restore-all.\n"
            "Run with --help to see available options."
        )
        raise SystemExit(1)

    try:
        cfg = resolve_config(args)
    except ValueError as exc:
        log.error("%s", exc)
        raise SystemExit(1) from exc

    # Resolve backup source directory
    input_root = Path(cfg["backup_source_dir"]).resolve()
    if not input_root.exists():
        log.error(
            "Backup source directory does not exist: %s\n"
            "Set AZURE_BACKUP_SOURCE_DIR in .env or pass --backup-source-dir.\n"
            "Expected layout: <dir>/AlertRules/, <dir>/AutomationRules/, etc.",
            input_root,
        )
        raise SystemExit(1)

    log.info("Backup source    : %s", input_root)

    # Build target workspace URLs
    workspace_base = WORKSPACE_BASE.format(
        base=MANAGEMENT_BASE,
        subscription_id=cfg["target_subscription_id"],
        resource_group=cfg["target_resource_group"],
        workspace_name=cfg["target_workspace_name"],
    )
    sentinel_base = workspace_base + "/providers/Microsoft.SecurityInsights"

    log.info(
        "Target workspace : /subscriptions/%s/resourceGroups/%s/workspaces/%s",
        cfg["target_subscription_id"],
        cfg["target_resource_group"],
        cfg["target_workspace_name"],
    )

    # Authenticate
    try:
        token = get_access_token(cfg["tenant_id"], cfg["client_id"], cfg["client_secret"])
        log.info("Authentication successful.")
    except requests.HTTPError as exc:
        log.error("Authentication failed: %s", exc)
        raise SystemExit(1) from exc

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    total_restored = 0

    # ══════════════════════════════════════════════════════════════════════════
    # Phase 1 — Prerequisites
    # Custom Tables, Content Packages, and Data Connectors must be restored
    # before dependent resources (DCRs, DCEs, Alert Rules, Saved Queries,
    # Summary Rules) that reference them.
    # ══════════════════════════════════════════════════════════════════════════

    # ── Custom Tables ────────────────────────────────────────────────────────
    if _wants(args, "custom-tables"):
        try:
            total_restored += restore_custom_tables(workspace_base, headers, input_root)
        except requests.HTTPError as exc:
            log.error("Failed to restore Custom Tables: %s", exc)

    # ── Table Retention ─────────────────────────────────────────────────────
    if _wants(args, "table-retention"):
        try:
            total_restored += restore_table_retention(workspace_base, headers, input_root)
        except requests.HTTPError as exc:
            log.error("Failed to restore table retention settings: %s", exc)

    # ── Content Packages ───────────────────────────────────────────────────
    if _wants(args, "content-packages"):
        try:
            total_restored += restore_content_packages(sentinel_base, headers, input_root)
        except requests.HTTPError as exc:
            log.error("Failed to restore Content Packages: %s", exc)

    # ── Data Connectors ────────────────────────────────────────────────────
    if _wants(args, "data-connectors"):
        try:
            total_restored += restore_data_connectors(sentinel_base, headers, input_root, args.generate_new_id)
        except requests.HTTPError as exc:
            log.error("Failed to restore Data Connectors: %s", exc)

    # ── Product Settings ────────────────────────────────────────────────────
    if _wants(args, "product-settings"):
        try:
            total_restored += restore_product_settings(sentinel_base, headers, input_root)
        except requests.HTTPError as exc:
            log.error("Failed to restore product settings: %s", exc)

    # ══════════════════════════════════════════════════════════════════════════
    # Phase 2 — Dependent resources
    # These may depend on Custom Tables, Content Packages, or Data Connectors
    # already being present in the target workspace.
    # ══════════════════════════════════════════════════════════════════════════

    # ── Alert Rules ──────────────────────────────────────────────────────────
    if _wants(args, "alert-rules"):
        try:
            total_restored += restore_alert_rules(sentinel_base, headers, input_root, args.generate_new_id)
        except requests.HTTPError as exc:
            log.error("Failed to restore Alert Rules: %s", exc)

    # ── Automation Rules ─────────────────────────────────────────────────────
    if _wants(args, "automation-rules"):
        try:
            total_restored += restore_automation_rules(sentinel_base, headers, input_root, args.generate_new_id)
        except requests.HTTPError as exc:
            log.error("Failed to restore Automation Rules: %s", exc)

    # ── Summary Rules ────────────────────────────────────────────────────────
    if _wants(args, "summary-rules"):
        try:
            total_restored += restore_summary_rules(workspace_base, headers, input_root, args.generate_new_id)
        except requests.HTTPError as exc:
            log.error("Failed to restore Summary Rules: %s", exc)

    # ── Hunting ──────────────────────────────────────────────────────────────
    if _wants(args, "hunting"):
        try:
            total_restored += restore_hunting(sentinel_base, workspace_base, headers, input_root, args.generate_new_id)
        except requests.HTTPError as exc:
            log.error("Failed to restore Hunting: %s", exc)

    # ── Workspace Functions ──────────────────────────────────────────────────
    if _wants(args, "workspace-functions"):
        try:
            total_restored += restore_workspace_functions(workspace_base, headers, input_root, args.generate_new_id)
        except requests.HTTPError as exc:
            log.error("Failed to restore Workspace Functions: %s", exc)

    # ── Saved Queries ────────────────────────────────────────────────────────
    if _wants(args, "saved-queries"):
        try:
            total_restored += restore_saved_queries(workspace_base, headers, input_root)
        except requests.HTTPError as exc:
            log.error("Failed to restore Saved Queries: %s", exc)

    # ── Watchlists ───────────────────────────────────────────────────────────
    if _wants(args, "watchlists"):
        try:
            total_restored += restore_watchlists(sentinel_base, headers, input_root, args.generate_new_id)
        except requests.HTTPError as exc:
            log.error("Failed to restore Watchlists: %s", exc)

    # ── DCRs ─────────────────────────────────────────────────────────────────
    if _wants(args, "dcr"):
        dcr_rg = cfg.get("target_dcr_rg", "")
        if dcr_rg:
            try:
                total_restored += restore_dcrs(
                    cfg["target_subscription_id"], dcr_rg, headers, input_root, args.generate_new_id,
                    target_workspace_resource_id=(
                        f"/subscriptions/{cfg['target_subscription_id']}"
                        f"/resourceGroups/{cfg['target_resource_group']}"
                        f"/providers/Microsoft.OperationalInsights/workspaces/{cfg['target_workspace_name']}"
                    ),
                )
            except requests.HTTPError as exc:
                log.error("Failed to restore DCRs: %s", exc)
        else:
            log.info(
                "Skipping DCRs — set --target-dcr-resource-group or "
                "AZURE_TARGET_DCR_RESOURCE_GROUP to enable."
            )

    # ── DCEs ─────────────────────────────────────────────────────────────────
    if _wants(args, "dce"):
        dce_rg = cfg.get("target_dce_rg", "")
        if dce_rg:
            try:
                total_restored += restore_dces(
                    cfg["target_subscription_id"], dce_rg, headers, input_root, args.generate_new_id
                )
            except requests.HTTPError as exc:
                log.error("Failed to restore DCEs: %s", exc)
        else:
            log.info(
                "Skipping DCEs — set --target-dce-resource-group or "
                "AZURE_TARGET_DCE_RESOURCE_GROUP to enable."
            )

    # ── Workbooks ────────────────────────────────────────────────────────────
    if _wants(args, "workbooks"):
        wb_rg = cfg.get("target_workbooks_rg", "")
        if wb_rg:
            try:
                total_restored += restore_workbooks(
                    cfg["target_subscription_id"], wb_rg, headers, input_root,
                    generate_new_id=args.generate_new_id,
                    target_source_id=(
                        f"/subscriptions/{cfg['target_subscription_id']}"
                        f"/resourceGroups/{cfg['target_resource_group']}"
                        f"/providers/Microsoft.OperationalInsights/workspaces/{cfg['target_workspace_name']}"
                    ),
                )
            except requests.HTTPError as exc:
                log.error("Failed to restore Workbooks: %s", exc)
        else:
            log.info(
                "Skipping Workbooks — set --target-workbooks-resource-group or "
                "AZURE_TARGET_WORKBOOKS_RESOURCE_GROUP to enable."
            )

    # ── Logic Apps ───────────────────────────────────────────────────────────
    if _wants(args, "logic-apps"):
        la_rg = cfg.get("target_logic_apps_rg", "")
        if la_rg:
            try:
                total_restored += restore_logic_apps(
                    cfg["target_subscription_id"], la_rg, headers, input_root, args.generate_new_id,
                    target_location=cfg.get("target_location", ""),
                    logic_app_mode=cfg.get("logic_app_mode", LOGIC_APP_MODE_SAME_TENANT),
                )
            except requests.HTTPError as exc:
                log.error("Failed to restore Logic Apps: %s", exc)
        else:
            log.info(
                "Skipping Logic Apps — set --target-logic-apps-resource-group or "
                "AZURE_TARGET_LOGIC_APPS_RESOURCE_GROUP to enable."
            )

    # ── Threat Intelligence ────────────────────────────────────────────────
    if _wants(args, "threat-intelligence"):
        try:
            total_restored += restore_threat_intelligence(sentinel_base, headers, input_root)
        except requests.HTTPError as exc:
            log.error("Failed to restore Threat Intelligence indicators: %s", exc)

    log.info("Restore complete. Total items restored: %d", total_restored)


if __name__ == "__main__":
    main()
