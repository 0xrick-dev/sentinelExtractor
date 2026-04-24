"""
AUTHOR: Predrag (Peter) Petrovic (ppetrovic@microsoft.com)
DESCRIPTION: Sentinel configuration extractor proof of concept.

Microsoft Sentinel Configuration Extractor
Backs up AlertRules, AutomationRules, SummaryRules, Hunting and LogicApps to local JSON files.

Authentication:
  - Azure App Registration (client_id, client_secret, tenant_id) — for CLI use.
  - Managed Identity (DefaultAzureCredential) — for Azure Function App / hosted environments.
"""

import os
import re
import json
import shutil
import logging
import argparse
import hashlib
from datetime import datetime
from pathlib import Path

import requests
from dotenv import load_dotenv
import time

# Optional: azure-identity for Managed Identity auth (used in Function App)
try:
    from azure.identity import DefaultAzureCredential
    _HAS_AZURE_IDENTITY = True
except ImportError:
    _HAS_AZURE_IDENTITY = False

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
API_VERSION_ALERT_RULES = "2023-12-01-preview"
API_VERSION_AUTOMATION_RULES = "2025-01-01-preview"
API_VERSION_SUMMARY_RULES = "2025-07-01"
API_VERSION_HUNTING = "2025-07-01-preview"
API_VERSION_HUNTING_QUERIES = "2025-07-01"
API_VERSION_LOGIC_APPS = "2019-05-01"
API_VERSION_WORKSPACE_FUNCTIONS = "2020-08-01"
API_VERSION_DCR = "2024-03-11"
API_VERSION_DCE = "2024-03-11"
API_VERSION_WORKBOOKS = "2021-08-01"
API_VERSION_WATCHLISTS = "2025-07-01-preview"
API_VERSION_TABLES = "2022-10-01"
API_VERSION_CONTENT_PACKAGES = "2025-07-01-preview"
API_VERSION_DATA_CONNECTORS = "2025-07-01-preview"
API_VERSION_PRODUCT_SETTINGS = "2025-07-01-preview"
API_VERSION_IAM = "2022-04-01"
API_VERSION_THREAT_INTELLIGENCE = "2025-07-01-preview"
API_VERSION_ML_ANALYTICS = "2025-07-01-preview"
MANAGEMENT_BASE = "https://management.azure.com"
TOKEN_URL_TEMPLATE = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
WORKSPACE_BASE = (
    "{base}/subscriptions/{subscription_id}"
    "/resourceGroups/{resource_group}"
    "/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}"
)
SENTINEL_BASE = WORKSPACE_BASE + "/providers/Microsoft.SecurityInsights"


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

def get_access_token(tenant_id: str, client_id: str, client_secret: str) -> str:
    """Obtain a bearer token using client credentials flow."""
    url = TOKEN_URL_TEMPLATE.format(tenant_id=tenant_id)
    payload = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "https://management.azure.com/.default",
    }
    response = requests.post(url, data=payload, timeout=30)
    response.raise_for_status()
    token = response.json().get("access_token")
    if not token:
        raise ValueError("No access_token in authentication response.")
    log.info("Access token acquired successfully (client credentials).")
    return token


def get_access_token_managed_identity() -> str:
    """Obtain a bearer token using DefaultAzureCredential (Managed Identity)."""
    if not _HAS_AZURE_IDENTITY:
        raise ImportError(
            "azure-identity is required for Managed Identity authentication. "
            "Install it with: pip install azure-identity"
        )
    credential = DefaultAzureCredential()
    token = credential.get_token("https://management.azure.com/.default")
    log.info("Access token acquired successfully (managed identity).")
    return token.token


# ---------------------------------------------------------------------------
# Token manager
# ---------------------------------------------------------------------------
class TokenManager:
    """Simple token manager for client-credentials or managed identity.

    - Caches token and expiry; proactively refreshes when less than 5 minutes
      remains.
    - Provides helper to refresh Authorization header in-place.
    """

    def __init__(self, tenant_id: str | None = None, client_id: str | None = None, client_secret: str | None = None, use_managed_identity: bool = False):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.use_managed_identity = use_managed_identity
        self._token: str | None = None
        self._expires_at: float | None = None

    def _fetch_client_credentials(self) -> None:
        url = TOKEN_URL_TEMPLATE.format(tenant_id=self.tenant_id)
        payload = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": "https://management.azure.com/.default",
        }
        resp = requests.post(url, data=payload, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        self._token = data.get("access_token")
        expires_in = int(data.get("expires_in", 3600))
        self._expires_at = time.time() + expires_in
        log.debug("Fetched new access token; expires_in=%s", expires_in)

    def _fetch_managed_identity(self) -> None:
        if not _HAS_AZURE_IDENTITY:
            raise ImportError("azure-identity is required for Managed Identity authentication.")
        credential = DefaultAzureCredential()
        at = credential.get_token("https://management.azure.com/.default")
        self._token = at.token
        # azure.identity returns expires_on as int seconds since epoch
        try:
            self._expires_at = float(at.expires_on)
        except Exception:
            # Fallback: assume 1 hour
            self._expires_at = time.time() + 3600

    def ensure_token(self) -> str:
        """Return a valid access token, refreshing proactively if needed."""
        # Refresh if no token or less than 5 minutes left
        if not self._token or not self._expires_at or (self._expires_at - time.time() < 300):
            if self.use_managed_identity:
                self._fetch_managed_identity()
            else:
                self._fetch_client_credentials()
        return self._token  # type: ignore[return-value]

    def refresh_headers(self, headers: dict) -> None:
        """Ensure the supplied headers dict contains a fresh Authorization header."""
        token = self.ensure_token()
        headers["Authorization"] = f"Bearer {token}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Module-level state for file change tracking
_file_tracker: dict = {}
_tracker_path: Path | None = None
_filename_uid_mode = False
_resume_mode = False

MAX_FILENAME_LENGTH = 255
UID_SUFFIX_LENGTH = 16


def load_tracker(output_root: Path) -> None:
    """Load the file tracker from the output root."""
    global _file_tracker, _tracker_path
    _tracker_path = output_root / ".file_tracker.json"
    if _tracker_path.exists():
        _file_tracker = json.loads(_tracker_path.read_text(encoding="utf-8"))
    else:
        _file_tracker = {}


def set_resume_mode(enabled: bool) -> None:
    """Enable resume mode: skip resources that already have a valid JSON file on disk."""
    global _resume_mode
    _resume_mode = enabled


def should_skip_existing(folder: Path, resource_id: str) -> bool:
    """Return True if resume mode is on and a valid JSON file already exists for this resource.

    Validity = tracker entry present, file exists, non-empty, and parseable JSON.
    A broken/partial file (missing, empty, or invalid JSON) returns False so the
    caller re-fetches and overwrites it — guaranteeing a solid backup.
    """
    if not _resume_mode:
        return False
    tracker_key = f"{folder.name}/{resource_id}"
    entry = _file_tracker.get(tracker_key)
    if not entry:
        return False
    filename = entry.get("filename")
    if not filename:
        return False
    path = folder / filename
    try:
        if not path.exists() or path.stat().st_size == 0:
            return False
        with path.open("r", encoding="utf-8") as fh:
            json.load(fh)
    except (OSError, ValueError):
        log.info("  Resume: existing file is broken, re-fetching: %s", path.name)
        return False
    return True


def persist_tracker() -> None:
    """Write the file tracker back to disk."""
    if _tracker_path:
        _tracker_path.write_text(
            json.dumps(_file_tracker, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )


def set_filename_uid_mode(enabled: bool) -> None:
    """Configure whether filenames should always include a stable UID suffix."""
    global _filename_uid_mode
    _filename_uid_mode = enabled


def _backup_file(file_path: Path) -> None:
    """Move an existing file to older_versions/ with a timestamp suffix."""
    older_dir = file_path.parent / "older_versions"
    older_dir.mkdir(parents=True, exist_ok=True)

    stem = file_path.stem
    ext = file_path.suffix
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_suffix = f"_{timestamp}{ext}"
    trimmed_stem = _trim_filename_stem(stem, MAX_FILENAME_LENGTH - len(backup_suffix))
    backup_name = f"{trimmed_stem}{backup_suffix}"
    backup_path = older_dir / backup_name

    shutil.move(str(file_path), str(backup_path))
    log.info("  Backed up: %s -> %s", file_path.name, backup_path)


def safe_filename(name: str) -> str:
    """Convert a display name to a safe filename (keep spaces, remove illegal chars)."""
    # Remove characters not allowed in Windows filenames
    sanitized = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name)
    # Trim trailing dots/spaces (Windows quirk)
    sanitized = sanitized.strip(". ")
    if not sanitized:
        sanitized = "unnamed"
    return sanitized


def resource_filename_uid(resource_id: str) -> str:
    """Return a stable short UID for a resource identifier."""
    return hashlib.sha1(resource_id.encode("utf-8")).hexdigest()[:UID_SUFFIX_LENGTH]


def _trim_filename_stem(stem: str, max_length: int) -> str:
    """Trim a filename stem while preserving Windows filename constraints."""
    if max_length <= 0:
        return "unnamed"
    trimmed = stem[:max_length].rstrip(" ._")
    return trimmed or "unnamed"


def build_resource_filename(display_name: str, resource_id: str, extension: str = ".json") -> str:
    """Build a safe, unique filename that fits within Windows component limits."""
    sanitized = safe_filename(display_name)
    uid = resource_filename_uid(resource_id)
    uid_suffix = f"_{uid}"
    max_stem_length = MAX_FILENAME_LENGTH - len(extension)

    if _filename_uid_mode:
        prefix_budget = max_stem_length - len(uid_suffix)
        prefix = _trim_filename_stem(sanitized, prefix_budget)
        return f"{prefix}{uid_suffix}{extension}"

    candidate = f"{sanitized}{extension}"
    if len(candidate) <= MAX_FILENAME_LENGTH:
        return candidate

    prefix_budget = max_stem_length - len(uid_suffix)
    prefix = _trim_filename_stem(sanitized, prefix_budget)
    return f"{prefix}{uid_suffix}{extension}"


def get_paginated(url: str, headers: dict, params: dict) -> list:
    """Fetch all items from a paginated Azure REST list endpoint."""
    items = []
    next_link = url
    extra_params = params.copy()

    while next_link:
        if next_link == url:
            response = requests.get(next_link, headers=headers, params=extra_params, timeout=30)
        else:
            # nextLink already contains query string parameters
            response = requests.get(next_link, headers=headers, timeout=30)

        response.raise_for_status()
        data = response.json()
        log.debug("Response JSON keys: %s", list(data.keys()))
        batch = data.get("value", [])
        items.extend(batch)
        log.debug("Fetched %d items (total so far: %d)", len(batch), len(items))
        next_link = data.get("nextLink")

    return items


def save_json(folder: Path, display_name: str, rule_id: str, data: dict) -> bool:
    """Save a rule dict as a JSON file. Returns True if file was written (new/changed)."""
    filename = build_resource_filename(display_name, rule_id)
    output_path = folder / filename
    new_content = json.dumps(data, indent=2, ensure_ascii=False)

    # Check tracker for previously used filename for this resource
    tracker_key = f"{folder.name}/{rule_id}"
    prev_entry = _file_tracker.get(tracker_key)
    if prev_entry:
        tracked_filename = prev_entry["filename"]
        if len(tracked_filename) <= MAX_FILENAME_LENGTH:
            output_path = folder / tracked_filename
    elif output_path.exists():
        # Handle name collisions by appending part of the resource id
        filename = build_resource_filename(f"{display_name}_{rule_id.split('/')[-1][:8]}", rule_id)
        output_path = folder / filename

    # Change detection
    if output_path.exists():
        existing_content = output_path.read_text(encoding="utf-8")
        if existing_content == new_content:
            log.debug("  No change: %s", output_path)
            return False
        # Content changed — backup old version
        _backup_file(output_path)

    output_path.write_text(new_content, encoding="utf-8")
    log.info("  Saved: %s", output_path)

    # Update tracker
    _file_tracker[tracker_key] = {
        "filename": output_path.name,
        "lastModified": datetime.now().isoformat(),
    }
    return True


# ---------------------------------------------------------------------------
# Extraction logic
# ---------------------------------------------------------------------------

def extract_alert_rules(sentinel_base: str, headers: dict, output_root: Path) -> int:
    """List all alert rules and save each one individually."""
    folder = output_root / "AlertRules"
    folder.mkdir(parents=True, exist_ok=True)

    list_url = f"{sentinel_base}/alertRules"
    params = {"api-version": API_VERSION_ALERT_RULES}

    log.info("Fetching alert rules list …")
    rules = get_paginated(list_url, headers, params)
    log.info("Found %d alert rule(s).", len(rules))

    saved = 0
    for rule in rules:
        try:
            rule_id: str = rule.get("name", "")
            kind: str = rule.get("kind", "Unknown")
            display_name: str = (
                rule.get("properties", {}).get("displayName")
                or rule.get("name")
                or "unknown"
            )
            if should_skip_existing(folder, rule_id):
                log.info("Skipping existing alert rule [kind=%s]: %s", kind, display_name)
                continue
            log.info("Processing alert rule [kind=%s]: %s", kind, display_name)

            # Fetch the full rule details
            get_url = f"{sentinel_base}/alertRules/{rule_id}"
            try:
                resp = requests.get(get_url, headers=headers, params=params, timeout=30)
                resp.raise_for_status()
                full_rule = resp.json()
            except requests.RequestException as exc:
                log.warning("  Could not fetch rule %s (%s): %s — using list data", rule_id, kind, exc)
                full_rule = rule  # fall back to list data

            if save_json(folder, display_name, rule_id, full_rule):
                saved += 1
        except Exception as exc:  # noqa: BLE001
            log.error("  Unexpected error processing alert rule %s: %s", rule.get("name", "?"), exc)

    return saved


def extract_automation_rules(sentinel_base: str, headers: dict, output_root: Path) -> int:
    """List all automation rules and save each one individually."""
    folder = output_root / "AutomationRules"
    folder.mkdir(parents=True, exist_ok=True)

    list_url = f"{sentinel_base}/automationRules"
    params = {"api-version": API_VERSION_AUTOMATION_RULES}

    log.info("Fetching automation rules list …")
    rules = get_paginated(list_url, headers, params)
    log.info("Found %d automation rule(s).", len(rules))

    saved = 0
    for rule in rules:
        try:
            rule_id: str = rule.get("name", "")
            display_name: str = (
                rule.get("properties", {}).get("displayName")
                or rule.get("name")
                or "unknown"
            )
            if should_skip_existing(folder, rule_id):
                log.info("Skipping existing automation rule: %s", display_name)
                continue
            log.info("Processing automation rule: %s", display_name)

            # Fetch the full rule details
            get_url = f"{sentinel_base}/automationRules/{rule_id}"
            try:
                resp = requests.get(get_url, headers=headers, params=params, timeout=30)
                resp.raise_for_status()
                full_rule = resp.json()
            except requests.RequestException as exc:
                log.warning("  Could not fetch automation rule %s: %s — using list data", rule_id, exc)
                full_rule = rule  # fall back to list data

            if save_json(folder, display_name, rule_id, full_rule):
                saved += 1
        except Exception as exc:  # noqa: BLE001
            log.error("  Unexpected error processing automation rule %s: %s", rule.get("name", "?"), exc)

    return saved


def extract_summary_rules(workspace_base: str, headers: dict, output_root: Path) -> int:
    """List all summary rules and save each one individually."""
    folder = output_root / "SummaryRules"
    folder.mkdir(parents=True, exist_ok=True)

    list_url = f"{workspace_base}/summaryLogs"
    params = {"api-version": API_VERSION_SUMMARY_RULES}

    log.info("Fetching summary rules list …")
    rules = get_paginated(list_url, headers, params)
    log.info("Found %d summary rule(s).", len(rules))

    saved = 0
    for rule in rules:
        try:
            rule_name: str = rule.get("name", "")
            display_name: str = (
                rule.get("properties", {}).get("displayName")
                or rule_name
                or "unknown"
            )
            if should_skip_existing(folder, rule_name):
                log.info("Skipping existing summary rule: %s", display_name)
                continue
            log.info("Processing summary rule: %s", display_name)

            # Fetch the full rule details
            get_url = f"{workspace_base}/summaryLogs/{rule_name}"
            try:
                resp = requests.get(get_url, headers=headers, params=params, timeout=30)
                resp.raise_for_status()
                full_rule = resp.json()
            except requests.RequestException as exc:
                log.warning("  Could not fetch summary rule %s: %s — using list data", rule_name, exc)
                full_rule = rule  # fall back to list data

            if save_json(folder, display_name, rule_name, full_rule):
                saved += 1
        except Exception as exc:  # noqa: BLE001
            log.error("  Unexpected error processing summary rule %s: %s", rule.get("name", "?"), exc)

    return saved


def _fetch_saved_searches(workspace_base: str, headers: dict) -> list:
    """Fetch all saved searches from the workspace. Returns the raw list."""
    list_url = f"{workspace_base}/savedSearches"
    params = {"api-version": API_VERSION_WORKSPACE_FUNCTIONS}
    resp = requests.get(list_url, headers=headers, params=params, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    return data if isinstance(data, list) else data.get("value", [])


def extract_workspace_functions(workspace_base: str, headers: dict, output_root: Path) -> int:
    """List all workspace functions (parsers) and save each one.

    Only items with a functionAlias are saved — plain saved searches are excluded.
    The savedSearches list returns the full definition so no per-item GET is needed.
    """
    folder = output_root / "WorkspaceFunctions"
    folder.mkdir(parents=True, exist_ok=True)

    log.info("Fetching workspace saved searches …")
    try:
        all_items = _fetch_saved_searches(workspace_base, headers)
    except requests.RequestException as exc:
        log.error("Failed to list workspace saved searches: %s", exc)
        return 0

    # Filter to functions only (items with a functionAlias)
    functions = [
        item for item in all_items
        if item.get("properties", {}).get("functionAlias")
    ]
    log.info("Found %d workspace function(s) (out of %d saved searches).", len(functions), len(all_items))

    saved = 0
    for func in functions:
        try:
            func_id: str = func.get("name", "")
            display_name: str = (
                func.get("properties", {}).get("displayName")
                or func.get("properties", {}).get("functionAlias")
                or func_id
                or "unknown"
            )
            if should_skip_existing(folder, func_id):
                log.info("Skipping existing workspace function: %s", display_name)
                continue
            log.info("Processing workspace function: %s", display_name)
            if save_json(folder, display_name, func_id, func):
                saved += 1
        except Exception as exc:  # noqa: BLE001
            log.error("  Unexpected error processing function %s: %s", func.get("name", "?"), exc)

    return saved


def extract_saved_queries(workspace_base: str, headers: dict, output_root: Path) -> int:
    """Save all saved queries in the workspace (savedSearches without a functionAlias)."""
    folder = output_root / "SavedQueries"
    folder.mkdir(parents=True, exist_ok=True)

    log.info("Fetching saved queries …")
    try:
        all_items = _fetch_saved_searches(workspace_base, headers)
    except requests.RequestException as exc:
        log.error("Failed to list saved queries: %s", exc)
        return 0

    # Saved queries are saved searches WITHOUT a functionAlias
    queries = [
        item for item in all_items
        if not item.get("properties", {}).get("functionAlias")
    ]
    log.info("Found %d saved quer(ies) (out of %d saved searches).", len(queries), len(all_items))

    saved = 0
    for query in queries:
        try:
            query_id: str = query.get("name", "")
            display_name: str = (
                query.get("properties", {}).get("displayName")
                or query_id
                or "unknown"
            )
            if should_skip_existing(folder, query_id):
                log.info("Skipping existing saved query: %s", display_name)
                continue
            log.info("Processing saved query: %s", display_name)
            if save_json(folder, display_name, query_id, query):
                saved += 1
        except Exception as exc:  # noqa: BLE001
            log.error("  Unexpected error processing saved query %s: %s", query.get("name", "?"), exc)

    return saved


def extract_dcrs(
    subscription_id: str,
    resource_group: str,
    workspace_resource_id: str,
    headers: dict,
    output_root: Path,
) -> int:
    """List all DCRs in the resource group that target the workspace and save each one."""
    folder = output_root / "DataCollectionRules"
    folder.mkdir(parents=True, exist_ok=True)

    list_url = (
        f"{MANAGEMENT_BASE}/subscriptions/{subscription_id}"
        f"/resourceGroups/{resource_group}"
        f"/providers/Microsoft.Insights/dataCollectionRules"
    )
    params = {"api-version": API_VERSION_DCR}

    log.info("Fetching Data Collection Rules from resource group '%s' …", resource_group)
    all_dcrs = get_paginated(list_url, headers, params)
    log.info("Found %d DCR(s) total, filtering for workspace association …", len(all_dcrs))

    # Filter to DCRs that send data to this workspace
    ws_id_lower = workspace_resource_id.lower()
    dcrs = [
        dcr for dcr in all_dcrs
        if any(
            la.get("workspaceResourceId", "").lower() == ws_id_lower
            for la in dcr.get("properties", {}).get("destinations", {}).get("logAnalytics", [])
        )
    ]
    log.info("%d DCR(s) associated with workspace.", len(dcrs))

    saved = 0
    for dcr in dcrs:
        try:
            dcr_name: str = dcr.get("name", "")
            display_name: str = dcr_name or "unknown"
            if should_skip_existing(folder, dcr_name):
                log.info("Skipping existing DCR: %s", display_name)
                continue
            log.info("Processing DCR: %s", display_name)
            if save_json(folder, display_name, dcr_name, dcr):
                saved += 1
        except Exception as exc:  # noqa: BLE001
            log.error("  Unexpected error processing DCR %s: %s", dcr.get("name", "?"), exc)

    return saved


def extract_dces(
    subscription_id: str,
    resource_group: str,
    headers: dict,
    output_root: Path,
) -> int:
    """List all Data Collection Endpoints in the resource group and save each one."""
    folder = output_root / "DataCollectionEndpoints"
    folder.mkdir(parents=True, exist_ok=True)

    list_url = (
        f"{MANAGEMENT_BASE}/subscriptions/{subscription_id}"
        f"/resourceGroups/{resource_group}"
        f"/providers/Microsoft.Insights/dataCollectionEndpoints"
    )
    params = {"api-version": API_VERSION_DCE}

    log.info("Fetching Data Collection Endpoints from resource group '%s' …", resource_group)
    dces = get_paginated(list_url, headers, params)
    log.info("Found %d DCE(s).", len(dces))

    saved = 0
    for dce in dces:
        try:
            dce_name: str = dce.get("name", "")
            display_name: str = dce_name or "unknown"
            if should_skip_existing(folder, dce_name):
                log.info("Skipping existing DCE: %s", display_name)
                continue
            log.info("Processing DCE: %s", display_name)
            if save_json(folder, display_name, dce_name, dce):
                saved += 1
        except Exception as exc:  # noqa: BLE001
            log.error("  Unexpected error processing DCE %s: %s", dce.get("name", "?"), exc)

    return saved


def extract_workbooks(
    subscription_id: str,
    resource_group: str,
    workspace_resource_id: str,
    headers: dict,
    output_root: Path,
) -> int:
    """List all workbooks linked to the workspace and save each one.

    Uses sourceId filter so only workbooks associated with this workspace are returned.
    canFetchContent=true returns full serializedData in the list — no per-item GET needed.
    """
    folder = output_root / "Workbooks"
    folder.mkdir(parents=True, exist_ok=True)

    list_url = (
        f"{MANAGEMENT_BASE}/subscriptions/{subscription_id}"
        f"/resourceGroups/{resource_group}"
        f"/providers/Microsoft.Insights/workbooks"
    )
    categories = ["sentinel", "workbook"]
    all_workbooks: list = []
    for cat in categories:
        params = {
            "api-version": API_VERSION_WORKBOOKS,
            "category": cat,
            "canFetchContent": "true",
        }
        log.info("Fetching workbooks from resource group '%s' (category=%s) …", resource_group, cat)
        all_workbooks.extend(get_paginated(list_url, headers, params))

    log.info("Found %d workbook(s) total in RG, filtering by workspace sourceId …", len(all_workbooks))

    # Filter client-side with case-insensitive sourceId match — the API's
    # sourceId filter is case-sensitive but Azure stores the path in lowercase.
    ws_id_lower = workspace_resource_id.lower()
    workbooks = [
        wb for wb in all_workbooks
        if wb.get("properties", {}).get("sourceId", "").lower() == ws_id_lower
    ]
    log.info("Found %d workbook(s) linked to workspace.", len(workbooks))

    saved = 0
    for wb in workbooks:
        try:
            wb_name: str = wb.get("name", "")
            display_name: str = (
                wb.get("properties", {}).get("displayName")
                or wb_name
                or "unknown"
            )
            if should_skip_existing(folder, wb_name):
                log.info("Skipping existing workbook: %s", display_name)
                continue
            log.info("Processing workbook: %s", display_name)
            if save_json(folder, display_name, wb_name, wb):
                saved += 1
        except Exception as exc:  # noqa: BLE001
            log.error("  Unexpected error processing workbook %s: %s", wb.get("name", "?"), exc)

    return saved


def extract_hunting(sentinel_base: str, workspace_base: str, headers: dict, output_root: Path) -> int:
    """List all hunts, save each one, fetch+save hunt relations and their linked saved searches."""
    folder = output_root / "Hunting"
    folder.mkdir(parents=True, exist_ok=True)
    queries_folder = folder / "HuntingQueries"
    queries_folder.mkdir(parents=True, exist_ok=True)

    list_url = f"{sentinel_base}/hunts"
    params = {"api-version": API_VERSION_HUNTING}

    log.info("Fetching hunts list …")
    hunts = get_paginated(list_url, headers, params)
    log.info("Found %d hunt(s).", len(hunts))

    saved = 0
    for hunt in hunts:
        try:
            hunt_id: str = hunt.get("name", "")
            display_name: str = (
                hunt.get("properties", {}).get("displayName")
                or hunt_id
                or "unknown"
            )
            if should_skip_existing(folder, hunt_id):
                log.info("Skipping existing hunt: %s", display_name)
                continue
            log.info("Processing hunt: %s", display_name)

            get_url = f"{sentinel_base}/hunts/{hunt_id}"
            try:
                resp = requests.get(get_url, headers=headers, params=params, timeout=30)
                resp.raise_for_status()
                full_hunt = resp.json()
            except requests.RequestException as exc:
                log.warning("  Could not fetch hunt %s: %s — using list data", hunt_id, exc)
                full_hunt = hunt

            if save_json(folder, display_name, hunt_id, full_hunt):
                saved += 1

            # Fetch hunt relations (linked queries / saved searches)
            relations_url = f"{sentinel_base}/hunts/{hunt_id}/relations"
            try:
                relations = get_paginated(relations_url, headers, params)
                log.info("  Found %d relation(s) for hunt '%s'.", len(relations), display_name)
            except requests.RequestException as exc:
                log.warning("  Could not fetch relations for hunt '%s': %s", display_name, exc)
                relations = []

            if relations:
                details_data = {"value": relations}
                details_name = f"{display_name}_details"
                details_id = f"{hunt_id}_relations"
                save_json(folder, details_name, details_id, details_data)

                # Fetch each related saved search and save to HuntingQueries/
                ss_params = {"api-version": API_VERSION_HUNTING_QUERIES}
                for relation in relations:
                    try:
                        rel_props = relation.get("properties", {})
                        related_id = rel_props.get("relatedResourceId", "")
                        if not related_id:
                            continue
                        # Extract the saved search ID from the resource path
                        ss_id = related_id.rsplit("/", 1)[-1]
                        ss_url = f"{workspace_base}/savedSearches/{ss_id}"
                        resp = requests.get(ss_url, headers=headers, params=ss_params, timeout=30)
                        resp.raise_for_status()
                        ss_data = resp.json()
                        ss_display = (
                            ss_data.get("properties", {}).get("displayName")
                            or ss_id
                        )
                        log.info("  Saving hunting query: %s", ss_display)
                        save_json(queries_folder, ss_display, ss_id, ss_data)
                    except requests.RequestException as exc:
                        log.warning(
                            "  Could not fetch saved search %s: %s",
                            rel_props.get("relatedResourceName", "?"), exc,
                        )
                    except Exception as exc:  # noqa: BLE001
                        log.error(
                            "  Unexpected error fetching saved search for relation: %s", exc,
                        )

        except Exception as exc:  # noqa: BLE001
            log.error("  Unexpected error processing hunt %s: %s", hunt.get("name", "?"), exc)

    return saved


def extract_logic_apps(subscription_id: str, resource_group: str, headers: dict, output_root: Path) -> int:
    """List all Logic Apps in the given resource group and save each workflow definition."""
    folder = output_root / "LogicApps"
    folder.mkdir(parents=True, exist_ok=True)

    list_url = (
        f"{MANAGEMENT_BASE}/subscriptions/{subscription_id}"
        f"/resourceGroups/{resource_group}"
        f"/providers/Microsoft.Logic/workflows"
    )
    params = {"api-version": API_VERSION_LOGIC_APPS}

    log.info("Fetching Logic Apps from resource group '%s' …", resource_group)
    apps = get_paginated(list_url, headers, params)
    log.info("Found %d Logic App(s).", len(apps))

    saved = 0
    for app in apps:
        try:
            app_name: str = app.get("name", "")
            display_name: str = app_name or "unknown"
            if should_skip_existing(folder, app_name):
                log.info("Skipping existing Logic App: %s", display_name)
                continue
            log.info("Processing Logic App: %s", display_name)

            get_url = (
                f"{MANAGEMENT_BASE}/subscriptions/{subscription_id}"
                f"/resourceGroups/{resource_group}"
                f"/providers/Microsoft.Logic/workflows/{app_name}"
            )
            try:
                resp = requests.get(get_url, headers=headers, params=params, timeout=30)
                resp.raise_for_status()
                full_app = resp.json()
            except requests.RequestException as exc:
                log.warning("  Could not fetch Logic App %s: %s — using list data", app_name, exc)
                full_app = app

            if save_json(folder, display_name, app_name, full_app):
                saved += 1
        except Exception as exc:  # noqa: BLE001
            log.error("  Unexpected error processing Logic App %s: %s", app.get("name", "?"), exc)

    return saved


def extract_watchlists(
    sentinel_base: str,
    headers: dict,
    output_root: Path,
    token_mgr: "TokenManager | None" = None,
    skip_existing: bool = False,
) -> int:
    """List all Watchlists and their items; save each watchlist as a single JSON file.

    If `token_mgr` is provided, the access token is refreshed before each watchlist
    so long-running exports do not 401 on token expiry. If `skip_existing` is True,
    any watchlist already present in the file tracker is skipped (resume mode).
    """
    folder = output_root / "Watchlists"
    folder.mkdir(parents=True, exist_ok=True)

    list_url = f"{sentinel_base}/watchlists"
    params = {"api-version": API_VERSION_WATCHLISTS}

    log.info("Fetching Watchlists …")
    if token_mgr is not None:
        token_mgr.refresh_headers(headers)
    watchlists = get_paginated(list_url, headers, params)
    log.info("Found %d Watchlist(s).", len(watchlists))

    saved = 0
    skipped = 0
    for watchlist in watchlists:
        try:
            props = watchlist.get("properties", {})
            display_name: str = props.get("displayName") or watchlist.get("name", "unknown")
            watchlist_alias: str = props.get("watchlistAlias") or watchlist.get("name", "")

            # Resume support: skip watchlists already saved on disk
            if skip_existing or should_skip_existing(folder, watchlist_alias):
                log.info("Skipping existing Watchlist: %s", display_name)
                skipped += 1
                continue

            log.info("Processing Watchlist: %s", display_name)

            # Refresh token before each watchlist to survive long-running exports
            if token_mgr is not None:
                token_mgr.refresh_headers(headers)

            # Fetch all items for this watchlist
            items_url = f"{sentinel_base}/watchlists/{watchlist_alias}/watchlistItems"
            try:
                items = get_paginated(items_url, headers, params)
                log.info("  Found %d item(s) for watchlist '%s'.", len(items), display_name)
            except requests.RequestException as exc:
                log.warning("  Could not fetch items for watchlist '%s': %s", display_name, exc)
                items = []

            # Combine watchlist metadata and its items into one document
            combined = dict(watchlist)
            combined["watchlistItems"] = items

            if save_json(folder, display_name, watchlist_alias, combined):
                saved += 1
                # Persist tracker after every successful watchlist so a later
                # crash does not lose resume state
                try:
                    persist_tracker()
                except Exception:  # noqa: BLE001
                    pass
        except Exception as exc:  # noqa: BLE001
            log.error(
                "  Unexpected error processing Watchlist %s: %s",
                watchlist.get("name", "?"),
                exc,
            )

    if skip_existing and skipped:
        log.info("Watchlists skipped (already on disk): %d", skipped)
    return saved


def extract_custom_tables(workspace_base: str, headers: dict, output_root: Path) -> int:
    """List all custom tables (_CL) in the workspace and save each one."""
    folder = output_root / "CustomTables"
    folder.mkdir(parents=True, exist_ok=True)

    list_url = f"{workspace_base}/tables"
    params = {"api-version": API_VERSION_TABLES}

    log.info("Fetching tables list …")
    tables = get_paginated(list_url, headers, params)
    log.info("Found %d table(s) total, filtering for custom tables …", len(tables))

    # Keep only custom tables — must end with _CL
    custom_tables = [
        t for t in tables
        if t.get("name", "").endswith("_CL")
    ]
    log.info("%d custom table(s) found.", len(custom_tables))

    saved = 0
    for table in custom_tables:
        try:
            table_name: str = table.get("name", "")
            display_name: str = table_name or "unknown"
            if should_skip_existing(folder, table_name):
                log.info("Skipping existing custom table: %s", display_name)
                continue
            log.info("Processing custom table: %s", display_name)
            if save_json(folder, display_name, table_name, table):
                saved += 1
        except Exception as exc:  # noqa: BLE001
            log.error("  Unexpected error processing table %s: %s", table.get("name", "?"), exc)

    return saved


def extract_table_retention(workspace_base: str, headers: dict, output_root: Path) -> int:
    """Extract retention settings for all tables in the workspace.

    Saves a single JSON file containing an array of per-table retention
    entries: table name, retentionInDays, totalRetentionInDays,
    archiveRetentionInDays, and plan.
    """
    list_url = f"{workspace_base}/tables"
    params = {"api-version": API_VERSION_TABLES}

    log.info("Fetching tables for retention settings …")
    tables = get_paginated(list_url, headers, params)
    log.info("Found %d table(s).", len(tables))

    retention_entries = []
    for table in tables:
        props = table.get("properties", {})
        entry = {
            "name": table.get("name", ""),
            "retentionInDays": props.get("retentionInDays"),
            "totalRetentionInDays": props.get("totalRetentionInDays"),
            "archiveRetentionInDays": props.get("archiveRetentionInDays"),
            "plan": props.get("plan"),
        }
        retention_entries.append(entry)

    output_path = output_root / "table_retention.json"
    new_content = json.dumps(retention_entries, indent=2, ensure_ascii=False)

    if output_path.exists():
        existing_content = output_path.read_text(encoding="utf-8")
        if existing_content == new_content:
            log.debug("No change in table retention settings.")
            return 0
        _backup_file(output_path)

    output_path.write_text(new_content, encoding="utf-8")
    log.info("Saved table retention settings for %d table(s) to: %s", len(retention_entries), output_path)
    return 1


def extract_content_packages(sentinel_base: str, headers: dict, output_root: Path) -> int:
    """List all installed content packages (solutions) and save each one."""
    folder = output_root / "ContentPackages"
    folder.mkdir(parents=True, exist_ok=True)

    list_url = f"{sentinel_base}/contentPackages"
    params = {"api-version": API_VERSION_CONTENT_PACKAGES}

    log.info("Fetching content packages list \u2026")
    packages = get_paginated(list_url, headers, params)
    log.info("Found %d content package(s).", len(packages))

    saved = 0
    for pkg in packages:
        try:
            pkg_id: str = pkg.get("name", "")
            display_name: str = (
                pkg.get("properties", {}).get("displayName")
                or pkg_id
                or "unknown"
            )
            if should_skip_existing(folder, pkg_id):
                log.info("Skipping existing content package: %s", display_name)
                continue
            log.info("Processing content package: %s", display_name)
            if save_json(folder, display_name, pkg_id, pkg):
                saved += 1
        except Exception as exc:  # noqa: BLE001
            log.error("  Unexpected error processing content package %s: %s", pkg.get("name", "?"), exc)

    return saved


def extract_data_connectors(sentinel_base: str, headers: dict, output_root: Path) -> int:
    """List all data connectors and save each one."""
    folder = output_root / "DataConnectors"
    folder.mkdir(parents=True, exist_ok=True)

    list_url = f"{sentinel_base}/dataConnectors"
    params = {"api-version": API_VERSION_DATA_CONNECTORS}

    log.info("Fetching data connectors list \u2026")
    connectors = get_paginated(list_url, headers, params)
    log.info("Found %d data connector(s).", len(connectors))

    saved = 0
    for connector in connectors:
        try:
            connector_id: str = connector.get("name", "")
            kind: str = connector.get("kind", "Unknown")
            display_name: str = (
                connector.get("properties", {}).get("connectorUiConfig", {}).get("title")
                or connector_id
                or "unknown"
            )
            if should_skip_existing(folder, connector_id):
                log.info("Skipping existing data connector [kind=%s]: %s", kind, display_name)
                continue
            log.info("Processing data connector [kind=%s]: %s", kind, display_name)
            if save_json(folder, display_name, connector_id, connector):
                saved += 1
        except Exception as exc:  # noqa: BLE001
            log.error("  Unexpected error processing data connector %s: %s", connector.get("name", "?"), exc)

    return saved


def extract_product_settings(sentinel_base: str, headers: dict, output_root: Path) -> int:
    """List all Sentinel product settings and save each one."""
    folder = output_root / "ProductSettings"
    folder.mkdir(parents=True, exist_ok=True)

    list_url = f"{sentinel_base}/settings"
    params = {"api-version": API_VERSION_PRODUCT_SETTINGS}

    log.info("Fetching product settings \u2026")
    resp = requests.get(list_url, headers=headers, params=params, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    settings = data.get("value", [])
    log.info("Found %d product setting(s).", len(settings))

    saved = 0
    for setting in settings:
        try:
            setting_name: str = setting.get("name", "")
            kind: str = setting.get("kind", "Unknown")
            display_name: str = setting_name or kind or "unknown"
            if should_skip_existing(folder, setting_name):
                log.info("Skipping existing product setting [kind=%s]: %s", kind, display_name)
                continue
            log.info("Processing product setting [kind=%s]: %s", kind, display_name)
            if save_json(folder, display_name, setting_name, setting):
                saved += 1
        except Exception as exc:  # noqa: BLE001
            log.error("  Unexpected error processing product setting %s: %s", setting.get("name", "?"), exc)

    return saved


def extract_threat_intelligence(sentinel_base: str, headers: dict, output_root: Path) -> int:
    """Get the total count and then list all threat intelligence indicators."""
    folder = output_root / "ThreatIntelligence"
    folder.mkdir(parents=True, exist_ok=True)

    params = {"api-version": API_VERSION_THREAT_INTELLIGENCE}

    # Get total indicator count first
    count_url = f"{sentinel_base}/threatIntelligence/main/count"
    try:
        resp = requests.post(count_url, headers=headers, params=params, json={}, timeout=30)
        resp.raise_for_status()
        ti_count = resp.json().get("count", 0)
        log.info("Threat intelligence indicator count: %d", ti_count)
    except requests.RequestException as exc:
        log.warning("Could not fetch TI count: %s — proceeding with list.", exc)

    # List all indicators (paginated)
    list_url = f"{sentinel_base}/threatIntelligence/main/indicators"
    log.info("Fetching threat intelligence indicators …")
    indicators = get_paginated(list_url, headers, params)
    log.info("Found %d threat intelligence indicator(s).", len(indicators))

    saved = 0
    for indicator in indicators:
        try:
            indicator_id: str = indicator.get("name", "")
            display_name: str = (
                indicator.get("properties", {}).get("displayName")
                or indicator_id
                or "unknown"
            )
            if should_skip_existing(folder, indicator_id):
                log.debug("Skipping existing TI indicator: %s", display_name)
                continue
            log.info("Processing threat intelligence indicator: %s", display_name)
            if save_json(folder, display_name, indicator_id, indicator):
                saved += 1
        except Exception as exc:  # noqa: BLE001
            log.error("  Unexpected error processing TI indicator %s: %s", indicator.get("name", "?"), exc)

    return saved


def extract_ml_analytics_settings(sentinel_base: str, headers: dict, output_root: Path) -> int:
    """List all Security ML Analytics Settings and save each one."""
    folder = output_root / "MLAnalyticsSettings"
    folder.mkdir(parents=True, exist_ok=True)

    list_url = f"{sentinel_base}/securityMLAnalyticsSettings"
    params = {"api-version": API_VERSION_ML_ANALYTICS}

    log.info("Fetching Security ML Analytics Settings \u2026")
    settings = get_paginated(list_url, headers, params)
    log.info("Found %d ML Analytics setting(s).", len(settings))

    saved = 0
    for setting in settings:
        try:
            setting_id: str = setting.get("name", "")
            kind: str = setting.get("kind", "Unknown")
            display_name: str = (
                setting.get("properties", {}).get("displayName")
                or setting_id
                or "unknown"
            )
            if should_skip_existing(folder, setting_id):
                log.info("Skipping existing ML Analytics setting [kind=%s]: %s", kind, display_name)
                continue
            log.info("Processing ML Analytics setting [kind=%s]: %s", kind, display_name)
            if save_json(folder, display_name, setting_id, setting):
                saved += 1
        except Exception as exc:  # noqa: BLE001
            log.error("  Unexpected error processing ML Analytics setting %s: %s", setting.get("name", "?"), exc)

    return saved


def extract_iam_role_assignments(
    subscription_id: str,
    resource_group: str,
    headers: dict,
    output_root: Path,
) -> int:
    """List all IAM role assignments on the resource group and save each one."""
    folder = output_root / "IAM"
    folder.mkdir(parents=True, exist_ok=True)

    list_url = (
        f"{MANAGEMENT_BASE}/subscriptions/{subscription_id}"
        f"/resourceGroups/{resource_group}"
        f"/providers/Microsoft.Authorization/roleAssignments"
    )
    params = {"api-version": API_VERSION_IAM}

    log.info("Fetching IAM role assignments from resource group '%s' \u2026", resource_group)
    assignments = get_paginated(list_url, headers, params)
    log.info("Found %d role assignment(s).", len(assignments))

    saved = 0
    for assignment in assignments:
        try:
            assignment_name: str = assignment.get("name", "")
            props = assignment.get("properties", {})
            principal_type: str = props.get("principalType", "")
            principal_id: str = props.get("principalId", "")
            display_name: str = (
                f"{principal_type}_{principal_id[:8]}"
                if principal_type and principal_id
                else assignment_name
                or "unknown"
            )
            if should_skip_existing(folder, assignment_name):
                log.info("Skipping existing role assignment: %s", display_name)
                continue
            log.info("Processing role assignment: %s", display_name)
            if save_json(folder, display_name, assignment_name, assignment):
                saved += 1
        except Exception as exc:  # noqa: BLE001
            log.error(
                "  Unexpected error processing role assignment %s: %s",
                assignment.get("name", "?"),
                exc,
            )

    return saved


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract Microsoft Sentinel configuration (AlertRules, AutomationRules, SummaryRules, Hunting, WorkspaceFunctions, DCRs, DCEs, LogicApps) to JSON files."
    )
    parser.add_argument("--tenant-id", help="Azure AD tenant ID (overrides env)")
    parser.add_argument("--client-id", help="App registration client ID (overrides env)")
    parser.add_argument("--client-secret", help="App registration client secret (overrides env)")
    parser.add_argument(
        "--use-managed-identity",
        action="store_true",
        help="Use Managed Identity (DefaultAzureCredential) instead of client credentials. "
             "When set, --tenant-id, --client-id and --client-secret are not required.",
    )
    parser.add_argument("--subscription-id", help="Azure subscription ID (overrides env)")
    parser.add_argument("--resource-group", help="Resource group name for Sentinel workspace (overrides env)")
    parser.add_argument("--workspace-name", help="Log Analytics workspace name (overrides env)")
    parser.add_argument("--logic-apps-resource-group", help="Resource group where Logic Apps are deployed (overrides env AZURE_LOGIC_APPS_RESOURCE_GROUP)")
    parser.add_argument("--dcr-resource-group", help="Resource group where DCRs are deployed (overrides env AZURE_DCR_RESOURCE_GROUP)")
    parser.add_argument("--dce-resource-group", help="Resource group where DCEs are deployed (overrides env AZURE_DCE_RESOURCE_GROUP)")
    parser.add_argument("--workbooks-resource-group", help="Resource group where Workbooks are deployed (overrides env AZURE_WORKBOOKS_RESOURCE_GROUP)")
    parser.add_argument(
        "--output-dir",
        default="output",
        help="Root directory for extracted files (default: ./output)",
    )
    parser.add_argument(
        "--filename-uid",
        action="store_true",
        help=(
            "Force saved JSON filenames to use a truncated display name plus a stable UID suffix. "
            "Useful on Windows when resource names are too long for filenames."
        ),
    )
    parser.add_argument(
        "--skip-alert-rules",
        action="store_true",
        help="Skip extraction of alert rules",
    )
    parser.add_argument(
        "--skip-automation-rules",
        action="store_true",
        help="Skip extraction of automation rules",
    )
    parser.add_argument(
        "--skip-summary-rules",
        action="store_true",
        help="Skip extraction of summary rules",
    )
    parser.add_argument(
        "--skip-hunting",
        action="store_true",
        help="Skip extraction of hunting",
    )
    parser.add_argument(
        "--skip-workspace-functions",
        action="store_true",
        help="Skip extraction of workspace functions (parsers)",
    )
    parser.add_argument(
        "--skip-saved-queries",
        action="store_true",
        help="Skip extraction of saved queries",
    )
    parser.add_argument(
        "--skip-dcr",
        action="store_true",
        help="Skip extraction of Data Collection Rules",
    )
    parser.add_argument(
        "--skip-dce",
        action="store_true",
        help="Skip extraction of Data Collection Endpoints",
    )
    parser.add_argument(
        "--skip-workbooks",
        action="store_true",
        help="Skip extraction of Workbooks",
    )
    parser.add_argument(
        "--skip-logic-apps",
        action="store_true",
        help="Skip extraction of Logic Apps",
    )
    parser.add_argument(
        "--skip-watchlists",
        action="store_true",
        help="Skip extraction of Watchlists",
    )
    parser.add_argument(
        "--skip-existing-watchlists",
        action="store_true",
        help=(
            "Resume mode for watchlists ONLY: skip any watchlist whose JSON file "
            "already exists in the output folder. Prefer --resume to apply this to "
            "all categories."
        ),
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help=(
            "Resume mode: skip any resource whose JSON file already exists on disk "
            "AND is valid JSON. Broken/partial files are detected (missing, empty, or "
            "unparseable) and re-fetched so the backup is always complete. Applies to "
            "all categories."
        ),
    )
    parser.add_argument(
        "--skip-custom-tables",
        action="store_true",
        help="Skip extraction of custom tables",
    )
    parser.add_argument(
        "--skip-table-retention",
        action="store_true",
        help="Skip extraction of table retention settings",
    )
    parser.add_argument(
        "--skip-content-packages",
        action="store_true",
        help="Skip extraction of content packages (solutions)",
    )
    parser.add_argument(
        "--skip-data-connectors",
        action="store_true",
        help="Skip extraction of data connectors",
    )
    parser.add_argument(
        "--skip-product-settings",
        action="store_true",
        help="Skip extraction of product settings",
    )
    parser.add_argument(
        "--skip-iam",
        action="store_true",
        help="Skip extraction of IAM role assignments",
    )
    parser.add_argument(
        "--skip-threat-intelligence",
        action="store_true",
        help="Skip extraction of threat intelligence indicators",
    )
    parser.add_argument(
        "--skip-ml-analytics",
        action="store_true",
        help="Skip extraction of Security ML Analytics Settings",
    )
    parser.add_argument("--only-alert-rules", action="store_true", help="Extract only alert rules")
    parser.add_argument("--only-automation-rules", action="store_true", help="Extract only automation rules")
    parser.add_argument("--only-summary-rules", action="store_true", help="Extract only summary rules")
    parser.add_argument("--only-hunting", action="store_true", help="Extract only hunting")
    parser.add_argument("--only-workspace-functions", action="store_true", help="Extract only workspace functions (parsers)")
    parser.add_argument("--only-saved-queries", action="store_true", help="Extract only saved queries")
    parser.add_argument("--only-dcr", action="store_true", help="Extract only Data Collection Rules")
    parser.add_argument("--only-dce", action="store_true", help="Extract only Data Collection Endpoints")
    parser.add_argument("--only-workbooks", action="store_true", help="Extract only Workbooks")
    parser.add_argument("--only-logic-apps", action="store_true", help="Extract only Logic Apps")
    parser.add_argument("--only-watchlists", action="store_true", help="Extract only Watchlists")
    parser.add_argument("--only-custom-tables", action="store_true", help="Extract only custom tables")
    parser.add_argument("--only-table-retention", action="store_true", help="Extract only table retention settings")
    parser.add_argument("--only-content-packages", action="store_true", help="Extract only content packages (solutions)")
    parser.add_argument("--only-data-connectors", action="store_true", help="Extract only data connectors")
    parser.add_argument("--only-product-settings", action="store_true", help="Extract only product settings")
    parser.add_argument("--only-iam", action="store_true", help="Extract only IAM role assignments")
    parser.add_argument("--only-threat-intelligence", action="store_true", help="Extract only threat intelligence indicators")
    parser.add_argument("--only-ml-analytics", action="store_true", help="Extract only Security ML Analytics Settings")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser.parse_args()


def resolve_config(args: argparse.Namespace) -> dict:
    """Merge CLI args and environment variables; CLI takes precedence."""
    load_dotenv()

    use_managed_identity = args.use_managed_identity or os.getenv("USE_MANAGED_IDENTITY", "").lower() in ("1", "true", "yes")

    def get(arg_val, env_key, label):
        value = arg_val or os.getenv(env_key, "")
        if not value:
            raise ValueError(
                f"Required value '{label}' is missing. "
                f"Set it via CLI argument or the {env_key} environment variable."
            )
        return value

    def get_optional(arg_val, env_key):
        return arg_val or os.getenv(env_key, "")

    cfg = {
        "use_managed_identity": use_managed_identity,
        "subscription_id": get(args.subscription_id, "AZURE_SUBSCRIPTION_ID", "subscription-id"),
        "resource_group": get(args.resource_group, "AZURE_RESOURCE_GROUP", "resource-group"),
        "workspace_name": get(args.workspace_name, "AZURE_WORKSPACE_NAME", "workspace-name"),
        # Optional — if absent, the respective extraction is skipped
        "logic_apps_resource_group": (
            args.logic_apps_resource_group
            or os.getenv("AZURE_LOGIC_APPS_RESOURCE_GROUP", "")
        ),
        "dcr_resource_group": (
            args.dcr_resource_group
            or os.getenv("AZURE_DCR_RESOURCE_GROUP", "")
        ),
        "dce_resource_group": (
            args.dce_resource_group
            or os.getenv("AZURE_DCE_RESOURCE_GROUP", "")
        ),
        "workbooks_resource_group": (
            args.workbooks_resource_group
            or os.getenv("AZURE_WORKBOOKS_RESOURCE_GROUP", "")
            # Default to the workspace resource group — Sentinel workbooks are
            # almost always stored in the same RG as the workspace.
            or os.getenv("AZURE_RESOURCE_GROUP", "")
        ),
    }

    if not use_managed_identity:
        cfg["tenant_id"] = get(args.tenant_id, "AZURE_TENANT_ID", "tenant-id")
        cfg["client_id"] = get(args.client_id, "AZURE_CLIENT_ID", "client-id")
        cfg["client_secret"] = get(args.client_secret, "AZURE_CLIENT_SECRET", "client-secret")

    return cfg


def run_extraction(cfg_overrides: dict | None = None) -> dict:
    """Programmatic entry point for the extractor (used by Function App).

    Parameters
    ----------
    cfg_overrides : dict, optional
        Configuration dict with keys matching resolve_config output.
        If provided, skips CLI argument parsing and .env loading.

    Returns
    -------
    dict with keys 'total_saved' (int) and 'summary' (dict[str, str]).
    """
    if cfg_overrides is not None:
        cfg = cfg_overrides
        args_skip = {}  # no skip flags by default
        args_only = {}  # no only flags by default
        output_dir = cfg.get("output_dir", "output")
        debug = cfg.get("debug", False)
        filename_uid = cfg.get("filename_uid", False)
    else:
        args = parse_args()
        debug = args.debug
        output_dir = args.output_dir
        filename_uid = args.filename_uid
        try:
            cfg = resolve_config(args)
        except ValueError as exc:
            log.error("%s", exc)
            raise
        args_skip = {
            "skip_alert_rules": args.skip_alert_rules,
            "skip_automation_rules": args.skip_automation_rules,
            "skip_summary_rules": args.skip_summary_rules,
            "skip_hunting": args.skip_hunting,
            "skip_workspace_functions": args.skip_workspace_functions,
            "skip_saved_queries": args.skip_saved_queries,
            "skip_dcr": args.skip_dcr,
            "skip_dce": args.skip_dce,
            "skip_workbooks": args.skip_workbooks,
            "skip_logic_apps": args.skip_logic_apps,
            "skip_watchlists": args.skip_watchlists,
            "skip_custom_tables": args.skip_custom_tables,
            "skip_table_retention": args.skip_table_retention,
            "skip_content_packages": args.skip_content_packages,
            "skip_data_connectors": args.skip_data_connectors,
            "skip_product_settings": args.skip_product_settings,
            "skip_iam": args.skip_iam,
            "skip_threat_intelligence": args.skip_threat_intelligence,
            "skip_ml_analytics": args.skip_ml_analytics,
        }
        args_only = {
            "only_alert_rules": args.only_alert_rules,
            "only_automation_rules": args.only_automation_rules,
            "only_summary_rules": args.only_summary_rules,
            "only_hunting": args.only_hunting,
            "only_workspace_functions": args.only_workspace_functions,
            "only_saved_queries": args.only_saved_queries,
            "only_dcr": args.only_dcr,
            "only_dce": args.only_dce,
            "only_workbooks": args.only_workbooks,
            "only_logic_apps": args.only_logic_apps,
            "only_watchlists": args.only_watchlists,
            "only_custom_tables": args.only_custom_tables,
            "only_table_retention": args.only_table_retention,
            "only_content_packages": args.only_content_packages,
            "only_data_connectors": args.only_data_connectors,
            "only_product_settings": args.only_product_settings,
            "only_iam": args.only_iam,
            "only_threat_intelligence": args.only_threat_intelligence,
            "only_ml_analytics": args.only_ml_analytics,
        }
        # Resume / fast-rerun flags
        cfg["skip_existing_watchlists"] = args.skip_existing_watchlists
        cfg["resume"] = args.resume

    if debug:
        logging.getLogger().setLevel(logging.DEBUG)

    # Build base URLs
    workspace_base = WORKSPACE_BASE.format(
        base=MANAGEMENT_BASE,
        subscription_id=cfg["subscription_id"],
        resource_group=cfg["resource_group"],
        workspace_name=cfg["workspace_name"],
    )
    sentinel_base = workspace_base + "/providers/Microsoft.SecurityInsights"

    output_root = (
        Path(output_dir)
        / cfg["subscription_id"]
        / cfg["workspace_name"]
    ).resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    log.info("Output directory: %s", output_root)

    # Set up run log file
    logs_dir = output_root / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    run_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = logs_dir / f"run_{run_timestamp}.log"
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    )
    logging.getLogger().addHandler(file_handler)
    log.info("Run log: %s", log_file)

    # Load file tracker for change detection
    load_tracker(output_root)
    set_filename_uid_mode(filename_uid)
    set_resume_mode(bool(cfg.get("resume")))
    if cfg.get("resume"):
        log.info("Resume mode enabled: existing valid JSON files will be skipped; broken/partial files will be re-fetched.")
    if filename_uid:
        log.info("Filename UID mode enabled.")

    # Authenticate via TokenManager (supports managed identity or client creds)
    try:
        token_mgr = TokenManager(
            tenant_id=cfg.get("tenant_id"),
            client_id=cfg.get("client_id"),
            client_secret=cfg.get("client_secret"),
            use_managed_identity=cfg.get("use_managed_identity", False),
        )
        headers = {"Content-Type": "application/json"}
        token_mgr.refresh_headers(headers)
    except (requests.HTTPError, ImportError) as exc:
        log.error("Authentication failed: %s", exc)
        raise

    only_targets = [
        "alert_rules",
        "automation_rules",
        "summary_rules",
        "hunting",
        "workspace_functions",
        "saved_queries",
        "dcr",
        "dce",
        "workbooks",
        "logic_apps",
        "watchlists",
        "custom_tables",
        "table_retention",
        "content_packages",
        "data_connectors",
        "product_settings",
        "iam",
        "threat_intelligence",
        "ml_analytics",
    ]
    selected_only = {
        name for name in only_targets
        if args_only.get(f"only_{name}", False) or cfg.get(f"only_{name}", False)
    }
    if selected_only:
        log.info("Only mode enabled for: %s", ", ".join(sorted(selected_only)))

    def _should_skip(flag_name: str) -> bool:
        target = flag_name[5:] if flag_name.startswith("skip_") else flag_name
        if selected_only and target not in selected_only:
            return True
        return args_skip.get(flag_name, False) or cfg.get(flag_name, False)

    total_saved = 0
    summary: dict[str, str] = {}

    return _run_all_extractions(
        cfg, sentinel_base, workspace_base, headers, output_root, _should_skip, total_saved, summary, token_mgr
    )


def _run_all_extractions(
    cfg, sentinel_base, workspace_base, headers, output_root, should_skip, total_saved, summary, token_mgr
) -> dict:
    """Execute all extraction steps. Returns dict with total_saved and summary."""

    if not should_skip("skip_alert_rules"):
        try:
            token_mgr.refresh_headers(headers)
            saved = extract_alert_rules(sentinel_base, headers, output_root)
            total_saved += saved
            summary["Alert Rules"] = str(saved)
            log.info("Alert rules extracted: %d", saved)
        except requests.HTTPError as exc:
            summary["Alert Rules"] = "FAILED"
            log.error("Failed to extract alert rules: %s", exc)
    else:
        summary["Alert Rules"] = "Skipped"

    if not should_skip("skip_automation_rules"):
        try:
            token_mgr.refresh_headers(headers)
            saved = extract_automation_rules(sentinel_base, headers, output_root)
            total_saved += saved
            summary["Automation Rules"] = str(saved)
            log.info("Automation rules extracted: %d", saved)
        except requests.HTTPError as exc:
            summary["Automation Rules"] = "FAILED"
            log.error("Failed to extract automation rules: %s", exc)
    else:
        summary["Automation Rules"] = "Skipped"

    if not should_skip("skip_summary_rules"):
        try:
            token_mgr.refresh_headers(headers)
            saved = extract_summary_rules(workspace_base, headers, output_root)
            total_saved += saved
            summary["Summary Rules"] = str(saved)
            log.info("Summary rules extracted: %d", saved)
        except requests.HTTPError as exc:
            summary["Summary Rules"] = "FAILED"
            log.error("Failed to extract summary rules: %s", exc)
    else:
        summary["Summary Rules"] = "Skipped"

    if not should_skip("skip_hunting"):
        try:
            token_mgr.refresh_headers(headers)
            saved = extract_hunting(sentinel_base, workspace_base, headers, output_root)
            total_saved += saved
            summary["Hunting"] = str(saved)
            log.info("Hunts extracted: %d", saved)
        except requests.HTTPError as exc:
            summary["Hunting"] = "FAILED"
            log.error("Failed to extract hunts: %s", exc)
    else:
        summary["Hunting"] = "Skipped"

    if not should_skip("skip_workspace_functions"):
        try:
            token_mgr.refresh_headers(headers)
            saved = extract_workspace_functions(workspace_base, headers, output_root)
            total_saved += saved
            summary["Workspace Functions"] = str(saved)
            log.info("Workspace functions extracted: %d", saved)
        except requests.HTTPError as exc:
            summary["Workspace Functions"] = "FAILED"
            log.error("Failed to extract workspace functions: %s", exc)
    else:
        summary["Workspace Functions"] = "Skipped"

    if not should_skip("skip_saved_queries"):
        try:
            token_mgr.refresh_headers(headers)
            saved = extract_saved_queries(workspace_base, headers, output_root)
            total_saved += saved
            summary["Saved Queries"] = str(saved)
            log.info("Saved queries extracted: %d", saved)
        except requests.HTTPError as exc:
            summary["Saved Queries"] = "FAILED"
            log.error("Failed to extract saved queries: %s", exc)
    else:
        summary["Saved Queries"] = "Skipped"

    workspace_resource_id = (
        f"/subscriptions/{cfg['subscription_id']}"
        f"/resourceGroups/{cfg['resource_group']}"
        f"/providers/Microsoft.OperationalInsights/workspaces/{cfg['workspace_name']}"
    )

    if not should_skip("skip_dcr"):
        dcr_rg = cfg.get("dcr_resource_group", "")
        if dcr_rg:
            try:
                token_mgr.refresh_headers(headers)
                saved = extract_dcrs(
                    cfg["subscription_id"],
                    dcr_rg,
                    workspace_resource_id,
                    headers,
                    output_root,
                )
                total_saved += saved
                summary["Data Collection Rules"] = str(saved)
                log.info("DCRs extracted: %d", saved)
            except requests.HTTPError as exc:
                summary["Data Collection Rules"] = "FAILED"
                log.error("Failed to extract DCRs: %s", exc)
        else:
            summary["Data Collection Rules"] = "Skipped (no RG)"
            log.info(
                "Skipping DCRs — set --dcr-resource-group or AZURE_DCR_RESOURCE_GROUP to enable."
            )
    else:
        summary["Data Collection Rules"] = "Skipped"

    if not should_skip("skip_dce"):
        dce_rg = cfg.get("dce_resource_group", "")
        if dce_rg:
            try:
                token_mgr.refresh_headers(headers)
                saved = extract_dces(
                    cfg["subscription_id"],
                    dce_rg,
                    headers,
                    output_root,
                )
                total_saved += saved
                summary["Data Collection Endpoints"] = str(saved)
                log.info("DCEs extracted: %d", saved)
            except requests.HTTPError as exc:
                summary["Data Collection Endpoints"] = "FAILED"
                log.error("Failed to extract DCEs: %s", exc)
        else:
            summary["Data Collection Endpoints"] = "Skipped (no RG)"
            log.info(
                "Skipping DCEs — set --dce-resource-group or AZURE_DCE_RESOURCE_GROUP to enable."
            )
    else:
        summary["Data Collection Endpoints"] = "Skipped"

    if not should_skip("skip_workbooks"):
        wb_rg = cfg.get("workbooks_resource_group", "")
        if wb_rg:
            try:
                token_mgr.refresh_headers(headers)
                saved = extract_workbooks(
                    cfg["subscription_id"],
                    wb_rg,
                    workspace_resource_id,
                    headers,
                    output_root,
                )
                total_saved += saved
                summary["Workbooks"] = str(saved)
                log.info("Workbooks extracted: %d", saved)
            except requests.HTTPError as exc:
                summary["Workbooks"] = "FAILED"
                log.error("Failed to extract workbooks: %s", exc)
        else:
            summary["Workbooks"] = "Skipped (no RG)"
            log.info(
                "Skipping Workbooks — set --workbooks-resource-group or "
                "AZURE_WORKBOOKS_RESOURCE_GROUP to enable (defaults to AZURE_RESOURCE_GROUP)."
            )
    else:
        summary["Workbooks"] = "Skipped"

    if not should_skip("skip_logic_apps"):
        la_rg = cfg.get("logic_apps_resource_group", "")
        if la_rg:
            try:
                token_mgr.refresh_headers(headers)
                saved = extract_logic_apps(cfg["subscription_id"], la_rg, headers, output_root)
                total_saved += saved
                summary["Logic Apps"] = str(saved)
                log.info("Logic Apps extracted: %d", saved)
            except requests.HTTPError as exc:
                summary["Logic Apps"] = "FAILED"
                log.error("Failed to extract Logic Apps: %s", exc)
        else:
            summary["Logic Apps"] = "Skipped (no RG)"
            log.info(
                "Skipping Logic Apps — set --logic-apps-resource-group or "
                "AZURE_LOGIC_APPS_RESOURCE_GROUP to enable."
            )
    else:
        summary["Logic Apps"] = "Skipped"

    if not should_skip("skip_watchlists"):
        try:
            token_mgr.refresh_headers(headers)
            saved = extract_watchlists(
                sentinel_base,
                headers,
                output_root,
                token_mgr=token_mgr,
                skip_existing=bool(cfg.get("skip_existing_watchlists")),
            )
            total_saved += saved
            summary["Watchlists"] = str(saved)
            log.info("Watchlists extracted: %d", saved)
        except requests.HTTPError as exc:
            summary["Watchlists"] = "FAILED"
            log.error("Failed to extract watchlists: %s", exc)
    else:
        summary["Watchlists"] = "Skipped"

    if not should_skip("skip_custom_tables"):
        try:
            token_mgr.refresh_headers(headers)
            saved = extract_custom_tables(workspace_base, headers, output_root)
            total_saved += saved
            summary["Custom Tables"] = str(saved)
            log.info("Custom tables extracted: %d", saved)
        except requests.HTTPError as exc:
            summary["Custom Tables"] = "FAILED"
            log.error("Failed to extract custom tables: %s", exc)
    else:
        summary["Custom Tables"] = "Skipped"

    if not should_skip("skip_table_retention"):
        try:
            token_mgr.refresh_headers(headers)
            saved = extract_table_retention(workspace_base, headers, output_root)
            total_saved += saved
            summary["Table Retention"] = str(saved)
            log.info("Table retention settings extracted.")
        except requests.HTTPError as exc:
            summary["Table Retention"] = "FAILED"
            log.error("Failed to extract table retention settings: %s", exc)
    else:
        summary["Table Retention"] = "Skipped"

    if not should_skip("skip_content_packages"):
        try:
            token_mgr.refresh_headers(headers)
            saved = extract_content_packages(sentinel_base, headers, output_root)
            total_saved += saved
            summary["Content Packages"] = str(saved)
            log.info("Content packages extracted: %d", saved)
        except requests.HTTPError as exc:
            summary["Content Packages"] = "FAILED"
            log.error("Failed to extract content packages: %s", exc)
    else:
        summary["Content Packages"] = "Skipped"

    if not should_skip("skip_data_connectors"):
        try:
            token_mgr.refresh_headers(headers)
            saved = extract_data_connectors(sentinel_base, headers, output_root)
            total_saved += saved
            summary["Data Connectors"] = str(saved)
            log.info("Data connectors extracted: %d", saved)
        except requests.HTTPError as exc:
            summary["Data Connectors"] = "FAILED"
            log.error("Failed to extract data connectors: %s", exc)
    else:
        summary["Data Connectors"] = "Skipped"

    if not should_skip("skip_product_settings"):
        try:
            token_mgr.refresh_headers(headers)
            saved = extract_product_settings(sentinel_base, headers, output_root)
            total_saved += saved
            summary["Product Settings"] = str(saved)
            log.info("Product settings extracted: %d", saved)
        except requests.HTTPError as exc:
            summary["Product Settings"] = "FAILED"
            log.error("Failed to extract product settings: %s", exc)
    else:
        summary["Product Settings"] = "Skipped"

    if not should_skip("skip_iam"):
        try:
            token_mgr.refresh_headers(headers)
            saved = extract_iam_role_assignments(
                cfg["subscription_id"],
                cfg["resource_group"],
                headers,
                output_root,
            )
            total_saved += saved
            summary["IAM Role Assignments"] = str(saved)
            log.info("IAM role assignments extracted: %d", saved)
        except requests.HTTPError as exc:
            summary["IAM Role Assignments"] = "FAILED"
            log.error("Failed to extract IAM role assignments: %s", exc)
    else:
        summary["IAM Role Assignments"] = "Skipped"

    if not should_skip("skip_threat_intelligence"):
        try:
            saved = extract_threat_intelligence(sentinel_base, headers, output_root)
            total_saved += saved
            summary["Threat Intelligence"] = str(saved)
            log.info("Threat intelligence indicators extracted: %d", saved)
        except requests.HTTPError as exc:
            summary["Threat Intelligence"] = "FAILED"
            log.error("Failed to extract threat intelligence indicators: %s", exc)
    else:
        summary["Threat Intelligence"] = "Skipped"

    if not should_skip("skip_ml_analytics"):
        try:
            saved = extract_ml_analytics_settings(sentinel_base, headers, output_root)
            total_saved += saved
            summary["ML Analytics Settings"] = str(saved)
            log.info("ML Analytics settings extracted: %d", saved)
        except requests.HTTPError as exc:
            summary["ML Analytics Settings"] = "FAILED"
            log.error("Failed to extract ML Analytics settings: %s", exc)
    else:
        summary["ML Analytics Settings"] = "Skipped"

    # Persist file tracker
    persist_tracker()

    # --- Export Summary ---
    if summary:
        cat_width = max(len(c) for c in summary) + 2
        border = "+" + "-" * (cat_width + 2) + "+" + "-" * 16 + "+"
        print("\n" + border)
        print(f"| {'Category':<{cat_width}} | {'Result':>14} |")
        print(border)
        for category, result in summary.items():
            print(f"| {category:<{cat_width}} | {result:>14} |")
        print(border)
        print(f"| {'TOTAL FILES SAVED':<{cat_width}} | {total_saved:>14} |")
        print(border)
        print(f"Output directory: {output_root}\n")

    if total_saved > 0:
        log.info("Total changes this run: %d file(s) saved/updated.", total_saved)
    else:
        log.info("No changes detected — all content is up to date.")

    return {"total_saved": total_saved, "summary": summary}


def main() -> None:
    try:
        run_extraction()
    except (ValueError, ImportError, requests.HTTPError) as exc:
        log.error("%s", exc)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
