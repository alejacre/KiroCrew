"""Imported browser cookies, stored as a Playwright ``storageState`` and applied
to the agent's ``playwright-cli`` sessions.

The dashboard user exports cookies from the browser where they are already
logged in and imports them here; the gateway normalises them to Playwright's
cookie shape, writes one owner-only ``storageState`` file under the data home,
and :mod:`kiro_crew.browser_cli.launch` names that file in the launch config so
every NEW ``playwright-cli`` session starts with the cookies loaded. This is the
remote-gateway path a hand-written ``PLAYWRIGHT_MCP_CONFIG`` otherwise has to
carry by hand.

**Three import shapes are accepted**, because that is what the browsers and
their export extensions actually produce:

1. A Playwright ``storageState`` object (``{"cookies": [...], "origins": [...]}``)
   -- what ``playwright-cli state-save`` writes, so a round-trip is lossless.
2. A bare JSON array of cookie objects -- the Cookie-Editor / EditThisCookie /
   "Get cookies.txt" extension export. Field names differ from Playwright's
   (``expirationDate`` for the expiry, a wider ``sameSite`` vocabulary), so they
   are normalised.
3. Netscape ``cookies.txt`` -- the tab-separated format ``curl``/``wget`` and
   the "Get cookies.txt" extension emit, including the ``#HttpOnly_`` domain
   prefix convention.

Every cookie is normalised to the Playwright shape: ``name``, ``value``,
``domain``, ``path``, ``expires`` (a float, or ``-1`` for a session cookie),
``httpOnly``, ``secure``, ``sameSite`` in ``{"Strict", "Lax", "None"}``. Already
expired cookies are dropped. Every failure raises :class:`CookieImportError`
with a message meant to be shown to the user.

**Values never leave.** :func:`storage_state_summary` reports counts, domains
and the earliest expiry, and nothing here ever returns or logs a cookie value.
The agent is told (see ``docs/browser-control.md``) that imported cookies apply
to new sessions on their own and that it must never read the storage-state file.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

from kiro_crew.atomic_write import atomic_write
from kiro_crew.browser_cli.install import cli_command, cli_env
from kiro_crew.browser_cli.launch import _SESSION_PREFIX
from kiro_crew.config.paths import config_dir

logger = logging.getLogger(__name__)

#: The storageState file playwright-cli loads. Fixed name under the data home so
#: an isolated ``KIROCREW_HOME`` (a pod, a test) stays isolated here too.
STORAGE_STATE_FILE = "browser-storage-state.json"

#: Reject an import whose raw text exceeds this, before parsing: the same 2 MiB
#: ceiling the HTTP handler enforces, restated here so a non-HTTP caller
#: (a test, a future CLI path) gets the same bound.
MAX_IMPORT_BYTES = 2 * 1024 * 1024

#: Reject an import carrying more than this many cookies. A logged-in browser
#: profile has a few hundred; five thousand is far past any legitimate export
#: and bounds the work of writing and re-loading the state.
MAX_COOKIES = 5000

#: How long a ``state-load`` on one live session is allowed to take.
_HOT_LOAD_TIMEOUT_S = 15.0

#: Playwright's three accepted ``sameSite`` values.
_SAME_SITE_VALUES = frozenset({"Strict", "Lax", "None"})

#: Maps the wider extension/browser ``sameSite`` vocabulary onto Playwright's
#: three. Anything absent or unrecognised falls back to ``Lax`` (see
#: :func:`_normalize_same_site`), which is the browser default for an unspecified
#: attribute.
_SAME_SITE_ALIASES = {
    "strict": "Strict",
    "lax": "Lax",
    "none": "None",
    "no_restriction": "None",
    "unspecified": "Lax",
}


class CookieImportError(ValueError):
    """A cookie import that cannot be accepted, with a user-readable message."""


def storage_state_path() -> Path:
    """Where the imported storageState lives, under the data home."""
    return config_dir() / STORAGE_STATE_FILE


def _normalize_same_site(raw: Any) -> str:
    """Normalise any browser/extension ``sameSite`` spelling to Playwright's set.

    Playwright accepts only ``Strict``/``Lax``/``None``; the extensions emit
    ``strict``/``lax``/``none``/``no_restriction``/``unspecified`` as well as the
    capitalised forms. An absent or unrecognised value becomes ``Lax`` -- the
    browser default for a cookie with no ``SameSite`` attribute.
    """
    if isinstance(raw, str):
        if raw in _SAME_SITE_VALUES:
            return raw
        mapped = _SAME_SITE_ALIASES.get(raw.strip().lower())
        if mapped is not None:
            return mapped
    return "Lax"


def _normalize_expires(raw: Any) -> float:
    """Normalise an expiry to a float unix timestamp, or ``-1`` for a session cookie.

    Playwright uses ``-1`` for "expires at end of session". A missing, null,
    non-numeric, or non-positive expiry is treated as a session cookie: an
    export that omits the field is common, and Netscape ``cookies.txt`` writes a
    literal ``0`` for a session cookie. A positive value is kept verbatim (an
    already-past one is dropped by the caller against the current time).
    """
    if isinstance(raw, bool) or raw is None:
        return -1.0
    parsed: float | None = None
    if isinstance(raw, (int, float)):
        parsed = float(raw)
    elif isinstance(raw, str):
        try:
            parsed = float(raw)
        except ValueError:
            parsed = None
    if parsed is None or parsed <= 0:
        return -1.0
    return parsed


def _normalize_cookie(raw: Any) -> dict[str, Any]:
    """Normalise one extension/browser cookie object to the Playwright shape.

    Raises :class:`CookieImportError` when a required field is missing: a cookie
    with no ``name`` or no ``domain`` cannot be applied to a session and silently
    dropping it would hide a broken export. Expiry-based dropping is the caller's
    job (:func:`parse_cookie_import`), which knows the current time.
    """
    if not isinstance(raw, dict):
        raise CookieImportError("each cookie must be a JSON object")
    name = raw.get("name")
    domain = raw.get("domain")
    if not isinstance(name, str) or not name:
        raise CookieImportError("a cookie is missing its name")
    if not isinstance(domain, str) or not domain:
        raise CookieImportError(f"cookie {name!r} is missing its domain")
    value = raw.get("value")
    # ``expirationDate`` is the extension spelling; ``expires`` is Playwright's.
    expires = _normalize_expires(
        raw["expirationDate"] if "expirationDate" in raw else raw.get("expires")
    )
    path = raw.get("path")
    return {
        "name": name,
        "value": value if isinstance(value, str) else "",
        "domain": domain,
        "path": path if isinstance(path, str) and path else "/",
        "expires": expires,
        "httpOnly": bool(raw.get("httpOnly", False)),
        "secure": bool(raw.get("secure", False)),
        "sameSite": _normalize_same_site(raw.get("sameSite")),
    }


def _parse_netscape(text: str) -> list[dict[str, Any]]:
    """Parse a Netscape ``cookies.txt`` body into raw cookie dicts.

    Tab-separated, seven columns: ``domain  includeSubdomains  path  secure
    expires  name  value``. Lines beginning ``#`` are comments, except the
    ``#HttpOnly_`` prefix convention which marks the cookie httpOnly and carries
    the real domain after the prefix. A line with too few columns is skipped
    rather than failing the whole import.
    """
    cookies: list[dict[str, Any]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        http_only = False
        if stripped.startswith("#HttpOnly_"):
            http_only = True
            stripped = stripped[len("#HttpOnly_") :]
        elif stripped.startswith("#"):
            continue
        parts = stripped.split("\t")
        if len(parts) < 7:
            continue
        domain, _sub, path, secure, expires, name, value = parts[:7]
        cookies.append(
            {
                "domain": domain,
                "path": path,
                "secure": secure.strip().upper() == "TRUE",
                "expires": expires,
                "name": name,
                "value": value,
                "httpOnly": http_only,
            }
        )
    return cookies


def parse_cookie_import(text: str) -> list[dict[str, Any]]:
    """Parse and normalise an import in any accepted shape into Playwright cookies.

    Accepts a Playwright ``storageState`` object, a bare JSON array of cookie
    objects, or a Netscape ``cookies.txt`` body. Normalises every cookie to the
    Playwright shape, drops already-expired cookies, and enforces the size and
    count limits. Raises :class:`CookieImportError` with a user-readable message
    on any rejection.
    """
    if not isinstance(text, str):
        raise CookieImportError("cookie import must be text")
    if len(text.encode("utf-8", "surrogatepass")) > MAX_IMPORT_BYTES:
        raise CookieImportError("cookie import is too large (limit 2 MiB)")
    if not text.strip():
        raise CookieImportError("cookie import is empty")

    raw_cookies: list[Any]
    stripped = text.lstrip()
    if stripped[:1] in "{[":
        try:
            parsed = json.loads(text)
        except ValueError as exc:
            raise CookieImportError(f"cookie import is not valid JSON: {exc}") from exc
        if isinstance(parsed, dict):
            # A Playwright storageState object.
            candidate = parsed.get("cookies")
            if not isinstance(candidate, list):
                raise CookieImportError('storageState JSON must carry a "cookies" array')
            raw_cookies = candidate
        elif isinstance(parsed, list):
            raw_cookies = parsed
        else:
            raise CookieImportError(
                "cookie import JSON must be a storageState object or an array of cookies"
            )
    else:
        raw_cookies = _parse_netscape(text)
        if not raw_cookies:
            raise CookieImportError(
                "cookie import is neither JSON nor a recognisable cookies.txt file"
            )

    if len(raw_cookies) > MAX_COOKIES:
        raise CookieImportError(f"too many cookies (limit {MAX_COOKIES})")

    now = time.time()
    cookies: list[dict[str, Any]] = []
    for raw in raw_cookies:
        cookie = _normalize_cookie(raw)
        # Drop an already-expired cookie: a positive expiry in the past can
        # never authenticate a session, and loading it only clutters the state.
        if cookie["expires"] > 0 and cookie["expires"] < now:
            continue
        cookies.append(cookie)

    if not cookies:
        raise CookieImportError("no unexpired cookies to import")
    return cookies


def save_storage_state(cookies: list[dict[str, Any]]) -> Path:
    """Write *cookies* as a Playwright storageState file, owner-only, and return its path.

    Atomic (temp file + rename) and locked down to the owner: the file carries
    live session cookies, so it is written ``0o600`` on POSIX and with an
    owner-only DACL on Windows via :func:`atomic_write`'s ``restrict_to_owner``
    (a raw ``mode=0o600`` is a no-op on Windows).
    """
    path = storage_state_path()
    payload = json.dumps({"cookies": cookies, "origins": []}, indent=2) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write(path, payload, mode=0o600, restrict_to_owner=True)
    return path


def clear_storage_state() -> bool:
    """Delete the storageState file. Returns True if a file was removed."""
    path = storage_state_path()
    try:
        path.unlink()
        return True
    except FileNotFoundError:
        return False


def storage_state_summary() -> dict[str, Any] | None:
    """Summarise the stored cookies without ever returning a value.

    ``None`` when no storageState file is present or it cannot be read. The
    summary carries the cookie count, the distinct domains (leading dot
    stripped, sorted), the earliest positive expiry (or ``None`` if every cookie
    is a session cookie), and the file's modification time as ``imported_at``.
    NEVER a cookie value.
    """
    path = storage_state_path()
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        data = json.loads(raw)
    except ValueError:
        return None
    cookies = data.get("cookies") if isinstance(data, dict) else None
    if not isinstance(cookies, list):
        return None

    domains: set[str] = set()
    earliest_expiry: float | None = None
    for cookie in cookies:
        if not isinstance(cookie, dict):
            continue
        domain = cookie.get("domain")
        if isinstance(domain, str) and domain:
            domains.add(domain[1:] if domain.startswith(".") else domain)
        expires = cookie.get("expires")
        if isinstance(expires, (int, float)) and not isinstance(expires, bool) and expires > 0:
            if earliest_expiry is None or expires < earliest_expiry:
                earliest_expiry = float(expires)

    try:
        imported_at = path.stat().st_mtime
    except OSError:
        imported_at = time.time()

    return {
        "cookie_count": len(cookies),
        "domains": sorted(domains),
        "earliest_expiry": earliest_expiry,
        "imported_at": imported_at,
    }


def _live_session_names() -> list[str]:
    """Best-effort list of the live ``kc-*`` playwright-cli sessions.

    Runs ``playwright-cli list`` and returns the names beginning with the
    Kiro-Crew session prefix. Never raises: an empty list means "could not
    enumerate", which the caller reports rather than treating as an error. The
    output format is a line per session with the name as its first
    whitespace-separated token; a name is only accepted when it carries the
    reserved prefix, so a header or a stray line is ignored.
    """
    command = cli_command()
    if command is None:
        return []
    import subprocess  # noqa: PLC0415 - kept local so import-time never spawns

    try:
        proc = subprocess.run(
            [*command, "list"],
            capture_output=True,
            timeout=_HOT_LOAD_TIMEOUT_S,
            env=cli_env(),
            encoding="utf-8",
            errors="replace",
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if proc.returncode != 0:
        return []
    names: list[str] = []
    for line in (proc.stdout or "").splitlines():
        token = line.strip().split()[:1]
        if token and token[0].startswith(_SESSION_PREFIX):
            names.append(token[0])
    return names


def hot_load_into_live_sessions(path: Path) -> dict[str, Any]:
    """Load *path* into every live ``kc-*`` session, best effort.

    Runs ``playwright-cli -s=<name> state-load <path>`` for each enumerated
    session, so a browser already open picks up the freshly imported cookies
    without an agent restart. NEVER raises. Returns ``{"loaded": [names],
    "failed": {name: reason}}``; when the CLI is unavailable or no session could
    be enumerated it returns ``{"loaded": [], "failed": {}, "note": "..."}``
    explaining why. New sessions get the cookies from the launch config
    regardless, so an empty result is a "nothing to hot-load into", not a
    failure to import.
    """
    command = cli_command()
    if command is None:
        return {"loaded": [], "failed": {}, "note": "playwright-cli is not installed"}
    sessions = _live_session_names()
    if not sessions:
        return {
            "loaded": [],
            "failed": {},
            "note": "no live browser sessions; cookies apply to new sessions automatically",
        }
    import subprocess  # noqa: PLC0415 - kept local so import-time never spawns

    loaded: list[str] = []
    failed: dict[str, str] = {}
    env = cli_env()
    for name in sessions:
        try:
            proc = subprocess.run(
                [*command, f"-s={name}", "state-load", str(path)],
                capture_output=True,
                timeout=_HOT_LOAD_TIMEOUT_S,
                env=env,
                encoding="utf-8",
                errors="replace",
            )
        except (OSError, subprocess.SubprocessError) as exc:
            failed[name] = str(exc)
            continue
        if proc.returncode == 0:
            loaded.append(name)
        else:
            failed[name] = (proc.stderr or "state-load failed").strip()[:200]
    return {"loaded": loaded, "failed": failed}
