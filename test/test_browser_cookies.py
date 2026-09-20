"""Backend tests for the imported-cookies feature.

Covers the three parser shapes and their normalisation, expiry dropping and the
size/count limits, the owner-only 0600 storageState write, the conditional
``storageState`` key in the launch config, the value-free summary, the
best-effort hot-load's failure handling, and the three HTTP handlers (status,
import, clear) through the aiohttp client fixture including the non-owner 403 and
the restricted-session 403.

No real ``playwright-cli`` is ever spawned: ``cli_command``/``cli_env`` and
``subprocess.run`` are faked at the module boundary.
"""

from __future__ import annotations

import json
import os
import stat
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
from dashboard_owner_helpers import as_owner

from kiro_crew.browser_cli import cookies as mod
from kiro_crew.browser_cli import launch as launch_mod
from kiro_crew.platform_compat import IS_WINDOWS


@pytest.fixture()
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    h = tmp_path / "home"
    monkeypatch.setenv("KIROCREW_HOME", str(h))
    return h


# ── parse_cookie_import: the three shapes ──


class TestParseShapes:
    def test_playwright_storage_state(self, home: Path) -> None:
        text = json.dumps(
            {
                "cookies": [{"name": "sid", "value": "v", "domain": "example.com", "path": "/"}],
                "origins": [],
            }
        )
        cookies = mod.parse_cookie_import(text)
        assert len(cookies) == 1
        assert cookies[0]["name"] == "sid"
        assert cookies[0]["domain"] == "example.com"

    def test_bare_json_array_extension_export(self, home: Path) -> None:
        text = json.dumps(
            [
                {
                    "name": "auth",
                    "value": "tok",
                    "domain": ".example.com",
                    "path": "/app",
                    "expirationDate": 9999999999,
                    "sameSite": "no_restriction",
                    "secure": True,
                    "httpOnly": True,
                }
            ]
        )
        cookies = mod.parse_cookie_import(text)
        assert cookies[0]["expires"] == 9999999999.0
        assert cookies[0]["sameSite"] == "None"
        assert cookies[0]["secure"] is True
        assert cookies[0]["httpOnly"] is True

    def test_netscape_cookies_txt(self, home: Path) -> None:
        text = (
            "# Netscape HTTP Cookie File\n"
            "#HttpOnly_.example.com\tTRUE\t/\tTRUE\t9999999999\tsid\tsecret\n"
            "example.org\tFALSE\t/\tFALSE\t0\tplain\tv\n"
        )
        cookies = mod.parse_cookie_import(text)
        assert len(cookies) == 2
        http_only = next(c for c in cookies if c["name"] == "sid")
        assert http_only["httpOnly"] is True
        assert http_only["secure"] is True
        assert http_only["domain"] == ".example.com"
        plain = next(c for c in cookies if c["name"] == "plain")
        # `0` expiry means a session cookie -> normalised to -1.
        assert plain["expires"] == -1.0


class TestNormalisation:
    @pytest.mark.parametrize(
        "raw, expected",
        [
            ("Strict", "Strict"),
            ("lax", "Lax"),
            ("no_restriction", "None"),
            ("none", "None"),
            ("unspecified", "Lax"),
            ("garbage", "Lax"),
            (None, "Lax"),
        ],
    )
    def test_same_site(self, home: Path, raw: object, expected: str) -> None:
        text = json.dumps([{"name": "n", "domain": "d.com", "sameSite": raw}])
        assert mod.parse_cookie_import(text)[0]["sameSite"] == expected

    def test_missing_expiry_is_session_cookie(self, home: Path) -> None:
        text = json.dumps([{"name": "n", "domain": "d.com"}])
        assert mod.parse_cookie_import(text)[0]["expires"] == -1.0

    def test_expired_cookie_dropped(self, home: Path) -> None:
        past = time.time() - 3600
        text = json.dumps(
            [
                {"name": "old", "domain": "d.com", "expirationDate": past},
                {"name": "live", "domain": "d.com"},
            ]
        )
        cookies = mod.parse_cookie_import(text)
        assert [c["name"] for c in cookies] == ["live"]


class TestLimits:
    def test_over_size_limit_rejected(self, home: Path) -> None:
        big = "x" * (mod.MAX_IMPORT_BYTES + 1)
        with pytest.raises(mod.CookieImportError, match="too large"):
            mod.parse_cookie_import(big)

    def test_over_cookie_count_rejected(self, home: Path) -> None:
        many = [{"name": f"n{i}", "domain": "d.com"} for i in range(mod.MAX_COOKIES + 1)]
        with pytest.raises(mod.CookieImportError, match="too many"):
            mod.parse_cookie_import(json.dumps(many))

    def test_missing_name_rejected(self, home: Path) -> None:
        with pytest.raises(mod.CookieImportError, match="name"):
            mod.parse_cookie_import(json.dumps([{"domain": "d.com"}]))

    def test_missing_domain_rejected(self, home: Path) -> None:
        with pytest.raises(mod.CookieImportError, match="domain"):
            mod.parse_cookie_import(json.dumps([{"name": "n"}]))

    def test_empty_rejected(self, home: Path) -> None:
        with pytest.raises(mod.CookieImportError, match="empty"):
            mod.parse_cookie_import("   ")

    def test_all_expired_rejected(self, home: Path) -> None:
        text = json.dumps([{"name": "old", "domain": "d.com", "expirationDate": 1.0}])
        with pytest.raises(mod.CookieImportError, match="no unexpired"):
            mod.parse_cookie_import(text)

    def test_unrecognisable_rejected(self, home: Path) -> None:
        with pytest.raises(mod.CookieImportError):
            mod.parse_cookie_import("this is not json or a cookies.txt")


# ── save / summary / clear ──


class TestSaveAndSummary:
    def test_save_writes_owner_only_storage_state(self, home: Path) -> None:
        cookies = mod.parse_cookie_import(
            json.dumps([{"name": "n", "value": "v", "domain": "d.com"}])
        )
        path = mod.save_storage_state(cookies)
        assert path == mod.storage_state_path()
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data == {"cookies": cookies, "origins": []}
        if not IS_WINDOWS:
            assert stat.S_IMODE(os.stat(path).st_mode) == 0o600

    def test_summary_has_no_values(self, home: Path) -> None:
        cookies = mod.parse_cookie_import(
            json.dumps(
                [
                    {"name": "a", "value": "SECRET", "domain": ".example.com"},
                    {
                        "name": "b",
                        "value": "TOKEN",
                        "domain": "other.com",
                        "expirationDate": 9999999999,
                    },
                ]
            )
        )
        mod.save_storage_state(cookies)
        summary = mod.storage_state_summary()
        assert summary is not None
        assert summary["cookie_count"] == 2
        # Leading dot stripped, sorted, distinct.
        assert summary["domains"] == ["example.com", "other.com"]
        assert summary["earliest_expiry"] == 9999999999.0
        assert "imported_at" in summary
        blob = json.dumps(summary)
        assert "SECRET" not in blob and "TOKEN" not in blob

    def test_summary_none_when_absent(self, home: Path) -> None:
        assert mod.storage_state_summary() is None

    def test_summary_session_only_earliest_is_none(self, home: Path) -> None:
        cookies = mod.parse_cookie_import(json.dumps([{"name": "n", "domain": "d.com"}]))
        mod.save_storage_state(cookies)
        assert mod.storage_state_summary()["earliest_expiry"] is None

    def test_clear_removes_file(self, home: Path) -> None:
        cookies = mod.parse_cookie_import(json.dumps([{"name": "n", "domain": "d.com"}]))
        mod.save_storage_state(cookies)
        assert mod.clear_storage_state() is True
        assert not mod.storage_state_path().exists()
        assert mod.clear_storage_state() is False


# ── launch.desired_config conditional storageState key ──


class TestLaunchConfig:
    def test_no_key_without_file(self, home: Path) -> None:
        assert launch_mod.desired_config() == {"browser": {"browserName": "chromium"}}

    def test_key_present_with_file(self, home: Path) -> None:
        mod.save_storage_state(
            mod.parse_cookie_import(json.dumps([{"name": "n", "domain": "d.com"}]))
        )
        config = launch_mod.desired_config()
        browser = config["browser"]
        assert isinstance(browser, dict)
        assert browser["contextOptions"] == {"storageState": str(mod.storage_state_path())}

    def test_write_config_converges_after_save_and_clear(self, home: Path) -> None:
        mod.save_storage_state(
            mod.parse_cookie_import(json.dumps([{"name": "n", "domain": "d.com"}]))
        )
        path = launch_mod.write_config()
        assert path is not None
        assert "storageState" in path.read_text(encoding="utf-8")
        mod.clear_storage_state()
        launch_mod.write_config()
        assert "storageState" not in path.read_text(encoding="utf-8")


# ── hot_load: best effort, never raises ──


class TestHotLoad:
    def test_no_cli_returns_note(self, home: Path) -> None:
        with patch.object(mod, "cli_command", return_value=None):
            result = mod.hot_load_into_live_sessions(mod.storage_state_path())
        assert result == {
            "loaded": [],
            "failed": {},
            "note": "playwright-cli is not installed",
        }

    def test_no_sessions_returns_note(self, home: Path) -> None:
        with (
            patch.object(mod, "cli_command", return_value=["node", "cli.js"]),
            patch.object(mod, "_live_session_names", return_value=[]),
        ):
            result = mod.hot_load_into_live_sessions(mod.storage_state_path())
        assert result["loaded"] == []
        assert result["failed"] == {}
        assert "note" in result

    def test_loads_and_reports_failures(self, home: Path) -> None:
        path = mod.storage_state_path()

        def fake_run(argv, **kwargs):
            proc = MagicMock()
            proc.returncode = 0 if "-s=kc-aaaa1111" in argv else 1
            proc.stdout = ""
            proc.stderr = "boom"
            return proc

        with (
            patch.object(mod, "cli_command", return_value=["node", "cli.js"]),
            patch.object(mod, "cli_env", return_value={}),
            patch.object(mod, "_live_session_names", return_value=["kc-aaaa1111", "kc-bbbb2222"]),
            patch("subprocess.run", side_effect=fake_run),
        ):
            result = mod.hot_load_into_live_sessions(path)
        assert result["loaded"] == ["kc-aaaa1111"]
        assert "kc-bbbb2222" in result["failed"]

    def test_never_raises_on_subprocess_error(self, home: Path) -> None:
        with (
            patch.object(mod, "cli_command", return_value=["node", "cli.js"]),
            patch.object(mod, "cli_env", return_value={}),
            patch.object(mod, "_live_session_names", return_value=["kc-aaaa1111"]),
            patch("subprocess.run", side_effect=OSError("nope")),
        ):
            result = mod.hot_load_into_live_sessions(mod.storage_state_path())
        assert result["loaded"] == []
        assert "kc-aaaa1111" in result["failed"]

    def test_live_session_names_filters_to_prefix(self, home: Path) -> None:
        proc = MagicMock()
        proc.returncode = 0
        proc.stdout = "kc-aaaa1111 running\npanel-1 running\nkc-bbbb2222\n"
        with (
            patch.object(mod, "cli_command", return_value=["node", "cli.js"]),
            patch.object(mod, "cli_env", return_value={}),
            patch("subprocess.run", return_value=proc),
        ):
            assert mod._live_session_names() == ["kc-aaaa1111", "kc-bbbb2222"]


# ── HTTP handlers ──


@pytest.fixture()
def mock_sel():
    try:
        import kiro_crew.dashboard.handlers  # noqa: F401
    except ImportError:
        pytest.skip("dashboard handler deps not available locally")
    m = MagicMock()
    m.log_api_access = MagicMock()
    with patch("kiro_crew.dashboard.handlers.sel", return_value=m):
        yield m


def _make_state(restricted: bool = False) -> MagicMock:
    state = MagicMock()
    # Empty owner_id -> the standalone-local path, where as_owner's default
    # ``local-app`` caller reads as the owner (the same shape NoConfiguredOwner
    # gives). A MagicMock owner_id would stringify to a non-empty value and deny.
    state.owner_id = ""
    state._restricted_keys = {"dashboard:guest"} if restricted else set()
    state._slots = {}
    # inherited_session_memory_mode reads these; keep them concrete so it does
    # not iterate a MagicMock (which would raise) before the _restricted_keys
    # check runs.
    state.context_builder = None
    state.subagents = None
    return state


@pytest.fixture()
def app(home: Path, mock_sel):
    from kiro_crew.dashboard.handlers import messaging

    application = web.Application()
    application.router.add_get("/api/browser/cookies", messaging.api_browser_cookies_get)
    application.router.add_post("/api/browser/cookies", messaging.api_browser_cookies_import)
    application.router.add_delete("/api/browser/cookies", messaging.api_browser_cookies_clear)
    as_owner(application)
    # as_owner installs NoConfiguredOwner only when there is no state; give a real
    # enough state so the restricted-session predicate has its maps.
    application["state"] = _make_state()
    return application


@pytest.mark.asyncio
async def test_status_absent_then_present(app, home: Path) -> None:
    async with TestClient(TestServer(app)) as client:
        resp = await client.get("/api/browser/cookies")
        assert resp.status == 200
        body = await resp.json()
        assert body["present"] is False
        assert body["summary"] is None
        assert body["config_path"].endswith("browser-storage-state.json")

        with patch(
            "kiro_crew.browser_cli.cookies.hot_load_into_live_sessions",
            return_value={"loaded": [], "failed": {}},
        ):
            imp = await client.post(
                "/api/browser/cookies",
                json={"content": json.dumps([{"name": "n", "value": "v", "domain": "d.com"}])},
            )
        assert imp.status == 200
        imp_body = await imp.json()
        assert imp_body["ok"] is True
        assert imp_body["summary"]["cookie_count"] == 1

        resp2 = await client.get("/api/browser/cookies")
        assert (await resp2.json())["present"] is True


@pytest.mark.asyncio
async def test_import_malformed_is_400(app, home: Path) -> None:
    async with TestClient(TestServer(app)) as client:
        resp = await client.post("/api/browser/cookies", json={"content": "not-a-cookie"})
        assert resp.status == 400
        assert (await resp.json())["code"] == "invalid_cookies"


@pytest.mark.asyncio
async def test_import_missing_content_is_400(app, home: Path) -> None:
    async with TestClient(TestServer(app)) as client:
        resp = await client.post("/api/browser/cookies", json={"filename": "x"})
        assert resp.status == 400
        assert (await resp.json())["code"] == "invalid_content"


@pytest.mark.asyncio
async def test_import_oversize_is_413(app, home: Path) -> None:
    async with TestClient(TestServer(app)) as client:
        payload = json.dumps({"content": "x" * (mod.MAX_IMPORT_BYTES + 100)})
        resp = await client.post(
            "/api/browser/cookies",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        assert resp.status == 413


@pytest.mark.asyncio
async def test_clear_removes(app, home: Path) -> None:
    mod.save_storage_state(mod.parse_cookie_import(json.dumps([{"name": "n", "domain": "d.com"}])))
    async with TestClient(TestServer(app)) as client:
        resp = await client.delete("/api/browser/cookies")
        assert resp.status == 200
        assert (await resp.json()) == {"ok": True, "present": False}
    assert not mod.storage_state_path().exists()


@pytest.mark.asyncio
async def test_non_owner_forbidden(app, home: Path) -> None:
    async with TestClient(TestServer(app)) as client:
        headers = {"X-Test-User": "someone-else"}
        assert (await client.get("/api/browser/cookies", headers=headers)).status == 403
        assert (
            await client.post("/api/browser/cookies", json={"content": "x"}, headers=headers)
        ).status == 403
        assert (await client.delete("/api/browser/cookies", headers=headers)).status == 403


@pytest.mark.asyncio
async def test_restricted_session_forbidden(home: Path, mock_sel) -> None:
    from kiro_crew.dashboard.handlers import messaging

    application = web.Application()
    application.router.add_post("/api/browser/cookies", messaging.api_browser_cookies_import)
    application.router.add_delete("/api/browser/cookies", messaging.api_browser_cookies_clear)
    as_owner(application)
    application["state"] = _make_state(restricted=True)
    headers = {"X-Session-Key": "dashboard:guest"}
    async with TestClient(TestServer(application)) as client:
        imp = await client.post(
            "/api/browser/cookies",
            json={"content": json.dumps([{"name": "n", "domain": "d.com"}])},
            headers=headers,
        )
        assert imp.status == 403
        assert (await imp.json())["code"] == "restricted_session"
        clr = await client.delete("/api/browser/cookies", headers=headers)
        assert clr.status == 403
