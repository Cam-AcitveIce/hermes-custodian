"""Loopback-only authenticated read-only web dashboard for Hermes Custodian."""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import socket
import stat
import sys
import threading
import time
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, TextIO
from urllib.parse import parse_qs, urlsplit

ALLOWED_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
SESSION_COOKIE_NAME = "custodian_session"
CSP_HEADER_VALUE = (
    "default-src 'none'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "font-src 'self'; "
    "base-uri 'none'; "
    "frame-ancestors 'none'; "
    "form-action 'self'"
)
POLICY_DISCLOSURE_TEXT = (
    "Content SHA-256 hashes are computed only for .py and .md files within max_file_bytes; "
    "all other file types are inspected metadata-only (mode, uid, size, mtime_ns), and "
    "sensitive directories/credentials are never enumerated or read."
)

_ANSI_ESCAPE_RE = re.compile(r"\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
_FORBIDDEN_SECRET_KEYS = frozenset(
    {
        "api_key",
        "apikey",
        "access_token",
        "refresh_token",
        "auth_token",
        "bearer_token",
        "token",
        "secret",
        "secret_key",
        "private_key",
        "password",
        "passwd",
        "credential",
        "credentials",
        "authorization",
        "cookie",
        "env",
        "headers",
        "command",
        "args",
        "url",
    }
)


class DashboardAuthNotConfiguredError(RuntimeError, ValueError):
    """Raised when starting the dashboard before credentials are set via CLI."""


def _sanitise_text(value: str) -> str:
    """Remove ANSI escape sequences and control characters from text."""
    try:
        from custodian import policy as _policy

        if hasattr(_policy, "sanitise_text"):
            value = _policy.sanitise_text(value)
    except Exception:
        pass
    cleaned = _ANSI_ESCAPE_RE.sub("", value)
    return "".join(
        ch for ch in cleaned if ch in ("\n", "\t") or (ord(ch) >= 32 and ord(ch) != 127 and not (0x80 <= ord(ch) <= 0x9F))
    )


_STATIC_ASSETS: dict[str, tuple[str, str]] = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/styles.css": ("styles.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "application/javascript; charset=utf-8"),
}


def _resolve_static_dir(
    module_file: Path | None = None,
    sys_prefix: Path | None = None,
) -> Path:
    """Resolve dashboard static directory from repo root or installed wheel data-files."""
    mod_path = Path(module_file) if module_file is not None else Path(__file__).resolve()
    repo_candidate = mod_path.parent.parent / "dashboard"
    if repo_candidate.is_dir():
        return repo_candidate
    prefix_path = Path(sys_prefix) if sys_prefix is not None else Path(sys.prefix)
    return prefix_path / "share" / "hermes-custodian" / "dashboard"


def _scrub_value(value: Any) -> Any:
    """Recursively sanitize strings and strip forbidden secret-bearing dictionary keys."""
    if isinstance(value, str):
        return _sanitise_text(value)
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            key_str = _sanitise_text(str(k))
            if key_str.lower() in _FORBIDDEN_SECRET_KEYS:
                continue
            out[key_str] = _scrub_value(v)
        return out
    if isinstance(value, (list, tuple)):
        return [_scrub_value(item) for item in value]
    return value


def _validate_loopback_host(host: str) -> str:
    if not isinstance(host, str) or not host.strip():
        raise ValueError("Host must be a non-empty loopback address.")
    normalized = host.strip()
    if normalized in ALLOWED_LOOPBACK_HOSTS:
        return normalized
    try:
        addr = ipaddress.ip_address(normalized)
    except ValueError as exc:
        raise ValueError(
            f"Refusing to bind dashboard to non-loopback host {host!r}."
        ) from exc
    if not addr.is_loopback or (normalized != "127.0.0.1" and normalized != "::1"):
        raise ValueError(
            f"Refusing to bind dashboard to non-loopback address {host!r}."
        )
    return normalized


def _resolve_auth(engine: Any, auth: Any | None) -> Any:
    if auth is None:
        store = getattr(engine, "store", None)
        state_dir = getattr(store, "root", None) or getattr(engine, "state_dir", None)
        if state_dir is None:
            raise DashboardAuthNotConfiguredError(
                "Dashboard login is not configured. Run 'custodian dashboard-credentials' first."
            )
        try:
            from custodian.dashboard_auth import DashboardAuth
        except ImportError as exc:
            raise DashboardAuthNotConfiguredError(
                "Dashboard authentication module unavailable. Run 'custodian dashboard-credentials' first."
            ) from exc
        auth = DashboardAuth(Path(state_dir))
    if not hasattr(auth, "configured") or not auth.configured():
        raise DashboardAuthNotConfiguredError(
            "Dashboard login credentials are not configured. Run 'custodian dashboard-credentials' to set a username and password."
        )
    return auth


def _safe_settings(engine: Any) -> tuple[bool, dict[str, Any] | None]:
    try:
        raw = engine.settings()
        if isinstance(raw, dict):
            return True, _scrub_value(raw)
        return False, None
    except Exception:
        return False, None


def _safe_status(engine: Any) -> dict[str, Any]:
    try:
        raw = engine.status()
        if isinstance(raw, dict):
            return _scrub_value(raw)
    except Exception as exc:
        return {
            "configured": False,
            "monitoring": False,
            "last_scan": None,
            "findings_open": 0,
            "coverage": "degraded",
            "stale": True,
            "service_health": f"Engine status error: {_sanitise_text(str(exc))}",
        }
    return {
        "configured": False,
        "monitoring": False,
        "last_scan": None,
        "findings_open": 0,
        "coverage": "unconfigured",
        "stale": False,
    }


def _compute_coverage_summary(
    status: dict[str, Any],
    settings: dict[str, Any] | None,
    configured: bool,
) -> dict[str, Any]:
    last_scan = status.get("last_scan") if isinstance(status.get("last_scan"), dict) else None
    raw_cov = status.get("coverage")
    stale_flag = bool(status.get("stale", False))
    monitoring = bool(status.get("monitoring", False))
    findings_open = int(status.get("findings_open", 0) or 0)
    max_files = int(settings.get("max_files", 0)) if isinstance(settings, dict) and settings.get("max_files") else 0
    files_checked = int(last_scan.get("files_checked", 0)) if last_scan else 0
    scan_errors = list(last_scan.get("errors") or []) if last_scan else []
    scan_complete = bool(last_scan.get("complete", False)) if last_scan else False

    if isinstance(raw_cov, dict):
        raw_state = str(raw_cov.get("state") or ("complete" if scan_complete else "degraded"))
        if not max_files and raw_cov.get("max_files"):
            max_files = int(raw_cov["max_files"])
    elif isinstance(raw_cov, str):
        raw_state = raw_cov
    else:
        raw_state = "unconfigured" if not configured else ("complete" if scan_complete else "not_scanned")

    if raw_state.lower() == "healthy":
        raw_state = "complete"

    monitor_state = "running" if monitoring else "stopped"
    monitor_note = "background monitor running" if monitoring else "background monitor stopped"
    findings_note = f"{findings_open} open finding{'s' if findings_open != 1 else ''}"

    if not configured or raw_state == "unconfigured":
        state = "unconfigured"
        label = "UNCONFIGURED"
        degraded = True
        reason = "Custodian is not configured yet. Run 'custodian setup' via CLI/TUI to select monitored roots."
    elif raw_state == "not_scanned" or last_scan is None:
        state = "not_scanned"
        label = "NOT SCANNED"
        degraded = True
        reason = f"Configuration saved, but no baseline scan has been recorded yet ({monitor_note})."
    elif raw_state == "scope_changed":
        state = "scope_changed"
        label = "SCOPE CHANGED"
        degraded = True
        reason = f"Configured scope changed since the last scan. Run a new scan to refresh baseline ({findings_note}; {monitor_note})."
    elif raw_state == "degraded" or not scan_complete or scan_errors:
        state = "degraded"
        label = "COVERAGE DEGRADED"
        degraded = True
        if scan_errors:
            reason = f"Degraded coverage: {scan_errors[0]} ({findings_note}; {monitor_note})."
        else:
            reason = f"Last scan did not complete within configured file/byte budget ({findings_note}; {monitor_note})."
    elif raw_state == "stale" or stale_flag:
        state = "stale"
        label = "COVERAGE STALE"
        degraded = True
        reason = f"Monitoring data is stale: last scan exceeded 2x configured interval ({findings_note}; {monitor_note})."
    else:
        state = "complete"
        label = "COMPLETE WITHIN POLICY"
        degraded = False
        reason = (
            f"Scan coverage complete within policy budgets ({findings_note}; {monitor_note}). "
            "Coverage completion reflects scan budget only, not absence of findings."
        )

    return {
        "state": state,
        "label": label,
        "monitor_state": monitor_state,
        "findings_open": findings_open,
        "degraded": degraded,
        "stale": stale_flag or state == "stale",
        "complete": scan_complete and not degraded,
        "files_checked": files_checked,
        "max_files": max_files,
        "errors": scan_errors,
        "reason": reason,
    }


def _mark_stores_unreadable(summary: dict[str, Any], data_errors: list[str]) -> dict[str, Any]:
    """An unreadable store must never look like a clean system: fail closed."""
    names = " and ".join(data_errors)
    updated = dict(summary)
    updated["state"] = "degraded"
    updated["label"] = "COVERAGE DEGRADED"
    updated["degraded"] = True
    updated["complete"] = False
    updated["errors"] = list(updated.get("errors") or []) + [f"stored {names} could not be read"]
    updated["reason"] = f"Could not read stored {names}; the lists shown may be incomplete."
    return updated


def _compute_scope_preview(
    settings: dict[str, Any] | None,
    status: dict[str, Any],
    configured: bool,
) -> dict[str, Any]:
    if not configured or not isinstance(settings, dict):
        return {
            "configured": False,
            "profiles": [],
            "watched_paths": [],
            "deduped_roots": [],
            "exclusions": [],
            "max_files": 0,
            "max_file_bytes": 0,
            "max_theoretical_scan_bytes": 0,
            "interval_seconds": 0,
            "retention_days": 0,
            "files_checked": 0,
            "budget_utilization_pct": None,
            "policy_disclosure": POLICY_DISCLOSURE_TEXT,
            "read_only_notice": "Dashboard is read-only. Configure scope via CLI/TUI.",
        }

    profiles = list(settings.get("profiles") or settings.get("selected_profile_paths") or [])
    watched_paths = list(settings.get("watched_paths") or [])
    exclusions = list(settings.get("exclusions") or [])
    max_files = int(settings.get("max_files") or 0)
    max_file_bytes = int(settings.get("max_file_bytes") or 0)
    interval_seconds = int(settings.get("interval_seconds") or 0)
    retention_days = int(settings.get("retention_days") or 0)

    roots: list[Path] = []
    for raw_p in sorted(set(profiles + watched_paths)):
        cand = Path(raw_p)
        if not any(r == cand or r in cand.parents for r in roots):
            roots.append(cand)

    last_scan = status.get("last_scan") if isinstance(status.get("last_scan"), dict) else None
    files_checked = int(last_scan.get("files_checked", 0)) if last_scan else 0
    utilization = (
        round((files_checked / max_files) * 100.0, 1)
        if (max_files > 0 and last_scan is not None)
        else None
    )

    return {
        "configured": True,
        "profiles": profiles,
        "watched_paths": watched_paths,
        "deduped_roots": [str(r) for r in roots],
        "exclusions": exclusions,
        "max_files": max_files,
        "max_file_bytes": max_file_bytes,
        "max_theoretical_scan_bytes": max_files * max_file_bytes,
        "interval_seconds": interval_seconds,
        "retention_days": retention_days,
        "files_checked": files_checked,
        "budget_utilization_pct": utilization,
        "policy_disclosure": POLICY_DISCLOSURE_TEXT,
        "read_only_notice": "Dashboard is read-only. Modify scope or budgets via CLI/TUI (custodian setup).",
    }


def _normalize_inventory_entry(raw: dict[str, Any]) -> dict[str, Any]:
    cleaned = _scrub_value(raw)
    name = str(cleaned.get("name") or cleaned.get("profile") or "default")
    path = str(cleaned.get("path") or "")
    meta = cleaned.get("metadata") if isinstance(cleaned.get("metadata"), dict) else {}

    def _as_str_list(val: Any) -> list[str]:
        if isinstance(val, str) and val:
            return [val]
        if isinstance(val, list):
            return [str(x) for x in val if isinstance(x, (str, int, float))]
        if isinstance(val, dict):
            return [str(k) for k in val.keys()]
        return []

    models = _as_str_list(cleaned.get("models") or meta.get("models") or meta.get("model") or meta.get("default_model"))
    providers = _as_str_list(cleaned.get("providers") or meta.get("providers") or meta.get("provider"))
    plugins = _as_str_list(cleaned.get("plugins") or meta.get("plugins") or meta.get("enabled_plugins"))
    mcp_servers = _as_str_list(cleaned.get("mcp_servers") or meta.get("mcp_servers") or meta.get("mcp"))
    errors = _as_str_list(cleaned.get("errors") or [])

    return {
        "name": name,
        "profile": name,
        "path": path,
        "models": models,
        "providers": providers,
        "plugins": plugins,
        "mcp_servers": mcp_servers,
        "metadata": meta,
        "errors": errors,
    }


def _collect_consented_inventory(
    engine: Any,
    settings: dict[str, Any] | None,
    configured: bool,
) -> dict[str, Any]:
    """Query engine.inventory ONLY for an explicitly persisted hermes_root."""
    if not configured or not isinstance(settings, dict):
        return {
            "configured": False,
            "discovery_approved": False,
            "consented_roots": [],
            "profiles": [],
            "explanation": "Custodian is not configured; run setup first.",
            "privacy_notice": "Discovery not approved in setup. Private memory, history, SOUL, and credentials are never read.",
        }

    hermes_root = settings.get("hermes_root")
    if not isinstance(hermes_root, str) or not hermes_root.strip():
        return {
            "configured": True,
            "discovery_approved": False,
            "consented_roots": [],
            "profiles": [],
            "explanation": "Discovery not approved in setup",
            "privacy_notice": "Discovery not approved in setup. Selecting scan profiles does not grant config-discovery consent.",
        }

    consented_roots = [hermes_root.strip()]

    profiles: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    for root_str in consented_roots:
        try:
            items = engine.inventory(Path(root_str))
        except Exception as exc:
            profiles.append(
                {
                    "name": Path(root_str).name or "root",
                    "profile": Path(root_str).name or "root",
                    "path": _sanitise_text(root_str),
                    "models": [],
                    "providers": [],
                    "plugins": [],
                    "mcp_servers": [],
                    "metadata": {},
                    "errors": [_sanitise_text(f"Inventory unavailable: {exc}")],
                }
            )
            continue
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict):
                    norm = _normalize_inventory_entry(item)
                    dedupe_key = f"{norm['name']}::{norm['path']}"
                    if dedupe_key not in seen_paths:
                        seen_paths.add(dedupe_key)
                        profiles.append(norm)

    return {
        "configured": True,
        "discovery_approved": True,
        "consented_roots": [_sanitise_text(r) for r in consented_roots],
        "profiles": profiles,
        "explanation": "Metadata-only inventory from consented hermes_root.",
        "privacy_notice": "Metadata-only inventory from consented roots. Credentials, SOUL.md, memory, and chat history are never read.",
    }


def _safe_updates(engine: Any) -> dict[str, Any]:
    if not hasattr(engine, "updates"):
        return {
            "supported": False,
            "status": "unavailable",
            "available_count": None,
            "reason": "Update check adapter not available on this engine instance.",
        }
    try:
        res = engine.updates()
        if isinstance(res, dict):
            return _scrub_value(res)
    except Exception as exc:
        return {
            "supported": False,
            "status": "failed",
            "available_count": None,
            "reason": _sanitise_text(f"Update check failed: {exc}"),
        }
    return {
        "supported": False,
        "status": "unavailable",
        "available_count": None,
    }


DEFAULT_IDLE_SESSION_SECONDS = 12 * 3600
DEFAULT_ABSOLUTE_SESSION_SECONDS = 14 * 86400


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    if not text or not re.fullmatch(r"[A-Za-z0-9_-]+", text):
        raise ValueError("Invalid base64url segment")
    padding = "=" * ((4 - (len(text) % 4)) % 4)
    return base64.urlsafe_b64decode((text + padding).encode("ascii"))


def _resolve_state_dir(engine: Any, auth: Any) -> Path:
    store = getattr(engine, "store", None)
    raw = getattr(store, "root", None) or getattr(engine, "state_dir", None) or getattr(auth, "root", None)
    if raw is None:
        raise DashboardAuthNotConfiguredError("State directory unavailable for dashboard session key.")
    from .storage import Storage

    return Storage(raw).root


class CustodianDashboardServer(ThreadingHTTPServer):
    """ThreadingHTTPServer bound strictly to loopback with signed stateless session tokens."""

    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        RequestHandlerClass: type[BaseHTTPRequestHandler],
        *,
        engine: Any,
        auth: Any,
        requested_host: str,
        session_ttl_seconds: int = DEFAULT_IDLE_SESSION_SECONDS,
        absolute_session_seconds: int = DEFAULT_ABSOLUTE_SESSION_SECONDS,
        max_failed_logins: int = 5,
        rate_limit_window_seconds: int = 60,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if ":" in server_address[0]:
            self.address_family = socket.AF_INET6
        super().__init__(server_address, RequestHandlerClass)
        self.engine = engine
        self.auth = auth
        self.state_dir = _resolve_state_dir(engine, auth)
        self.session_key_path = self.state_dir / "dashboard-session-key.json"
        self.bound_host = requested_host
        self.bound_port = int(self.server_address[1])
        host_fmt = f"[{self.bound_host}]" if ":" in self.bound_host else self.bound_host
        self.expected_host_header = f"{host_fmt}:{self.bound_port}"
        self.base_url = f"http://{self.expected_host_header}"
        self.session_ttl_seconds = max(1, int(session_ttl_seconds))
        self.absolute_session_seconds = max(self.session_ttl_seconds, int(absolute_session_seconds))
        self.max_failed_logins = max(1, int(max_failed_logins))
        self.rate_limit_window_seconds = max(1, int(rate_limit_window_seconds))
        self.clock = clock or time.time
        self._lock = threading.Lock()
        self._failed_logins: list[float] = []
        # Ensure persisted signing key + epoch exist on startup
        self._load_or_create_key_and_epoch()

    def _read_key_record_unlocked(self) -> tuple[bytes, str]:
        fd = os.open(
            self.session_key_path,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
        )
        with os.fdopen(fd, "r", encoding="utf-8") as stream:
            info = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_nlink != 1
                or (info.st_mode & 0o077) != 0
                or info.st_size > 4096
            ):
                raise ValueError("Invalid dashboard session key file permissions or link count")
            record = json.loads(stream.read(4097))
        if not isinstance(record, dict) or record.get("schema_version") != 1:
            raise ValueError("Unsupported session key schema")
        key_hex = record.get("signing_key")
        epoch_hex = record.get("epoch")
        if (
            not isinstance(key_hex, str)
            or not re.fullmatch(r"[0-9a-f]{64}", key_hex)
            or not isinstance(epoch_hex, str)
            or not re.fullmatch(r"[0-9a-f]{32}", epoch_hex)
        ):
            raise ValueError("Malformed session key or epoch")
        return bytes.fromhex(key_hex), epoch_hex

    def _write_key_record_unlocked(self, key_hex: str, epoch_hex: str) -> None:
        record_bytes = json.dumps(
            {"schema_version": 1, "signing_key": key_hex, "epoch": epoch_hex},
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            fd = os.open(self.session_key_path, flags, 0o600)
            try:
                os.write(fd, record_bytes)
                os.fsync(fd)
            finally:
                os.close(fd)
        except FileExistsError:
            # Verify existing path is not a symlink before atomic replacement
            st = os.lstat(self.session_key_path)
            if not stat.S_ISREG(st.st_mode):
                raise ValueError("Refusing to overwrite non-regular session key path")
            tmp_path = self.state_dir / f".dashboard-session-key-{secrets.token_hex(8)}"
            fd = os.open(tmp_path, flags, 0o600)
            try:
                os.write(fd, record_bytes)
                os.fsync(fd)
            finally:
                os.close(fd)
            try:
                os.replace(tmp_path, self.session_key_path)
            finally:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
        dir_fd = os.open(self.state_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)

    def _load_or_create_key_and_epoch(self) -> tuple[bytes, str]:
        with self._lock:
            try:
                return self._read_key_record_unlocked()
            except FileNotFoundError:
                pass
            except (OSError, ValueError, TypeError):
                try:
                    st = os.lstat(self.session_key_path)
                    if not stat.S_ISREG(st.st_mode):
                        raise
                except FileNotFoundError:
                    pass
            key_hex = secrets.token_hex(32)
            epoch_hex = secrets.token_hex(16)
            self._write_key_record_unlocked(key_hex, epoch_hex)
            return bytes.fromhex(key_hex), epoch_hex

    def _current_auth_revision(self) -> str | None:
        if not hasattr(self.auth, "revision"):
            return ""
        try:
            rev = self.auth.revision()
            return str(rev) if isinstance(rev, str) else None
        except Exception:
            return None

    def _sign_claims(self, key_bytes: bytes, claims: dict[str, Any]) -> str:
        raw_payload = json.dumps(claims, separators=(",", ":"), sort_keys=True).encode("utf-8")
        payload_b64 = _b64url_encode(raw_payload)
        sig = hmac.new(key_bytes, payload_b64.encode("ascii"), hashlib.sha256).digest()
        sig_b64 = _b64url_encode(sig)
        return f"{payload_b64}.{sig_b64}"

    def check_rate_limit(self) -> tuple[bool, int]:
        """Return (is_limited, retry_after_seconds)."""
        now = self.clock()
        cutoff = now - self.rate_limit_window_seconds
        with self._lock:
            self._failed_logins = [t for t in self._failed_logins if t > cutoff]
            if len(self._failed_logins) >= self.max_failed_logins:
                oldest = self._failed_logins[0]
                retry_after = max(1, int((oldest + self.rate_limit_window_seconds) - now + 0.999))
                return True, retry_after
            return False, 0

    def record_failed_login(self) -> None:
        now = self.clock()
        with self._lock:
            self._failed_logins.append(now)

    def create_session_cookie_value(self) -> tuple[str, int]:
        now = int(self.clock())
        exp = min(now + self.session_ttl_seconds, now + self.absolute_session_seconds)
        rev = self._current_auth_revision()
        if rev is None:
            raise DashboardAuthNotConfiguredError("Dashboard login verifier unavailable.")
        key_bytes, epoch = self._load_or_create_key_and_epoch()
        claims = {
            "epoch": epoch,
            "exp": exp,
            "iat": now,
            "revision": rev,
        }
        token = self._sign_claims(key_bytes, claims)
        with self._lock:
            self._failed_logins.clear()
        max_age = max(1, exp - now)
        return token, max_age

    def validate_and_refresh_session(self, token: str | None) -> tuple[bool, str | None, int]:
        if not token or not isinstance(token, str) or len(token) > 1024 or "." not in token:
            return False, None, 0
        parts = token.split(".")
        if len(parts) != 2:
            return False, None, 0
        payload_b64, sig_b64 = parts
        if not payload_b64 or not sig_b64:
            return False, None, 0
        try:
            key_bytes, current_epoch = self._load_or_create_key_and_epoch()
            current_rev = self._current_auth_revision()
            if current_rev is None:
                return False, None, 0
            expected_sig = hmac.new(key_bytes, payload_b64.encode("ascii"), hashlib.sha256).digest()
            expected_sig_b64 = _b64url_encode(expected_sig)
            if not hmac.compare_digest(expected_sig_b64, sig_b64):
                return False, None, 0
            raw_claims = _b64url_decode(payload_b64)
            claims = json.loads(raw_claims.decode("utf-8"))
        except Exception:
            return False, None, 0

        if not isinstance(claims, dict):
            return False, None, 0
        iat = claims.get("iat")
        exp = claims.get("exp")
        tok_rev = claims.get("revision")
        tok_epoch = claims.get("epoch")
        if (
            type(iat) is not int
            or type(exp) is not int
            or not isinstance(tok_rev, str)
            or not isinstance(tok_epoch, str)
        ):
            return False, None, 0

        now = int(self.clock())
        # Reject future-dated, expired idle, or absolute-cap-exceeded tokens
        if (
            iat > now
            or exp <= iat
            or now >= exp
            or (now - iat) >= self.absolute_session_seconds
            or (exp - iat) > self.absolute_session_seconds
        ):
            return False, None, 0

        if not hmac.compare_digest(tok_rev, current_rev):
            return False, None, 0
        if not hmac.compare_digest(tok_epoch, current_epoch):
            return False, None, 0

        new_exp = min(now + self.session_ttl_seconds, iat + self.absolute_session_seconds)
        if new_exp <= now:
            return False, None, 0
        refreshed_claims = {
            "epoch": current_epoch,
            "exp": new_exp,
            "iat": iat,
            "revision": current_rev,
        }
        refreshed_token = self._sign_claims(key_bytes, refreshed_claims)
        return True, refreshed_token, max(1, new_exp - now)

    def validate_session(self, token: str | None) -> bool:
        valid, _, _ = self.validate_and_refresh_session(token)
        return valid

    def revoke_session(self, _token: str | None = None) -> None:
        """Rotate persisted session epoch so Sign Out revokes all outstanding tokens."""
        with self._lock:
            try:
                key_bytes, _ = self._read_key_record_unlocked()
                key_hex = key_bytes.hex()
            except Exception:
                key_hex = secrets.token_hex(32)
            new_epoch = secrets.token_hex(16)
            self._write_key_record_unlocked(key_hex, new_epoch)


class _DashboardRequestHandler(BaseHTTPRequestHandler):
    server: CustodianDashboardServer  # type: ignore[assignment]

    def log_message(self, format: str, *args: Any) -> None:
        # Never write credentials, query strings, or headers to stderr logs.
        return

    def _send_security_headers(self) -> None:
        self.send_header("Content-Security-Policy", CSP_HEADER_VALUE)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")

    def _send_json(
        self,
        status: int,
        payload: dict[str, Any],
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self._send_security_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        refreshed_cookie = getattr(self, "_refreshed_cookie_header", None)
        if refreshed_cookie and (not extra_headers or "Set-Cookie" not in extra_headers):
            self.send_header("Set-Cookie", refreshed_cookie)
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _validate_host_and_query(self) -> tuple[bool, str, dict[str, list[str]]]:
        host_headers = self.headers.get_all("Host") or []
        if len(host_headers) != 1 or host_headers[0] != self.server.expected_host_header:
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": "invalid_host", "message": "Exact loopback Host:port header required."},
            )
            return False, "", {}
        parsed = urlsplit(self.path)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        for forbidden_param in ("username", "user", "password", "passwd", "token", "access_token", "auth", "session", "key"):
            if forbidden_param in qs:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {
                        "error": "credentials_in_url_forbidden",
                        "message": "Credentials or session tokens must never be passed in URL parameters.",
                    },
                )
                return False, "", {}
        return True, parsed.path, qs

    def _extract_session_cookie(self) -> str | None:
        raw_cookie = self.headers.get("Cookie")
        if not raw_cookie:
            return None
        cookie = SimpleCookie()
        try:
            cookie.load(raw_cookie)
        except Exception:
            return None
        morsel = cookie.get(SESSION_COOKIE_NAME)
        return morsel.value if morsel else None

    def _is_authenticated(self) -> bool:
        sid = self._extract_session_cookie()
        valid, refreshed_token, max_age = self.server.validate_and_refresh_session(sid)
        if valid and refreshed_token:
            self._refreshed_cookie_header = (
                f"{SESSION_COOKIE_NAME}={refreshed_token}; "
                f"HttpOnly; SameSite=Strict; Path=/; Max-Age={max_age}"
            )
            return True
        self._refreshed_cookie_header = None
        return False

    def _require_exact_origin(self) -> bool:
        origin = self.headers.get("Origin")
        if not origin or origin != self.server.base_url:
            self._send_json(
                HTTPStatus.FORBIDDEN,
                {"error": "invalid_origin", "message": "Exact loopback Origin header required."},
            )
            return False
        return True

    def _build_snapshot(self, event_limit: int = 100) -> dict[str, Any]:
        engine = self.server.engine
        has_settings, settings = _safe_settings(engine)
        status = _safe_status(engine)
        configured = bool(status.get("configured", False) and has_settings)
        status["configured"] = configured

        data_errors: list[str] = []
        try:
            findings = _scrub_value(engine.findings()) if configured else []
        except Exception:
            findings = []
            data_errors.append("findings")
        try:
            events = _scrub_value(engine.events(limit=event_limit)) if configured else []
        except Exception:
            events = []
            data_errors.append("events")

        coverage_summary = _compute_coverage_summary(status, settings, configured)
        if data_errors:
            coverage_summary = _mark_stores_unreadable(coverage_summary, data_errors)
        scope_preview = _compute_scope_preview(settings, status, configured)
        inventory_data = _collect_consented_inventory(engine, settings, configured)
        updates_data = _safe_updates(engine)

        return {
            "read_only": True,
            "status": status,
            "coverage_summary": coverage_summary,
            "scope_preview": scope_preview,
            "settings": settings if configured else None,
            "findings": findings if isinstance(findings, list) else [],
            "events": events if isinstance(events, list) else [],
            "data_errors": data_errors,
            "inventory": inventory_data,
            "updates": updates_data,
        }

    def do_GET(self) -> None:
        ok, route, qs = self._validate_host_and_query()
        if not ok:
            return
        if route == "/api/session":
            self._send_json(
                HTTPStatus.OK,
                {"authenticated": self._is_authenticated(), "read_only": True},
            )
            return
        if route.startswith("/api/"):
            if not self._is_authenticated():
                self._send_json(
                    HTTPStatus.UNAUTHORIZED,
                    {"error": "unauthorized", "message": "Valid session required."},
                )
                return
            engine = self.server.engine
            if route == "/api/snapshot":
                self._send_json(HTTPStatus.OK, self._build_snapshot())
                return
            if route == "/api/status":
                has_settings, settings = _safe_settings(engine)
                status = _safe_status(engine)
                configured = bool(status.get("configured", False) and has_settings)
                status["configured"] = configured
                status["coverage_summary"] = _compute_coverage_summary(status, settings, configured)
                self._send_json(HTTPStatus.OK, status)
                return
            if route == "/api/findings":
                has_settings, _ = _safe_settings(engine)
                status = _safe_status(engine)
                configured = bool(status.get("configured", False) and has_settings)
                try:
                    items = _scrub_value(engine.findings()) if configured else []
                except Exception:
                    self._send_json(
                        HTTPStatus.SERVICE_UNAVAILABLE,
                        {"error": "store_unavailable", "message": "Stored findings could not be read."},
                    )
                    return
                self._send_json(
                    HTTPStatus.OK,
                    {"configured": configured, "findings": items if isinstance(items, list) else []},
                )
                return
            if route == "/api/events":
                limit = 100
                if "limit" in qs and qs["limit"]:
                    try:
                        limit = max(1, min(1000, int(qs["limit"][0])))
                    except ValueError:
                        limit = 100
                has_settings, _ = _safe_settings(engine)
                status = _safe_status(engine)
                configured = bool(status.get("configured", False) and has_settings)
                try:
                    items = _scrub_value(engine.events(limit=limit)) if configured else []
                except Exception:
                    self._send_json(
                        HTTPStatus.SERVICE_UNAVAILABLE,
                        {"error": "store_unavailable", "message": "Stored events could not be read."},
                    )
                    return
                self._send_json(
                    HTTPStatus.OK,
                    {"configured": configured, "events": items if isinstance(items, list) else []},
                )
                return
            if route == "/api/settings":
                has_settings, settings = _safe_settings(engine)
                status = _safe_status(engine)
                configured = bool(status.get("configured", False) and has_settings)
                self._send_json(
                    HTTPStatus.OK,
                    {
                        "configured": configured,
                        "read_only": True,
                        "settings": settings if configured else None,
                        "scope_preview": _compute_scope_preview(settings, status, configured),
                    },
                )
                return
            if route == "/api/inventory":
                has_settings, settings = _safe_settings(engine)
                status = _safe_status(engine)
                configured = bool(status.get("configured", False) and has_settings)
                self._send_json(
                    HTTPStatus.OK,
                    _collect_consented_inventory(engine, settings, configured),
                )
                return
            if route == "/api/updates":
                self._send_json(HTTPStatus.OK, _safe_updates(engine))
                return
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return
        if route in _STATIC_ASSETS:
            filename, content_type = _STATIC_ASSETS[route]
            static_dir = _resolve_static_dir()
            asset_path = static_dir / filename
            try:
                fd = os.open(asset_path, os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    st = os.fstat(fd)
                    if not stat.S_ISREG(st.st_mode) or st.st_size > 1048576:
                        raise ValueError("Invalid static asset")
                    body = os.read(fd, st.st_size + 1)
                finally:
                    os.close(fd)
            except OSError:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
                return
            self.send_response(HTTPStatus.OK)
            self._send_security_headers()
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

    def do_POST(self) -> None:
        ok, route, _ = self._validate_host_and_query()
        if not ok:
            return
        if route not in ("/api/session", "/api/logout"):
            self._send_json(
                HTTPStatus.METHOD_NOT_ALLOWED,
                {
                    "error": "read_only_dashboard",
                    "message": "Dashboard API is strictly read-only. Use CLI/TUI for changes.",
                },
                extra_headers={"Allow": "GET"},
            )
            return
        if not self._require_exact_origin():
            return
        if route == "/api/logout":
            sid = self._extract_session_cookie()
            self.server.revoke_session(sid)
            clear_cookie = (
                f"{SESSION_COOKIE_NAME}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"
            )
            self._send_json(
                HTTPStatus.OK,
                {"authenticated": False},
                extra_headers={"Set-Cookie": clear_cookie},
            )
            return

        limited, retry_after = self.server.check_rate_limit()
        if limited:
            self._send_json(
                HTTPStatus.TOO_MANY_REQUESTS,
                {
                    "error": "rate_limited",
                    "message": "Too many failed login attempts. Try again later.",
                    "retry_after_seconds": retry_after,
                },
                extra_headers={"Retry-After": str(retry_after)},
            )
            return

        content_type = (self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": "invalid_content_type", "message": "Expected application/json."},
            )
            return

        try:
            length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            length = 0
        if length <= 0 or length > 4096:
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": "invalid_body", "message": "Invalid request payload size."},
            )
            return

        raw_body = self.rfile.read(length)
        try:
            body_obj = json.loads(raw_body.decode("utf-8"))
        except Exception:
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": "invalid_json", "message": "Malformed JSON body."},
            )
            return

        username = body_obj.get("username") if isinstance(body_obj, dict) else None
        password = body_obj.get("password") if isinstance(body_obj, dict) else None
        if (
            not isinstance(username, str)
            or not isinstance(password, str)
            or not username.strip()
            or not password
            or not self.server.auth.authenticate(username.strip(), password)
        ):
            self.server.record_failed_login()
            self._send_json(
                HTTPStatus.UNAUTHORIZED,
                {"error": "invalid_credentials", "message": "Invalid username or password."},
            )
            return

        token, max_age = self.server.create_session_cookie_value()
        cookie_val = (
            f"{SESSION_COOKIE_NAME}={token}; "
            f"HttpOnly; SameSite=Strict; Path=/; Max-Age={max_age}"
        )
        self._send_json(
            HTTPStatus.OK,
            {
                "authenticated": True,
                "expires_in_seconds": max_age,
                "read_only": True,
            },
            extra_headers={"Set-Cookie": cookie_val},
        )

    def _reject_mutation(self) -> None:
        ok, _, _ = self._validate_host_and_query()
        if not ok:
            return
        self._send_json(
            HTTPStatus.METHOD_NOT_ALLOWED,
            {
                "error": "read_only_dashboard",
                "message": "Dashboard API is strictly read-only. Use CLI/TUI for changes.",
            },
            extra_headers={"Allow": "GET"},
        )

    do_PUT = _reject_mutation
    do_DELETE = _reject_mutation
    do_PATCH = _reject_mutation


def make_server(
    engine: Any,
    host: str | int = "127.0.0.1",
    port: int = 0,
    *,
    auth: Any | None = None,
    session_ttl_seconds: int = DEFAULT_IDLE_SESSION_SECONDS,
    absolute_session_seconds: int = DEFAULT_ABSOLUTE_SESSION_SECONDS,
    max_failed_logins: int = 5,
    rate_limit_window_seconds: int = 60,
    clock: Callable[[], float] | None = None,
) -> CustodianDashboardServer:
    """Create a loopback-bound CustodianDashboardServer without starting its loop."""
    if isinstance(host, int):
        port = host
        host = "127.0.0.1"
    validated_host = _validate_loopback_host(host)
    resolved_auth = _resolve_auth(engine, auth)
    bind_ip = "::1" if validated_host == "::1" else "127.0.0.1"
    return CustodianDashboardServer(
        (bind_ip, int(port)),
        _DashboardRequestHandler,
        engine=engine,
        auth=resolved_auth,
        requested_host=validated_host,
        session_ttl_seconds=session_ttl_seconds,
        absolute_session_seconds=absolute_session_seconds,
        max_failed_logins=max_failed_logins,
        rate_limit_window_seconds=rate_limit_window_seconds,
        clock=clock,
    )


def run_dashboard(
    engine: Any,
    host: str = "127.0.0.1",
    port: int = 0,
    *,
    auth: Any | None = None,
    output: TextIO | None = None,
    _on_ready: Callable[[CustodianDashboardServer], None] | None = None,
) -> None:
    """Run the loopback dashboard until interrupted (Ctrl-C), then close cleanly."""
    out = output if output is not None else sys.stdout
    srv = make_server(engine, host=host, port=port, auth=auth)
    try:
        out.write(f"Hermes Custodian Dashboard URL: {srv.base_url}\n")
        out.flush()
        if _on_ready is not None:
            _on_ready(srv)
        srv.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
