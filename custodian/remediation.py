"""Quarantine, false-positive allowlist, custom IOC blocklist, on-demand target scan, and report export.

All state files are written atomically with private permissions (0600 / private ACLs).
Privacy invariant: sensitive credential/memory/chat paths (custodian.policy.is_sensitive)
are never read, scanned, or quarantined.
"""
from __future__ import annotations

import csv
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import stat
import time
from typing import Any

from . import _platform
from . import policy as _policy
from . import scanner as _scanner

_QID_RE = re.compile(r"^[0-9a-f]{32}$")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_MAX_QUARANTINE_FILE_BYTES = 50 * 1024 * 1024
_MAX_QUARANTINE_ITEMS = 500
_MAX_ALLOWLIST_ITEMS = 500
_MAX_IOC_ITEMS = 5000


def _sanitise(text: Any) -> str:
    return _policy.sanitise_text(str(text))


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _quarantine_dir(state_dir: Path) -> Path:
    qdir = Path(state_dir) / "quarantine"
    _platform.ensure_private_dir(qdir)
    return qdir


def _load_private_json(path: Path, default: Any, max_bytes: int = 2 * 1024 * 1024) -> Any:
    if not os.path.lexists(path):
        return default
    raw = _platform.read_private_file(path, max_bytes=max_bytes)
    return json.loads(raw.decode("utf-8"))


def _save_private_json(path: Path, data: Any) -> None:
    payload = json.dumps(data, indent=2, sort_keys=True).encode("utf-8")
    _platform.atomic_write_private_file(path, payload)


# --- Quarantine ------------------------------------------------------------

def list_quarantine(state_dir: Path) -> list[dict[str, Any]]:
    manifest_path = Path(state_dir) / "quarantine" / "manifest.json"
    if not os.path.lexists(manifest_path):
        return []
    try:
        data = _load_private_json(manifest_path, {"schema_version": 1, "items": []})
        items = data.get("items", []) if isinstance(data, dict) else []
        return [item for item in items if isinstance(item, dict)]
    except (OSError, ValueError, UnicodeError):
        return []


def quarantine_file(
    state_dir: Path,
    raw_path: str,
    *,
    allowed_roots: list[Path],
    finding_id: str | None = None,
    reason: str = "",
) -> dict[str, Any]:
    """Move a flagged non-sensitive regular file within approved roots into private quarantine."""
    if not isinstance(raw_path, str) or not raw_path.strip():
        raise ValueError("Target path is required.")
    target = Path(raw_path)
    if not target.is_absolute() or ".." in target.parts:
        raise ValueError("Target path must be an absolute path without traversal.")
    state_root = Path(os.path.abspath(state_dir))
    if target == state_root or state_root in target.parents:
        raise ValueError("Cannot quarantine files inside Warden state directory.")
    if not any(target != root and root in target.parents for root in allowed_roots):
        raise ValueError("Target path must be inside an approved watched scope.")
    if _policy.is_sensitive(target):
        raise ValueError("Sensitive credential, memory, or private paths cannot be quarantined.")

    qdir = _quarantine_dir(state_root)
    items = list_quarantine(state_root)
    if len(items) >= _MAX_QUARANTINE_ITEMS:
        raise ValueError("Quarantine capacity limit reached; delete old entries first.")

    # Read target safely (no symlink traversal, regular single-linked file only)
    orig_mode = 0o600
    if _platform.IS_WINDOWS:
        data = _platform.read_file_nofollow(target, max_bytes=_MAX_QUARANTINE_FILE_BYTES)
        st = target.lstat()
        orig_mode = stat.S_IMODE(st.st_mode)
    else:
        with _platform.open_directory_nofollow(target.parent) as parent:
            fd = os.open(
                target.name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0),
                dir_fd=parent.fd,
            )
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode):
                    raise ValueError("Only regular files can be quarantined.")
                if info.st_nlink != 1:
                    raise ValueError("Hard-linked files cannot be quarantined automatically.")
                if info.st_size > _MAX_QUARANTINE_FILE_BYTES:
                    raise ValueError("File exceeds 50 MiB quarantine limit.")
                orig_mode = stat.S_IMODE(info.st_mode)
                chunks: list[bytes] = []
                remaining = info.st_size
                while remaining > 0:
                    chunk = os.read(fd, min(65536, remaining))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                data = b"".join(chunks)
            finally:
                os.close(fd)

            qid = secrets.token_hex(16)
            payload_path = qdir / f"{qid}.bin"
            _platform.atomic_write_private_file(payload_path, data)
            try:
                os.unlink(target.name, dir_fd=parent.fd)
            except OSError:
                try:
                    os.unlink(payload_path)
                except OSError:
                    pass
                raise

    if _platform.IS_WINDOWS:
        qid = secrets.token_hex(16)
        payload_path = qdir / f"{qid}.bin"
        _platform.atomic_write_private_file(payload_path, data)
        try:
            os.unlink(target)
        except OSError:
            try:
                os.unlink(payload_path)
            except OSError:
                pass
            raise

    entry = {
        "id": qid,
        "original_path": _sanitise(str(target)),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "original_mode": oct(orig_mode),
        "finding_id": _sanitise(finding_id)[:128] if finding_id else None,
        "reason": _sanitise(reason)[:240] or "Quarantined from dashboard",
        "quarantined_at": _now_iso(),
    }
    items.insert(0, entry)
    _save_private_json(qdir / "manifest.json", {"schema_version": 1, "items": items})
    return entry


def restore_quarantine(state_dir: Path, qid: str) -> dict[str, Any]:
    """Restore a quarantined file back to its original path (refuses overwrite or symlink traversal)."""
    if not isinstance(qid, str) or not _QID_RE.fullmatch(qid):
        raise ValueError("Invalid quarantine ID.")
    qdir = _quarantine_dir(Path(state_dir))
    items = list_quarantine(Path(state_dir))
    match = next((it for it in items if it.get("id") == qid), None)
    if match is None:
        raise ValueError("Quarantine record not found.")

    payload_path = qdir / f"{qid}.bin"
    data = _platform.read_private_file(payload_path, max_bytes=_MAX_QUARANTINE_FILE_BYTES)
    dest = Path(match["original_path"])
    if not dest.is_absolute() or ".." in dest.parts:
        raise ValueError("Stored destination path is invalid.")
    if os.path.lexists(dest):
        raise ValueError("A file already exists at the original path; move or delete it before restoring.")

    dest.parent.mkdir(parents=True, exist_ok=True)
    raw_mode = 0o600
    try:
        raw_mode = int(str(match.get("original_mode", "0o600")), 8) & 0o755
    except ValueError:
        raw_mode = 0o600
    if raw_mode == 0:
        raw_mode = 0o600

    if _platform.IS_WINDOWS:
        _platform.atomic_write_private_file(dest, data)
    else:
        with _platform.open_directory_nofollow(dest.parent) as parent:
            fd = os.open(
                dest.name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                raw_mode,
                dir_fd=parent.fd,
            )
            try:
                view = memoryview(data)
                while view:
                    written = os.write(fd, view)
                    if written <= 0:
                        raise OSError("Short write restoring quarantined file")
                    view = view[written:]
                os.fchmod(fd, raw_mode)
                os.fsync(fd)
            finally:
                os.close(fd)
            _platform.fsync_directory(dest.parent)

    try:
        os.unlink(payload_path)
    except FileNotFoundError:
        pass
    remaining = [it for it in items if it.get("id") != qid]
    _save_private_json(qdir / "manifest.json", {"schema_version": 1, "items": remaining})
    return match


def delete_quarantine(state_dir: Path, qid: str) -> dict[str, Any]:
    """Permanently delete a quarantined payload and remove its manifest entry."""
    if not isinstance(qid, str) or not _QID_RE.fullmatch(qid):
        raise ValueError("Invalid quarantine ID.")
    qdir = _quarantine_dir(Path(state_dir))
    items = list_quarantine(Path(state_dir))
    match = next((it for it in items if it.get("id") == qid), None)
    if match is None:
        raise ValueError("Quarantine record not found.")
    payload_path = qdir / f"{qid}.bin"
    try:
        os.unlink(payload_path)
    except FileNotFoundError:
        pass
    remaining = [it for it in items if it.get("id") != qid]
    _save_private_json(qdir / "manifest.json", {"schema_version": 1, "items": remaining})
    return match


# --- Allowlist (False-Positive Suppression) --------------------------------

def list_allowlist(state_dir: Path) -> list[dict[str, Any]]:
    path = Path(state_dir) / "allowlist.json"
    if not os.path.lexists(path):
        return []
    try:
        data = _load_private_json(path, {"schema_version": 1, "entries": []})
        entries = data.get("entries", []) if isinstance(data, dict) else []
        return [e for e in entries if isinstance(e, dict)]
    except (OSError, ValueError, UnicodeError):
        return []


def add_allowlist(
    state_dir: Path,
    *,
    finding_id: str | None = None,
    path: str = "",
    rule: str | None = None,
    reason: str = "",
) -> dict[str, Any]:
    if not finding_id and not path:
        raise ValueError("finding_id or path is required to allowlist a finding.")
    entries = list_allowlist(state_dir)
    if len(entries) >= _MAX_ALLOWLIST_ITEMS:
        raise ValueError("Allowlist capacity reached (500 entries).")
    clean_fid = _sanitise(finding_id)[:128] if finding_id else None
    clean_path = _sanitise(path)[:4096] if path else ""
    clean_rule = _sanitise(rule)[:128] if rule else None
    # Deduplicate existing identical rule
    for existing in entries:
        if (clean_fid and existing.get("finding_id") == clean_fid) or (
            clean_path and existing.get("path") == clean_path and existing.get("rule") == clean_rule
        ):
            return existing
    entry = {
        "id": secrets.token_hex(12),
        "finding_id": clean_fid,
        "path": clean_path,
        "rule": clean_rule,
        "reason": _sanitise(reason)[:240] or "Marked as false positive / ignored",
        "created_at": _now_iso(),
    }
    entries.insert(0, entry)
    _save_private_json(Path(state_dir) / "allowlist.json", {"schema_version": 1, "entries": entries})
    return entry


def remove_allowlist(state_dir: Path, entry_id: str) -> bool:
    if not isinstance(entry_id, str) or not re.fullmatch(r"[0-9a-f]{24}", entry_id):
        raise ValueError("Invalid allowlist entry ID.")
    entries = list_allowlist(state_dir)
    remaining = [e for e in entries if e.get("id") != entry_id]
    if len(remaining) == len(entries):
        return False
    _save_private_json(Path(state_dir) / "allowlist.json", {"schema_version": 1, "entries": remaining})
    return True


def is_finding_allowlisted(finding: dict[str, Any], entries: list[dict[str, Any]]) -> bool:
    if not entries:
        return False
    fid = finding.get("id")
    fpath = finding.get("path")
    frule = (finding.get("evidence") or {}).get("rule") if isinstance(finding.get("evidence"), dict) else None
    for e in entries:
        if e.get("finding_id") and e["finding_id"] == fid:
            return True
        if e.get("path") and e["path"] == fpath:
            erule = e.get("rule")
            if not erule or erule == frule:
                return True
    return False


# --- Custom IOC Blocklist Manager ------------------------------------------

def list_ioc_entries(state_dir: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for digest, desc in sorted(_scanner.BUILTIN_IOC_HASHES.items()):
        rows.append({"sha256": digest, "description": _sanitise(desc), "builtin": True})
    custom_path = Path(state_dir) / "ioc_blocklist.json"
    if os.path.lexists(custom_path):
        try:
            data = _load_private_json(custom_path, {"hashes": {}})
            raw_map = data.get("hashes", data) if isinstance(data, dict) else {}
            if isinstance(raw_map, dict):
                for h, desc in sorted(raw_map.items()):
                    if isinstance(h, str) and _SHA256_RE.fullmatch(h):
                        rows.append({
                            "sha256": h.lower(),
                            "description": _sanitise(desc)[:200],
                            "builtin": False,
                        })
        except (OSError, ValueError, UnicodeError):
            pass
    return rows


def add_ioc_hash(state_dir: Path, sha256_hex: str, description: str = "") -> dict[str, Any]:
    if not isinstance(sha256_hex, str) or not _SHA256_RE.fullmatch(sha256_hex.strip()):
        raise ValueError("SHA-256 hash must be exactly 64 hexadecimal characters.")
    digest = sha256_hex.strip().lower()
    desc = _sanitise(description).strip()[:200] or "Custom IOC blocklist hash"
    custom_path = Path(state_dir) / "ioc_blocklist.json"
    current: dict[str, str] = {}
    if os.path.lexists(custom_path):
        try:
            data = _load_private_json(custom_path, {"hashes": {}})
            raw_map = data.get("hashes", data) if isinstance(data, dict) else {}
            if isinstance(raw_map, dict):
                for k, v in raw_map.items():
                    if isinstance(k, str) and _SHA256_RE.fullmatch(k):
                        current[k.lower()] = _sanitise(v)[:200]
        except (OSError, ValueError, UnicodeError):
            current = {}
    if len(current) >= _MAX_IOC_ITEMS and digest not in current:
        raise ValueError("IOC blocklist limit reached (5,000 hashes).")
    current[digest] = desc
    _save_private_json(custom_path, {"schema_version": 1, "hashes": current})
    return {"sha256": digest, "description": desc, "builtin": False}


def remove_ioc_hash(state_dir: Path, sha256_hex: str) -> bool:
    if not isinstance(sha256_hex, str) or not _SHA256_RE.fullmatch(sha256_hex.strip()):
        raise ValueError("SHA-256 hash must be exactly 64 hexadecimal characters.")
    digest = sha256_hex.strip().lower()
    if digest in _scanner.BUILTIN_IOC_HASHES:
        raise ValueError("Built-in signatures cannot be removed.")
    custom_path = Path(state_dir) / "ioc_blocklist.json"
    if not os.path.lexists(custom_path):
        return False
    data = _load_private_json(custom_path, {"hashes": {}})
    raw_map = data.get("hashes", data) if isinstance(data, dict) else {}
    if not isinstance(raw_map, dict) or digest not in raw_map:
        return False
    del raw_map[digest]
    _save_private_json(custom_path, {"schema_version": 1, "hashes": raw_map})
    return True


# --- On-Demand Custom File / Folder Scan -----------------------------------

def scan_custom_target(
    target_str: str,
    settings: dict[str, Any],
    *,
    state_dir: Path,
) -> dict[str, Any]:
    """Run an immediate one-off AV/security scan on any absolute folder or regular file."""
    if not isinstance(target_str, str) or not target_str.strip() or len(target_str) > 4096:
        raise ValueError("Provide a valid absolute file or folder path.")
    if any(ord(c) < 32 or ord(c) == 127 for c in target_str):
        raise ValueError("Target path contains invalid control characters.")
    target = Path(target_str.strip()).expanduser()
    if not target.is_absolute() or ".." in target.parts or target == Path("/"):
        raise ValueError("Select a specific absolute path (not / and no .. traversal).")
    if any(part.is_symlink() for part in (target, *target.parents)):
        raise ValueError("Target path must not contain symlink components.")
    if not target.exists():
        raise ValueError("Target path does not exist.")
    state_root = Path(os.path.abspath(state_dir))
    if target == state_root or state_root in target.parents:
        raise ValueError("Warden state directory cannot be scanned.")
    if _policy.is_sensitive(target):
        raise ValueError("Sensitive credential, memory, or private paths are excluded from scanning.")

    t0 = time.monotonic()
    started = _now_iso()
    ioc_hashes = _scanner.load_ioc_hashes(state_root)
    allowlist = list_allowlist(state_root)
    max_file_bytes = min(int(settings.get("max_file_bytes", _scanner.MAX_SCAN_FILE_BYTES)), _scanner.MAX_SCAN_FILE_BYTES)

    if target.is_file():
        st = target.lstat()
        mode = stat.S_IMODE(st.st_mode)
        findings: list[dict[str, Any]] = []
        errors: list[str] = []
        if ((mode & stat.S_ISUID) and (mode & 0o111)) or ((mode & stat.S_ISGID) and (mode & 0o010)):
            findings.append({
                "id": _scanner._finding_id("suid_sgid_bit", str(target)),
                "severity": "high",
                "category": "privilege_escalation",
                "title": "Executable file has SUID/SGID privilege-escalation bit set",
                "path": _sanitise(str(target)),
                "evidence": {"detector": "metadata_audit", "mode": oct(mode), "category": "privilege_escalation"},
                "recommendation": "Verify why this executable has SUID/SGID bits set.",
                "first_seen": started,
                "last_seen": started,
                "status": "open",
            })
        raw = _scanner._safe_read_file(target, max_file_bytes)
        if raw is None and st.st_size > max_file_bytes:
            errors.append(f"File exceeds {max_file_bytes} byte inspection limit.")
        elif raw is not None:
            findings.extend(_scanner.scan_file_bytes(
                str(target), raw, ioc_hashes=ioc_hashes, started=started, scope_signature="ad-hoc", sanitise=_policy.sanitise_text
            ))
        findings = [f for f in findings if not is_finding_allowlisted(f, allowlist)]
        return {
            "ok": True,
            "target": _sanitise(str(target)),
            "kind": "file",
            "complete": len(errors) == 0,
            "files_checked": 1,
            "duration_ms": int((time.monotonic() - t0) * 1000),
            "findings": findings,
            "errors": errors,
        }

    if not target.is_dir():
        raise ValueError("Target must be a regular file or directory.")

    exclusions = list(settings.get("exclusions") or []) + [str(state_root)]
    max_files = min(int(settings.get("max_files", 5000)), 10000)
    snapshot = _policy.bounded_snapshot(target, exclusions=exclusions, max_files=max_files, max_file_bytes=max_file_bytes)
    files_map = {item["path"]: item for item in snapshot.get("files", [])}
    findings, sec_errors, av_summary = _scanner.scan_scope(
        [target],
        files_map,
        settings,
        state_dir=state_root,
        started=started,
        scope_signature="ad-hoc",
        policy_module=_policy,
    )
    findings = [f for f in findings if not is_finding_allowlisted(f, allowlist)]
    all_errors = [_sanitise(e) for e in (list(snapshot.get("errors") or []) + list(sec_errors))]
    return {
        "ok": True,
        "target": _sanitise(str(target)),
        "kind": "directory",
        "complete": bool(snapshot.get("complete") and av_summary.get("complete", True)),
        "files_checked": len(files_map),
        "duration_ms": int((time.monotonic() - t0) * 1000),
        "findings": findings,
        "errors": all_errors,
    }


# --- Report Export (JSON / CSV with formula neutralization) ----------------

def _csv_cell(value: Any) -> str:
    text = _sanitise("" if value is None else str(value)).replace("\r", " ").replace("\n", " ")
    if text and text[0] in ("=", "+", "-", "@", "\t"):
        return "'" + text
    return text


def build_report_csv(findings: list[dict[str, Any]]) -> bytes:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["id", "severity", "category", "status", "title", "path", "first_seen", "last_seen", "recommendation"])
    for f in findings:
        if not isinstance(f, dict):
            continue
        ev = f.get("evidence") if isinstance(f.get("evidence"), dict) else {}
        cat = f.get("category") or ev.get("category") or "security"
        writer.writerow([
            _csv_cell(f.get("id", "")),
            _csv_cell(f.get("severity", "")),
            _csv_cell(cat),
            _csv_cell(f.get("status", "")),
            _csv_cell(f.get("title", "")),
            _csv_cell(f.get("path", "")),
            _csv_cell(f.get("first_seen", "")),
            _csv_cell(f.get("last_seen", "")),
            _csv_cell(f.get("recommendation", "")),
        ])
    return buf.getvalue().encode("utf-8")
