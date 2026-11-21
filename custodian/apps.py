"""Installed Hermes plugins, MCP servers, OS apps/packages discovery and safe updates.

Security invariants:
- Never scans ~/.hermes or $HERMES_HOME without explicit consented settings['hermes_root'].
- Uses strict per-manager allowlist validation for update targets (forbids trailing -/+, .., /, :).
- Never escalates a missing target_name on singular update targets to a full upgrade.
- All subprocess calls resolve binaries from trusted minimal_env PATHs, pass stdin=DEVNULL,
  and never use shell=True.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
from typing import Any

from . import _platform
from ._subprocess_env import minimal_env
from . import policy as _policy

_APT_PKG_RE = re.compile(r"^[a-z0-9](?:[a-z0-9.+-]{0,126}[a-z0-9])?(?::[a-z0-9][a-z0-9-]{0,15})?$")
_FLATPAK_ID_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_-]{0,63}(?:\.[A-Za-z0-9_-]{1,64})+$")
_BREW_PKG_RE = re.compile(r"^[a-z0-9][a-z0-9@._-]{0,127}$")
_PLUGIN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def _sanitise(text: str) -> str:
    return _policy.sanitise_text(str(text))


def _trusted_which(name: str, env_cmd: str) -> str | None:
    trusted_path = minimal_env(env_cmd).get("PATH", "")
    found = shutil.which(name, path=trusted_path)
    if found and not _platform.IS_WINDOWS:
        try:
            st = os.stat(found)
            if not stat.S_ISREG(st.st_mode) or (st.st_mode & 0o022):
                return None
        except OSError:
            return None
    if found:
        return found
    # For user-installed Hermes CLI only: allow ~/.local/bin/hermes if owned by current user & not group/world-writable
    if name == "hermes" and not _platform.IS_WINDOWS:
        cand = Path.home() / ".local" / "bin" / "hermes"
        try:
            st = os.stat(cand)
            if stat.S_ISREG(st.st_mode) and st.st_uid == os.getuid() and not (st.st_mode & 0o022) and os.access(cand, os.X_OK):
                return str(cand)
        except OSError:
            pass
    return None


def _validate_target_name(target_type: str, target_name: str | None) -> tuple[bool, str]:
    """Validate package/plugin name strictly per package manager."""
    singular_types = {"hermes_plugin", "os_package", "flatpak", "brew"}
    if target_type in singular_types:
        if not isinstance(target_name, str) or not target_name:
            return False, f"target_name is required for {target_type}."
    elif target_name is None:
        return True, ""

    if not isinstance(target_name, str) or len(target_name) > 128:
        return False, "Invalid package or plugin name."
    if ".." in target_name or "/" in target_name or "\\" in target_name or "://" in target_name:
        return False, "Package or plugin name contains forbidden path/URL characters."
    if target_name.startswith("-") or target_name.endswith(("-", "+")):
        return False, "Package or plugin name must not start with '-' or end with '-'/'+'."

    if target_type == "os_package":
        if _platform.NAME == "linux":
            if not _APT_PKG_RE.fullmatch(target_name):
                return False, "Invalid APT package name."
        elif not _PLUGIN_ID_RE.fullmatch(target_name):
            return False, "Invalid package identifier."
    elif target_type == "flatpak":
        if not _FLATPAK_ID_RE.fullmatch(target_name):
            return False, "Invalid Flatpak application ID."
    elif target_type == "brew":
        if not _BREW_PKG_RE.fullmatch(target_name):
            return False, "Invalid Homebrew formula name."
    elif target_type == "hermes_plugin":
        if not _PLUGIN_ID_RE.fullmatch(target_name):
            return False, "Invalid Hermes plugin ID."
    return True, ""


def _read_bounded_file(path: Path, max_bytes: int = 32768) -> bytes | None:
    try:
        return _platform.read_file_nofollow(path, max_bytes=max_bytes)
    except (OSError, ValueError):
        return None


def _parse_yaml_metadata(raw: bytes) -> dict[str, str]:
    """Safely parse plugin.yaml via PyYAML (rejecting aliases/tags) with simple fallback."""
    fields: dict[str, str] = {}
    try:
        import yaml
        for token in yaml.scan(raw):
            if isinstance(token, (yaml.tokens.AliasToken, yaml.tokens.AnchorToken, yaml.tokens.TagToken)):
                return {}
        data = yaml.safe_load(raw)
        if isinstance(data, dict):
            for key in ("name", "version", "description", "author", "repository", "homepage", "source"):
                val = data.get(key)
                if isinstance(val, (str, int, float)):
                    cleaned = " ".join(_sanitise(str(val)).split())[:200]
                    if cleaned:
                        fields[key] = cleaned
            return fields
    except Exception:
        pass
    text = raw.decode("utf-8", errors="ignore")
    for line in text.splitlines()[:80]:
        if not line or line.startswith((" ", "\t", "#")) or ":" not in line:
            continue
        key, raw_val = line.split(":", 1)
        key = key.strip().lower()
        val = raw_val.split("#", 1)[0].strip().strip("\"'")
        if val in (">", "|", ">-", "|-"):
            continue
        if key in ("name", "version", "description", "author", "repository", "homepage", "source") and val:
            fields[key] = _sanitise(val)[:200]
    return fields


def _scrub_remote_url(raw_url: str) -> str:
    url = re.sub(r"://[^/@]+@", "://", raw_url.strip())
    url = url.split("?", 1)[0].split("#", 1)[0]
    return _sanitise(url)[:200]


def _read_plugin_metadata(plugin_dir: Path, *, has_hermes_cli: bool) -> dict[str, Any]:
    """Read safe metadata from a plugin directory (plugin.yaml, manifest.json, pyproject.toml)."""
    plugin_id = _sanitise(plugin_dir.name)
    meta: dict[str, Any] = {
        "id": plugin_id,
        "name": plugin_id,
        "version": "unknown",
        "description": "",
        "source": "local",
        "path": _sanitise(str(plugin_dir)),
        "git_backed": False,
        "updatable": False,
        "kind": "hermes_plugin",
    }

    for yaml_name in ("plugin.yaml", "plugin.yml"):
        raw = _read_bounded_file(plugin_dir / yaml_name, max_bytes=32768)
        if raw is not None:
            fields = _parse_yaml_metadata(raw)
            if fields.get("name"):
                meta["name"] = fields["name"]
            if fields.get("version"):
                meta["version"] = fields["version"]
            if fields.get("description"):
                meta["description"] = fields["description"]
            if fields.get("repository") or fields.get("source"):
                meta["source"] = fields.get("repository") or fields.get("source")
            break

    raw_manifest = _read_bounded_file(plugin_dir / "manifest.json", max_bytes=32768)
    if raw_manifest is not None:
        try:
            data = json.loads(raw_manifest.decode("utf-8", errors="ignore"))
            if isinstance(data, dict):
                if isinstance(data.get("name"), str) and data["name"].strip():
                    meta["name"] = _sanitise(data["name"].strip())[:128]
                if isinstance(data.get("version"), str) and data["version"].strip():
                    meta["version"] = _sanitise(data["version"].strip())[:64]
                if isinstance(data.get("description"), str) and data["description"].strip():
                    meta["description"] = _sanitise(data["description"].strip())[:200]
        except ValueError:
            pass

    if meta["version"] == "unknown":
        raw_pyproj = _read_bounded_file(plugin_dir / "pyproject.toml", max_bytes=32768)
        if raw_pyproj is not None:
            text = raw_pyproj.decode("utf-8", errors="ignore")
            m = re.search(r'(?m)^version\s*=\s*["\']([^"\']+)["\']', text)
            if m:
                meta["version"] = _sanitise(m.group(1))[:64]

    git_dir = plugin_dir / ".git"
    if git_dir.is_dir() and not git_dir.is_symlink():
        meta["git_backed"] = True
        meta["updatable"] = True
        git_bin = _trusted_which("git", "git")
        if git_bin:
            try:
                res = subprocess.run(
                    [git_bin, "-C", str(plugin_dir), "config", "--get", "remote.origin.url"],
                    stdin=subprocess.DEVNULL,
                    capture_output=True, text=True, timeout=3, check=False, env=minimal_env("git"),
                )
                if res.returncode == 0 and res.stdout.strip():
                    meta["source"] = _scrub_remote_url(res.stdout)
            except (OSError, subprocess.SubprocessError):
                pass

    if has_hermes_cli and _PLUGIN_ID_RE.fullmatch(plugin_id):
        meta["updatable"] = True

    return meta


def discover_hermes_plugins(
    settings: dict[str, Any] | None = None,
    inventory_data: dict[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], bool]:
    """Discover installed Hermes plugins & MCP servers ONLY from consented hermes_root.

    Returns (plugins, mcp_servers, discovery_approved).
    """
    plugins_by_id: dict[str, dict[str, Any]] = {}
    mcp_servers: list[dict[str, Any]] = []
    seen_mcp: set[tuple[str, str]] = set()
    has_hermes_cli = bool(_trusted_which("hermes", "hermes"))

    consented_root: Path | None = None
    if isinstance(settings, dict):
        raw_root = settings.get("hermes_root")
        if isinstance(raw_root, str) and raw_root.strip():
            cand = Path(raw_root.strip())
            if cand.is_absolute() and ".." not in cand.parts and not cand.is_symlink():
                consented_root = cand

    discovery_approved = bool(
        consented_root is not None
        or (isinstance(inventory_data, dict) and inventory_data.get("discovery_approved"))
    )

    if not discovery_approved:
        return [], [], False

    # 1. From consented inventory profiles (enabled plugins & MCP servers)
    enabled_names: set[str] = set()
    if isinstance(inventory_data, dict):
        for prof in inventory_data.get("profiles") or []:
            if not isinstance(prof, dict):
                continue
            prof_name = _sanitise(prof.get("name") or "default")
            meta_obj = prof.get("metadata") if isinstance(prof.get("metadata"), dict) else {}
            prof_plugins = prof.get("plugins") or meta_obj.get("plugins") or []
            prof_mcps = prof.get("mcp_servers") or meta_obj.get("mcp_servers") or []
            for pname in prof_plugins:
                clean = _sanitise(str(pname))
                enabled_names.add(clean)
                plugins_by_id.setdefault(clean, {
                    "id": clean,
                    "name": clean,
                    "version": "installed",
                    "description": f"Configured in profile '{prof_name}'",
                    "source": "hermes config",
                    "path": _sanitise(prof.get("path") or ""),
                    "enabled": True,
                    "git_backed": False,
                    "updatable": has_hermes_cli and bool(_PLUGIN_ID_RE.fullmatch(clean)),
                    "kind": "hermes_plugin",
                })
            for mname in prof_mcps:
                clean_m = _sanitise(str(mname))
                key = (clean_m, prof_name)
                if key not in seen_mcp:
                    seen_mcp.add(key)
                    mcp_servers.append({
                        "name": clean_m,
                        "profile": prof_name,
                        "status": "configured",
                        "kind": "mcp_server",
                    })

    # 2. Scan plugins/ directory strictly inside consented hermes_root
    if consented_root is not None:
        plugins_dir = consented_root / "plugins"
        if plugins_dir.is_dir() and not plugins_dir.is_symlink():
            try:
                for child in sorted(plugins_dir.iterdir()):
                    if not child.is_dir() or child.is_symlink() or child.name.startswith("."):
                        continue
                    meta = _read_plugin_metadata(child, has_hermes_cli=has_hermes_cli)
                    if enabled_names:
                        meta["enabled"] = (meta["id"] in enabled_names) or (meta["name"] in enabled_names)
                    else:
                        meta["enabled"] = True
                    plugins_by_id[meta["id"]] = meta
            except OSError:
                pass

    return sorted(plugins_by_id.values(), key=lambda x: x["name"].lower()), mcp_servers, True


def _discover_linux_apps(upgradable_map: dict[str, dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
    apps: list[dict[str, Any]] = []
    managers: list[str] = []

    # 1. APT / dpkg (prioritize upgradable + manually installed packages)
    dpkg_bin = _trusted_which("dpkg-query", "apt")
    if dpkg_bin:
        managers.append("apt")
        manual_pkgs: set[str] = set()
        apt_mark = _trusted_which("apt-mark", "apt")
        if apt_mark:
            try:
                res_m = subprocess.run(
                    [apt_mark, "showmanual"],
                    stdin=subprocess.DEVNULL,
                    capture_output=True, text=True, timeout=5, check=False, env=minimal_env("apt"),
                )
                if res_m.returncode == 0:
                    manual_pkgs = {line.strip() for line in res_m.stdout.splitlines() if line.strip()}
            except (OSError, subprocess.SubprocessError):
                pass
        seen_apt: set[str] = set()
        try:
            res = subprocess.run(
                [dpkg_bin, "-W", "-f=${Package}\t${Version}\t${db:Status-Abbrev}\t${Section}\n"],
                stdin=subprocess.DEVNULL,
                capture_output=True, text=True, timeout=10, check=False, env=minimal_env("apt"),
            )
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    parts = line.split("\t")
                    if len(parts) < 3:
                        continue
                    pkg_name, version, status = parts[0].strip(), parts[1].strip(), parts[2].strip()
                    section = parts[3].strip() if len(parts) > 3 else ""
                    if not status.startswith("ii") or pkg_name in seen_apt:
                        continue
                    upd = upgradable_map.get(pkg_name)
                    is_manual = pkg_name in manual_pkgs if manual_pkgs else not pkg_name.startswith("lib")
                    if not upd and not is_manual:
                        continue
                    seen_apt.add(pkg_name)
                    apps.append({
                        "name": _sanitise(pkg_name),
                        "manager": "apt",
                        "installed_version": _sanitise(version),
                        "candidate_version": _sanitise(upd["candidate_version"]) if upd else None,
                        "update_available": bool(upd),
                        "security": upd.get("security") if upd else None,
                        "section": _sanitise(section),
                        "kind": "os_package",
                    })
        except (OSError, subprocess.SubprocessError):
            pass

        for pkg_name, upd in upgradable_map.items():
            if pkg_name not in seen_apt:
                seen_apt.add(pkg_name)
                apps.append({
                    "name": _sanitise(pkg_name),
                    "manager": "apt",
                    "installed_version": _sanitise(upd.get("installed_version") or "—"),
                    "candidate_version": _sanitise(upd.get("candidate_version") or "—"),
                    "update_available": True,
                    "security": upd.get("security"),
                    "section": "",
                    "kind": "os_package",
                })

    # 2. Flatpak apps (preserve user vs system installation)
    flatpak_bin = _trusted_which("flatpak", "flatpak")
    if flatpak_bin:
        managers.append("flatpak")
        try:
            res = subprocess.run(
                [flatpak_bin, "list", "--app", "--columns=application,name,version,installation"],
                stdin=subprocess.DEVNULL,
                capture_output=True, text=True, timeout=5, check=False, env=minimal_env("flatpak"),
            )
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    parts = line.split("\t")
                    if len(parts) < 2:
                        continue
                    app_id = parts[0].strip()
                    display = parts[1].strip() or app_id
                    version = parts[2].strip() if len(parts) > 2 and parts[2].strip() else "installed"
                    install_scope = parts[3].strip().lower() if len(parts) > 3 and parts[3].strip() else "system"
                    apps.append({
                        "name": _sanitise(display),
                        "package_id": _sanitise(app_id),
                        "manager": "flatpak",
                        "installation": "user" if "user" in install_scope else "system",
                        "installed_version": _sanitise(version),
                        "candidate_version": None,
                        "update_available": False,
                        "security": None,
                        "section": "desktop app",
                        "kind": "os_package",
                    })
        except (OSError, subprocess.SubprocessError):
            pass

    # 3. Snap apps (only query if snapd socket exists, with short 2.5s timeout so API never hangs)
    snap_bin = _trusted_which("snap", "snap")
    if snap_bin and Path("/run/snapd.socket").exists():
        managers.append("snap")
        try:
            res = subprocess.run(
                [snap_bin, "list"],
                stdin=subprocess.DEVNULL,
                capture_output=True, text=True, timeout=2.5, check=False, env=minimal_env("snap"),
            )
            if res.returncode == 0:
                lines = res.stdout.splitlines()
                for line in lines[1:]:
                    cols = line.split()
                    if len(cols) >= 2:
                        apps.append({
                            "name": _sanitise(cols[0]),
                            "manager": "snap",
                            "installed_version": _sanitise(cols[1]),
                            "candidate_version": None,
                            "update_available": False,
                            "security": None,
                            "section": "snap",
                            "kind": "os_package",
                        })
        except (OSError, subprocess.SubprocessError):
            pass

    return apps, managers


def _discover_macos_apps(upgradable_map: dict[str, dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
    apps: list[dict[str, Any]] = []
    managers: list[str] = []
    brew_bin = _trusted_which("brew", "brew")
    if brew_bin:
        managers.append("brew")
        try:
            res = subprocess.run(
                [brew_bin, "list", "--versions"],
                stdin=subprocess.DEVNULL,
                capture_output=True, text=True, timeout=10, check=False, env=minimal_env("brew"),
            )
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        apps.append({
                            "name": _sanitise(parts[0]),
                            "manager": "brew",
                            "installed_version": _sanitise(parts[-1]),
                            "candidate_version": None,
                            "update_available": False,
                            "security": None,
                            "section": "homebrew",
                            "kind": "os_package",
                        })
        except (OSError, subprocess.SubprocessError):
            pass

    apps_dir = Path("/Applications")
    if apps_dir.is_dir():
        managers.append("applications")
        try:
            for item in sorted(apps_dir.iterdir()):
                if item.name.endswith(".app"):
                    apps.append({
                        "name": _sanitise(item.name[:-4]),
                        "manager": "macos_app",
                        "installed_version": "installed",
                        "candidate_version": None,
                        "update_available": False,
                        "security": None,
                        "section": "Application",
                        "kind": "os_package",
                    })
        except OSError:
            pass

    for pkg_name, upd in upgradable_map.items():
        apps.append({
            "name": _sanitise(pkg_name),
            "manager": "softwareupdate",
            "installed_version": _sanitise(upd.get("installed_version") or "—"),
            "candidate_version": _sanitise(upd.get("candidate_version") or "—"),
            "update_available": True,
            "security": upd.get("security"),
            "section": "OS update",
            "kind": "os_package",
        })

    return apps, managers


def _discover_windows_apps(upgradable_map: dict[str, dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
    apps: list[dict[str, Any]] = []
    managers: list[str] = []
    for pkg_name, upd in upgradable_map.items():
        apps.append({
            "name": _sanitise(pkg_name),
            "manager": "windowsupdate",
            "installed_version": _sanitise(upd.get("installed_version") or "—"),
            "candidate_version": _sanitise(upd.get("candidate_version") or "—"),
            "update_available": True,
            "security": upd.get("security"),
            "section": "Windows Update",
            "kind": "os_package",
        })
    if upgradable_map:
        managers.append("windowsupdate")
    return apps, managers


def discover_installed_apps(
    settings: dict[str, Any] | None = None,
    *,
    inventory_data: dict[str, Any] | None = None,
    updates_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return installed Hermes plugins, MCP servers, and OS apps/packages."""
    hermes_plugins, mcp_servers, discovery_approved = discover_hermes_plugins(settings, inventory_data)

    upgradable_map: dict[str, dict[str, Any]] = {}
    if isinstance(updates_data, dict):
        for pkg in updates_data.get("packages") or []:
            if isinstance(pkg, dict) and pkg.get("name"):
                upgradable_map[str(pkg["name"])] = pkg

    if _platform.NAME == "macos":
        os_apps, managers = _discover_macos_apps(upgradable_map)
    elif _platform.NAME == "windows":
        os_apps, managers = _discover_windows_apps(upgradable_map)
    else:
        os_apps, managers = _discover_linux_apps(upgradable_map)

    os_apps.sort(key=lambda a: (
        0 if a.get("security") is True else (1 if a.get("update_available") else 2),
        a["name"].lower(),
    ))

    total_os_apps = len(os_apps)
    updatable_count = sum(1 for a in os_apps if a.get("update_available"))
    security_count = sum(1 for a in os_apps if a.get("security") is True)

    return {
        "discovery_approved": discovery_approved,
        "hermes_plugins": hermes_plugins,
        "mcp_servers": mcp_servers,
        "os_apps": os_apps[:500],
        "managers": managers,
        "summary": {
            "plugins_count": len(hermes_plugins),
            "mcp_count": len(mcp_servers),
            "os_apps_count": total_os_apps,
            "os_apps_shown": min(total_os_apps, 500),
            "updatable_count": updatable_count,
            "security_updates_count": security_count,
        },
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


def run_update(
    target_type: str,
    target_name: str | None = None,
    *,
    settings: dict[str, Any] | None = None,
    inventory_data: dict[str, Any] | None = None,
    installation: str | None = None,
) -> dict[str, Any]:
    """Execute a safe, allowlisted update for a Hermes plugin, Flatpak/Brew app, or OS package.

    Never uses shell=True, passes stdin=DEVNULL, and validates target_name strictly per manager.
    """
    allowed_types = {"hermes_plugin", "hermes_plugins_all", "flatpak", "brew", "os_package", "os_all"}
    if target_type not in allowed_types:
        return {"ok": False, "status": "invalid", "message": f"Unsupported update target type: {target_type}"}

    valid, err_msg = _validate_target_name(target_type, target_name)
    if not valid:
        return {"ok": False, "status": "invalid", "message": err_msg}

    # 1. Hermes plugin updates (single or all)
    if target_type in ("hermes_plugin", "hermes_plugins_all"):
        plugins, _, approved = discover_hermes_plugins(settings, inventory_data)
        if not approved:
            return {
                "ok": False,
                "status": "denied",
                "message": "Hermes root discovery is not approved in setup. Approve hermes_root via 'warden setup' first.",
            }
        hermes_bin = _trusted_which("hermes", "hermes")
        if hermes_bin:
            if target_type == "hermes_plugin":
                argv = [hermes_bin, "plugins", "update", "--", str(target_name)]
            else:
                argv = [hermes_bin, "plugins", "update", "--yes"]
            try:
                res = subprocess.run(
                    argv, stdin=subprocess.DEVNULL,
                    capture_output=True, text=True, timeout=60, check=False, env=minimal_env("hermes"),
                )
                out = _sanitise((res.stdout or "") + ("\n" + res.stderr if res.stderr else "")).strip()[:2000]
                if res.returncode == 0:
                    return {
                        "ok": True,
                        "status": "updated",
                        "message": out or f"Updated {target_name or 'all Hermes plugins'} successfully.",
                        "command": " ".join(shlex.quote(a) for a in argv),
                    }
                return {
                    "ok": False,
                    "status": "failed",
                    "message": out or f"hermes plugins update exited with code {res.returncode}.",
                    "command": " ".join(shlex.quote(a) for a in argv),
                }
            except (OSError, subprocess.TimeoutExpired) as exc:
                return {"ok": False, "status": "failed", "message": f"Plugin update failed: {exc}"}

        # Fallback: git pull --ff-only for git-backed plugin directories under consented hermes_root
        consented_root = Path(settings["hermes_root"]) if (isinstance(settings, dict) and settings.get("hermes_root")) else None
        targets = [
            p for p in plugins
            if p.get("git_backed") and (target_type == "hermes_plugins_all" or p["id"] == target_name or p["name"] == target_name)
        ]
        git_bin = _trusted_which("git", "git")
        if not targets or not git_bin or consented_root is None:
            cmd = f"hermes plugins update {shlex.quote(str(target_name))}" if target_name else "hermes plugins update"
            return {
                "ok": False,
                "status": "unavailable",
                "message": "Hermes CLI not found and plugin is not git-backed. Run the command in your terminal.",
                "command": cmd,
            }
        results = []
        all_ok = True
        for p in targets:
            plugin_path = consented_root / "plugins" / p["id"]
            if not plugin_path.is_dir() or plugin_path.is_symlink():
                continue
            try:
                res = subprocess.run(
                    [git_bin, "-C", str(plugin_path), "-c", "core.hooksPath=/dev/null", "-c", "credential.helper=", "pull", "--ff-only"],
                    stdin=subprocess.DEVNULL,
                    capture_output=True, text=True, timeout=45, check=False, env=minimal_env("git"),
                )
                msg = _sanitise((res.stdout or res.stderr or "").strip())[:400]
                if res.returncode != 0:
                    all_ok = False
                results.append(f"{p['name']}: {msg or ('ok' if res.returncode == 0 else 'failed')}")
            except (OSError, subprocess.TimeoutExpired) as exc:
                all_ok = False
                results.append(f"{p['name']}: {exc}")
        return {
            "ok": all_ok,
            "status": "updated" if all_ok else "failed",
            "message": "\n".join(results),
        }

    # 2. Flatpak app update (respect user vs system installation)
    if target_type == "flatpak":
        flatpak_bin = _trusted_which("flatpak", "flatpak")
        if not flatpak_bin:
            return {"ok": False, "status": "unavailable", "message": "flatpak is not installed."}
        if installation == "system":
            cmd_str = f"sudo flatpak update -y {shlex.quote(str(target_name))}"
            return {
                "ok": False,
                "status": "needs_elevation",
                "message": "System-wide Flatpak apps require administrator privileges. Run this command in your terminal:",
                "command": cmd_str,
            }
        argv = [flatpak_bin, "update", "--user", "-y", "--", str(target_name)]
        try:
            res = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120, check=False, env=minimal_env("flatpak"))
            out = _sanitise((res.stdout or "") + ("\n" + res.stderr if res.stderr else "")).strip()[:2000]
            return {
                "ok": res.returncode == 0,
                "status": "updated" if res.returncode == 0 else "failed",
                "message": out or ("Flatpak updated." if res.returncode == 0 else "Flatpak update failed."),
                "command": " ".join(shlex.quote(a) for a in argv),
            }
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {"ok": False, "status": "failed", "message": f"Flatpak update failed: {exc}"}

    # 3. Homebrew update
    if target_type == "brew":
        brew_bin = _trusted_which("brew", "brew")
        if not brew_bin:
            return {"ok": False, "status": "unavailable", "message": "Homebrew is not installed."}
        argv = [brew_bin, "upgrade", "--", str(target_name)]
        try:
            res = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120, check=False, env=minimal_env("brew"))
            out = _sanitise((res.stdout or "") + ("\n" + res.stderr if res.stderr else "")).strip()[:2000]
            return {
                "ok": res.returncode == 0,
                "status": "updated" if res.returncode == 0 else "failed",
                "message": out or ("Homebrew updated." if res.returncode == 0 else "Homebrew update failed."),
                "command": " ".join(shlex.quote(a) for a in argv),
            }
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {"ok": False, "status": "failed", "message": f"Homebrew update failed: {exc}"}

    # 4. OS package / system update
    if _platform.NAME == "linux":
        apt_get = _trusted_which("apt-get", "apt")
        if not apt_get:
            return {
                "ok": False,
                "status": "unavailable",
                "message": "APT (apt-get) was not found on this Linux distribution. Use your system package manager in a terminal.",
            }
        non_interactive_opts = [
            "-o", "Dpkg::Options::=--force-confdef",
            "-o", "Dpkg::Options::=--force-confold",
        ]
        if target_type == "os_package" and target_name:
            cmd_str = f"sudo apt-get update && sudo apt-get install --only-upgrade -y -- {shlex.quote(target_name)}"
            apt_argv = [apt_get, *non_interactive_opts, "install", "--only-upgrade", "-y", "--", target_name]
        else:
            cmd_str = "sudo apt-get update && sudo apt-get upgrade -y"
            apt_argv = [apt_get, *non_interactive_opts, "upgrade", "-y"]

        has_desktop = bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
        pkexec_bin = _trusted_which("pkexec", "pkexec-apt") if has_desktop else None

        if pkexec_bin:
            try:
                res = subprocess.run(
                    [pkexec_bin, *apt_argv],
                    stdin=subprocess.DEVNULL,
                    capture_output=True, text=True, timeout=180, check=False, env=minimal_env("pkexec-apt"),
                )
                out = _sanitise((res.stdout or "") + ("\n" + res.stderr if res.stderr else "")).strip()[:2000]
                if res.returncode == 0:
                    return {"ok": True, "status": "updated", "message": out or "OS packages updated.", "command": cmd_str}
                return {
                    "ok": False,
                    "status": "needs_elevation" if res.returncode in (126, 127) else "failed",
                    "message": out or "Administrator authorization was cancelled or failed. You can run the command in a terminal.",
                    "command": cmd_str,
                }
            except (OSError, subprocess.TimeoutExpired) as exc:
                return {"ok": False, "status": "failed", "message": str(exc), "command": cmd_str}

        return {
            "ok": False,
            "status": "needs_elevation",
            "message": "OS package updates require administrator (root) privileges. Copy and run this command in your terminal:",
            "command": cmd_str,
        }

    if _platform.NAME == "macos":
        cmd_str = f"sudo softwareupdate -i {shlex.quote(str(target_name))}" if target_name else "sudo softwareupdate -i -a"
        return {
            "ok": False,
            "status": "needs_elevation",
            "message": "macOS system updates require administrator privileges. Run this command in your terminal:",
            "command": cmd_str,
        }

    return {
        "ok": False,
        "status": "needs_elevation",
        "message": "Install Windows updates from Settings → Windows Update or an elevated PowerShell terminal.",
        "command": "winget upgrade --all",
    }
