"""Installed Hermes plugins, MCP servers, OS apps/packages discovery and safe updates."""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from typing import Any

from . import _platform
from ._subprocess_env import minimal_env
from . import policy as _policy

_SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+:/-]{0,127}$")


def _sanitise(text: str) -> str:
    return _policy.sanitise_text(str(text))


def _parse_simple_yaml_fields(text: str) -> dict[str, str]:
    """Extract top-level scalar fields from plugin.yaml without requiring PyYAML."""
    fields: dict[str, str] = {}
    for line in text.splitlines()[:80]:
        if not line or line.startswith((" ", "\t", "#")):
            continue
        if ":" not in line:
            continue
        key, raw_val = line.split(":", 1)
        key = key.strip().lower()
        val = raw_val.strip().strip("\"'")
        if key in ("name", "version", "description", "author", "repository", "homepage", "source") and val:
            fields[key] = _sanitise(val)[:200]
    return fields


def _read_plugin_metadata(plugin_dir: Path) -> dict[str, Any]:
    """Read safe metadata from a plugin directory (plugin.yaml, manifest.json, pyproject.toml)."""
    meta: dict[str, Any] = {
        "name": _sanitise(plugin_dir.name),
        "version": "unknown",
        "description": "",
        "source": "local",
        "path": _sanitise(str(plugin_dir)),
        "git_backed": False,
        "updatable": False,
        "kind": "hermes_plugin",
    }

    for yaml_name in ("plugin.yaml", "plugin.yml"):
        cand = plugin_dir / yaml_name
        if cand.is_file() and not cand.is_symlink():
            try:
                fields = _parse_simple_yaml_fields(cand.read_text(encoding="utf-8", errors="ignore")[:32768])
                if fields.get("name"):
                    meta["name"] = fields["name"]
                if fields.get("version"):
                    meta["version"] = fields["version"]
                if fields.get("description"):
                    meta["description"] = fields["description"]
                if fields.get("repository") or fields.get("source"):
                    meta["source"] = fields.get("repository") or fields.get("source")
            except OSError:
                pass
            break

    manifest = plugin_dir / "manifest.json"
    if manifest.is_file() and not manifest.is_symlink():
        try:
            data = json.loads(manifest.read_text(encoding="utf-8", errors="ignore")[:32768])
            if isinstance(data, dict):
                if isinstance(data.get("name"), str):
                    meta["name"] = _sanitise(data["name"])[:128]
                if isinstance(data.get("version"), str):
                    meta["version"] = _sanitise(data["version"])[:64]
                if isinstance(data.get("description"), str):
                    meta["description"] = _sanitise(data["description"])[:200]
        except (OSError, ValueError):
            pass

    pyproject = plugin_dir / "pyproject.toml"
    if meta["version"] == "unknown" and pyproject.is_file() and not pyproject.is_symlink():
        try:
            text = pyproject.read_text(encoding="utf-8", errors="ignore")[:32768]
            m = re.search(r'(?m)^version\s*=\s*["\']([^"\']+)["\']', text)
            if m:
                meta["version"] = _sanitise(m.group(1))[:64]
        except OSError:
            pass

    git_dir = plugin_dir / ".git"
    if git_dir.exists():
        meta["git_backed"] = True
        meta["updatable"] = True
        git_bin = shutil.which("git")
        if git_bin:
            try:
                res = subprocess.run(
                    [git_bin, "-C", str(plugin_dir), "config", "--get", "remote.origin.url"],
                    capture_output=True, text=True, timeout=3, check=False, env=minimal_env("git"),
                )
                if res.returncode == 0 and res.stdout.strip():
                    # Strip any embedded credentials in git URLs
                    url = re.sub(r"://[^/@]+@", "://", res.stdout.strip())
                    meta["source"] = _sanitise(url)[:200]
            except (OSError, subprocess.SubprocessError):
                pass

    if shutil.which("hermes"):
        meta["updatable"] = True

    return meta


def discover_hermes_plugins(settings: dict[str, Any] | None = None, inventory_data: dict[str, Any] | None = None) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Discover installed Hermes plugins and configured MCP servers."""
    plugins_by_name: dict[str, dict[str, Any]] = {}
    mcp_servers: list[dict[str, Any]] = []
    seen_mcp: set[tuple[str, str]] = set()

    # 1. From consented inventory profiles (enabled plugins & MCP servers)
    enabled_names: set[str] = set()
    if isinstance(inventory_data, dict):
        for prof in inventory_data.get("profiles") or []:
            if not isinstance(prof, dict):
                continue
            prof_name = _sanitise(prof.get("name") or "default")
            for pname in prof.get("plugins") or []:
                clean = _sanitise(str(pname))
                enabled_names.add(clean)
                plugins_by_name.setdefault(clean, {
                    "name": clean,
                    "version": "installed",
                    "description": f"Configured in profile '{prof_name}'",
                    "source": "hermes config",
                    "path": _sanitise(prof.get("path") or ""),
                    "enabled": True,
                    "git_backed": False,
                    "updatable": bool(shutil.which("hermes")),
                    "kind": "hermes_plugin",
                })
            for mname in prof.get("mcp_servers") or []:
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

    # 2. Scan plugin directories under HERMES_HOME / consented hermes_root / ~/.hermes
    candidate_roots: list[Path] = []
    if isinstance(settings, dict) and isinstance(settings.get("hermes_root"), str) and settings["hermes_root"]:
        candidate_roots.append(Path(settings["hermes_root"]))
    env_home = os.environ.get("HERMES_HOME")
    if env_home:
        candidate_roots.append(Path(env_home))
    default_hermes = Path.home() / ".hermes"
    if default_hermes.is_dir():
        candidate_roots.append(default_hermes)

    seen_dirs: set[str] = set()
    for root in candidate_roots:
        plugins_dir = root / "plugins"
        if not plugins_dir.is_dir() or plugins_dir.is_symlink():
            continue
        try:
            for child in sorted(plugins_dir.iterdir()):
                if not child.is_dir() or child.is_symlink() or child.name.startswith("."):
                    continue
                resolved = str(child)
                if resolved in seen_dirs:
                    continue
                seen_dirs.add(resolved)
                meta = _read_plugin_metadata(child)
                meta["enabled"] = meta["name"] in enabled_names or child.name in enabled_names or True
                plugins_by_name[meta["name"]] = meta
        except OSError:
            continue

    return sorted(plugins_by_name.values(), key=lambda x: x["name"].lower()), mcp_servers


def _discover_linux_apps(upgradable_map: dict[str, dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
    apps: list[dict[str, Any]] = []
    managers: list[str] = []

    # 1. APT / dpkg (prioritize upgradable + manually installed packages so list is clean & actionable)
    dpkg_bin = shutil.which("dpkg-query") or ("/usr/bin/dpkg-query" if Path("/usr/bin/dpkg-query").is_file() else None)
    if dpkg_bin:
        managers.append("apt")
        manual_pkgs: set[str] = set()
        apt_mark = shutil.which("apt-mark") or ("/usr/bin/apt-mark" if Path("/usr/bin/apt-mark").is_file() else None)
        if apt_mark:
            try:
                res_m = subprocess.run(
                    [apt_mark, "showmanual"],
                    capture_output=True, text=True, timeout=10, check=False, env=minimal_env("apt"),
                )
                if res_m.returncode == 0:
                    manual_pkgs = {line.strip() for line in res_m.stdout.splitlines() if line.strip()}
            except (OSError, subprocess.SubprocessError):
                pass
        try:
            res = subprocess.run(
                [dpkg_bin, "-W", "-f=${Package}\t${Version}\t${db:Status-Abbrev}\t${Section}\n"],
                capture_output=True, text=True, timeout=15, check=False, env=minimal_env("apt"),
            )
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    parts = line.split("\t")
                    if len(parts) < 3:
                        continue
                    pkg_name, version, status = parts[0].strip(), parts[1].strip(), parts[2].strip()
                    section = parts[3].strip() if len(parts) > 3 else ""
                    if not status.startswith("ii"):
                        continue
                    upd = upgradable_map.get(pkg_name)
                    is_manual = pkg_name in manual_pkgs if manual_pkgs else not pkg_name.startswith("lib")
                    if not upd and not is_manual:
                        continue
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

    # Include any upgradable APT packages not already in list
    seen_apt = {a["name"] for a in apps if a["manager"] == "apt"}
    for pkg_name, upd in upgradable_map.items():
        if pkg_name not in seen_apt:
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

    # 2. Flatpak apps
    flatpak_bin = shutil.which("flatpak")
    if flatpak_bin:
        managers.append("flatpak")
        try:
            res = subprocess.run(
                [flatpak_bin, "list", "--app", "--columns=application,name,version,installation"],
                capture_output=True, text=True, timeout=10, check=False, env=minimal_env("flatpak"),
            )
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    parts = line.split("\t")
                    if len(parts) < 2:
                        continue
                    app_id = parts[0].strip()
                    display = parts[1].strip() or app_id
                    version = parts[2].strip() if len(parts) > 2 and parts[2].strip() else "installed"
                    apps.append({
                        "name": _sanitise(display),
                        "package_id": _sanitise(app_id),
                        "manager": "flatpak",
                        "installed_version": _sanitise(version),
                        "candidate_version": None,
                        "update_available": False,
                        "security": None,
                        "section": "desktop app",
                        "kind": "os_package",
                    })
        except (OSError, subprocess.SubprocessError):
            pass

    # 3. Snap apps
    snap_bin = shutil.which("snap")
    if snap_bin:
        managers.append("snap")
        try:
            res = subprocess.run(
                [snap_bin, "list"],
                capture_output=True, text=True, timeout=10, check=False, env=minimal_env("snap"),
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
    brew_bin = shutil.which("brew")
    if brew_bin:
        managers.append("brew")
        try:
            res = subprocess.run(
                [brew_bin, "list", "--versions"],
                capture_output=True, text=True, timeout=15, check=False, env=minimal_env("brew"),
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
    hermes_plugins, mcp_servers = discover_hermes_plugins(settings, inventory_data)

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

    # Sort OS apps: security updates first, then other updates, then alphabetical
    os_apps.sort(key=lambda a: (
        0 if a.get("security") is True else (1 if a.get("update_available") else 2),
        a["name"].lower(),
    ))

    # Cap list to keep UI snappy while preserving accurate total count
    total_os_apps = len(os_apps)
    updatable_count = sum(1 for a in os_apps if a.get("update_available"))
    security_count = sum(1 for a in os_apps if a.get("security") is True)

    return {
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
) -> dict[str, Any]:
    """Execute a safe, allowlisted update for a Hermes plugin, Flatpak app, or OS package.

    Never uses shell=True. When OS-level root privileges are required and no interactive
    Polkit prompt is available, returns status='needs_elevation' with the exact command.
    """
    allowed_types = {"hermes_plugin", "hermes_plugins_all", "flatpak", "brew", "os_package", "os_all"}
    if target_type not in allowed_types:
        return {"ok": False, "status": "invalid", "message": f"Unsupported update target type: {target_type}"}

    if target_name is not None:
        if not isinstance(target_name, str) or not _SAFE_NAME_RE.fullmatch(target_name):
            return {"ok": False, "status": "invalid", "message": "Invalid package or plugin name."}

    # 1. Hermes plugin updates (single or all)
    if target_type in ("hermes_plugin", "hermes_plugins_all"):
        hermes_bin = shutil.which("hermes")
        if hermes_bin:
            argv = [hermes_bin, "plugins", "update"]
            if target_type == "hermes_plugin" and target_name:
                argv.append(target_name)
            try:
                res = subprocess.run(
                    argv, capture_output=True, text=True, timeout=60, check=False, env=minimal_env("hermes"),
                )
                out = _sanitise((res.stdout or "") + ("\n" + res.stderr if res.stderr else "")).strip()[:2000]
                if res.returncode == 0:
                    return {
                        "ok": True,
                        "status": "updated",
                        "message": out or f"Updated {target_name or 'all Hermes plugins'} successfully.",
                        "command": " ".join(argv),
                    }
                return {
                    "ok": False,
                    "status": "failed",
                    "message": out or f"hermes plugins update exited with code {res.returncode}.",
                    "command": " ".join(argv),
                }
            except (OSError, subprocess.TimeoutExpired) as exc:
                return {"ok": False, "status": "failed", "message": f"Plugin update failed: {exc}"}

        # Fallback: git pull --ff-only for git-backed plugin directories
        plugins, _ = discover_hermes_plugins(settings, inventory_data)
        targets = [p for p in plugins if p.get("git_backed") and (target_type == "hermes_plugins_all" or p["name"] == target_name)]
        git_bin = shutil.which("git")
        if not targets or not git_bin:
            cmd = f"hermes plugins update {target_name}" if target_name else "hermes plugins update"
            return {
                "ok": False,
                "status": "unavailable",
                "message": "Hermes CLI not found on PATH and plugin is not git-backed. Run the command in your terminal.",
                "command": cmd,
            }
        results = []
        all_ok = True
        for p in targets:
            try:
                res = subprocess.run(
                    [git_bin, "-C", p["path"], "pull", "--ff-only"],
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

    # 2. Flatpak user app update
    if target_type == "flatpak":
        flatpak_bin = shutil.which("flatpak")
        if not flatpak_bin:
            return {"ok": False, "status": "unavailable", "message": "flatpak is not installed."}
        argv = [flatpak_bin, "update", "--user", "-y"]
        if target_name:
            argv.append(target_name)
        try:
            res = subprocess.run(argv, capture_output=True, text=True, timeout=120, check=False, env=minimal_env("flatpak"))
            out = _sanitise((res.stdout or "") + ("\n" + res.stderr if res.stderr else "")).strip()[:2000]
            return {
                "ok": res.returncode == 0,
                "status": "updated" if res.returncode == 0 else "failed",
                "message": out or ("Flatpak updated." if res.returncode == 0 else "Flatpak update failed."),
                "command": " ".join(argv),
            }
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {"ok": False, "status": "failed", "message": f"Flatpak update failed: {exc}"}

    # 3. Homebrew update (macOS/Linux)
    if target_type == "brew":
        brew_bin = shutil.which("brew")
        if not brew_bin:
            return {"ok": False, "status": "unavailable", "message": "Homebrew is not installed."}
        argv = [brew_bin, "upgrade"] + ([target_name] if target_name else [])
        try:
            res = subprocess.run(argv, capture_output=True, text=True, timeout=120, check=False, env=minimal_env("brew"))
            out = _sanitise((res.stdout or "") + ("\n" + res.stderr if res.stderr else "")).strip()[:2000]
            return {
                "ok": res.returncode == 0,
                "status": "updated" if res.returncode == 0 else "failed",
                "message": out or ("Homebrew updated." if res.returncode == 0 else "Homebrew update failed."),
                "command": " ".join(argv),
            }
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {"ok": False, "status": "failed", "message": f"Homebrew update failed: {exc}"}

    # 4. OS package / system update
    if _platform.NAME == "linux":
        if target_type == "os_package" and target_name:
            cmd_str = f"sudo apt-get update && sudo apt-get install --only-upgrade -y {target_name}"
            apt_argv = ["/usr/bin/apt-get", "install", "--only-upgrade", "-y", target_name]
        else:
            cmd_str = "sudo apt-get update && sudo apt-get upgrade -y"
            apt_argv = ["/usr/bin/apt-get", "upgrade", "-y"]

        is_root = hasattr(os, "geteuid") and os.geteuid() == 0
        has_desktop = bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
        pkexec_bin = shutil.which("pkexec") if has_desktop else None

        if is_root or pkexec_bin:
            prefix = [] if is_root else [pkexec_bin]
            try:
                res = subprocess.run(
                    prefix + apt_argv,
                    capture_output=True, text=True, timeout=180, check=False, env=minimal_env("apt"),
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
        cmd_str = f"sudo softwareupdate -i {target_name}" if target_name else "sudo softwareupdate -i -a"
        return {
            "ok": False,
            "status": "needs_elevation",
            "message": "macOS system updates require administrator privileges. Run this command in your terminal:",
            "command": cmd_str,
        }

    cmd_str = f"winget upgrade --id {target_name}" if target_name else "winget upgrade --all"
    return {
        "ok": False,
        "status": "needs_elevation",
        "message": "Run this command in an elevated PowerShell terminal to install Windows updates:",
        "command": cmd_str,
    }
