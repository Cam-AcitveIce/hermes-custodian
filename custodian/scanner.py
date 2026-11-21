"""Built-in antivirus, malware heuristic, agent-security, IOC, and system AV scanner.

Privacy invariant: never opens or reads sensitive credential, memory, or chat-history
files (governed by custodian.policy.is_sensitive — fails closed if unavailable).
All file reads pin ancestor directories (no-follow) and reject hardlinks (st_nlink != 1).
All subprocess calls use trusted binary resolution, fixed argument vectors, minimal
environments, stdin=DEVNULL, and bounded timeouts.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import time
from typing import Any

from . import _platform
from ._subprocess_env import minimal_env

# Maximum per-file size for content hashing/reading (2 MiB)
MAX_SCAN_FILE_BYTES = 2 * 1024 * 1024
# Cap text length passed to regex engines (256 KiB) to prevent slowdowns on huge files
_MAX_REGEX_CHARS = 256 * 1024
# Maximum aggregate bytes read by the heuristic scanner per scan (32 MiB)
MAX_SCAN_TOTAL_BYTES = 32 * 1024 * 1024
# Maximum wall-clock seconds for heuristic content scanning
MAX_SCAN_SECONDS = 10.0
# Shared wall-clock budget for external AV/YARA subprocesses (must stay under Engine.lock_timeout=30s)
MAX_EXTERNAL_AV_SECONDS = 22.0
# Cache TTL for detect_system_av() so dashboard polls don't respawn --version every 15s
_AV_DETECT_TTL_SECONDS = 60.0
_av_detect_cache: tuple[float, dict[str, Any]] | None = None

# Construct the EICAR test string dynamically so this source file never self-triggers
# antivirus engines or its own heuristic scanner.
_EICAR_PARTS = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$",
    b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
)
_EICAR_SIGNATURE = b"".join(_EICAR_PARTS)
_EICAR_SHA256 = hashlib.sha256(_EICAR_SIGNATURE).hexdigest()

# Built-in known-bad SHA-256 hashes (extensible via <state_dir>/ioc_blocklist.json)
BUILTIN_IOC_HASHES: dict[str, str] = {
    _EICAR_SHA256: "EICAR antivirus test file signature",
}

# Extensions where binary executable headers (ELF/PE/Mach-O) are unexpected / disguised
_TEXT_LIKE_EXTENSIONS = frozenset({
    ".md", ".mdx", ".rst", ".txt", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
    ".py", ".pyw", ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx",
    ".sh", ".bash", ".zsh", ".ksh", ".csh", ".fish",
    ".ps1", ".psm1", ".psd1", ".bat", ".cmd",
    ".html", ".htm", ".css", ".xml", ".csv", ".sql", ".rb", ".pl", ".php",
    ".service", ".timer", ".desktop", ".plist", ".vbs", ".vbe", ".jse", ".wsf", ".hta", ".awk",
})

# Extensions scanned for text/code malware heuristics
_SCANNABLE_TEXT_EXTENSIONS = _TEXT_LIKE_EXTENSIONS | frozenset({
    ".lua", ".go", ".rs", ".c", ".cpp", ".h", ".java",
})

# Code/config extensions where Unicode bidirectional controls are Trojan Source risks
_CODE_EXTENSIONS = _SCANNABLE_TEXT_EXTENSIONS - frozenset({".md", ".mdx", ".rst", ".txt"})

# Extensions scanned for AI agent / prompt-injection patterns
_AGENT_PROMPT_EXTENSIONS = frozenset({".md", ".mdx", ".rst", ".txt", ".yaml", ".yml", ".json", ".toml"})

# Doc-only extensions where install instructions like `curl | sh` are common (lower severity)
_DOC_EXTENSIONS = frozenset({".md", ".mdx", ".rst", ".txt"})

# Unicode Bidirectional override/isolate control characters (Trojan Source, CVE-2021-42574)
_BIDI_OVERRIDE_CHARS = frozenset({"\u202a", "\u202b", "\u202c", "\u202d", "\u202e"})
_BIDI_ALL_CHARS = _BIDI_OVERRIDE_CHARS | frozenset({"\u2066", "\u2067", "\u2068", "\u2069"})
# Invisible zero-width space / word-joiner (excludes ZWJ \u200d for emojis and ZWNJ \u200c for RTL scripts)
_ZERO_WIDTH_SUSPICIOUS = frozenset({"\u200b", "\u2060"})

_THIS_FILE_STAT: tuple[int, int] | None = None
try:
    _st = os.lstat(__file__)
    _THIS_FILE_STAT = (_st.st_dev, _st.st_ino)
except OSError:
    _THIS_FILE_STAT = None

# Heuristic rules: (rule_id, severity, category, title, required_substrings_lower, compiled_regex, recommendation)
# Every regex is strictly bounded (no nested unbounded wildcards) and gated by cheap literal pre-checks
# so catastrophic backtracking (ReDoS) is impossible even on pathological input.
_HEURISTIC_RULES: tuple[tuple[str, str, str, str, tuple[str, ...], re.Pattern[str], str], ...] = (
    (
        "reverse_shell_dev_tcp",
        "critical",
        "reverse_shell",
        "Potential reverse shell using /dev/tcp or /dev/udp",
        ("/dev/tcp/",),
        re.compile(r"(?i)(?:bash|sh|zsh)\s+-i\s+>&\s*/dev/(?:tcp|udp)/|>\s*&?\s*/dev/(?:tcp|udp)/[0-9a-zA-Z.-]{1,120}/\d{1,5}"),
        "Inspect this file immediately. Reverse shell redirections to /dev/tcp or /dev/udp are strong indicators of compromise.",
    ),
    (
        "reverse_shell_dev_udp",
        "critical",
        "reverse_shell",
        "Potential reverse shell using /dev/udp",
        ("/dev/udp/",),
        re.compile(r"(?i)(?:bash|sh|zsh)\s+-i\s+>&\s*/dev/udp/|>\s*&?\s*/dev/udp/[0-9a-zA-Z.-]{1,120}/\d{1,5}"),
        "Inspect this file immediately. Reverse shell redirections to /dev/udp are strong indicators of compromise.",
    ),
    (
        "reverse_shell_netcat",
        "critical",
        "reverse_shell",
        "Potential reverse/bind shell using netcat or mkfifo",
        (),
        re.compile(r"(?i)\b(?:nc|ncat|netcat)\b[^\n]{0,80}(?:\s-e\s|\s-c\s|/bin/(?:ba)?sh)|\bmkfifo\s+/tmp/[^\n]{0,60}\|\s*(?:nc|sh|bash)\b"),
        "Inspect this file immediately. Netcat shell execution and named-pipe shells are commonly used for unauthorized remote access.",
    ),
    (
        "reverse_shell_python",
        "critical",
        "reverse_shell",
        "Potential Python socket reverse shell",
        ("socket.socket(", ".connect("),
        re.compile(r"socket\.socket\([^)\n]{0,120}\)[\s\S]{0,300}?\.connect\([^)\n]{0,120}\)[\s\S]{0,300}?(?:os\.dup2|pty\.spawn|subprocess\.(?:call|Popen|run))"),
        "Inspect this file immediately. Connecting a raw socket directly to OS file descriptors or a shell indicates a reverse shell.",
    ),
    (
        "reverse_shell_powershell",
        "critical",
        "reverse_shell",
        "Potential PowerShell TCP reverse shell",
        ("tcpclient",),
        re.compile(r"(?i)New-Object\s+System\.Net\.Sockets\.TCPClient"),
        "Inspect this file immediately. PowerShell TCPClient shells are commonly used in post-exploitation payloads.",
    ),
    (
        "dropper_curl_pipe_shell",
        "high",
        "dropper",
        "Remote script piped directly into a shell interpreter",
        ("|",),
        re.compile(r"(?i)\b(?:curl|wget)\b(?:[^\n|]{1,180}|\\\r?\n[^\n|]{0,120})\|\s*(?:sudo\s+)?(?:/(?:usr/)?bin/)?(?:ba|z|da|k)?sh\b"),
        "Review the remote URL and avoid piping unverified remote content directly into a shell.",
    ),
    (
        "dropper_powershell_encoded",
        "high",
        "dropper",
        "Obfuscated PowerShell download-and-execute pattern",
        (),
        re.compile(r"(?i)(?:powershell(?:\.exe)?\s+[^\n]{0,60}-(?:e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/=]{24,}|(?:IEX|Invoke-Expression)\s*\([^\n]{0,120}(?:DownloadString|WebClient|Invoke-WebRequest))"),
        "Decode and inspect the PowerShell payload before allowing it to remain on disk.",
    ),
    (
        "obfuscated_eval_base64",
        "high",
        "obfuscation",
        "Obfuscated dynamic code execution from encoded/compressed payload",
        (),
        re.compile(r"(?i)\b(?:eval|exec)\s*\(\s*(?:compile\s*\(\s*)?(?:base64\.b64decode|zlib\.decompress|codecs\.decode|bytes\.fromhex|atob)\s*\("),
        "Inspect the decoded payload. Legitimate software rarely executes base64-encoded or compressed code dynamically via eval/exec.",
    ),
    (
        "cryptominer_indicator",
        "high",
        "cryptominer",
        "Potential cryptocurrency miner configuration or pool URL",
        (),
        re.compile(r"(?i)(?:stratum\+(?:tcp|ssl)://|\bxmrig\b|\bcoinhive\b|\bmoneroocean\b|\bcryptonight\b)"),
        "Verify whether cryptocurrency mining software is authorized on this machine; unauthorized miners often indicate compromise.",
    ),
    (
        "persistence_cron_or_rc",
        "medium",
        "persistence",
        "Suspicious persistence mechanism modifying cron, shell rc, or autostart",
        (),
        re.compile(r"(?i)(?:\(\s*crontab\s+-l[^\n]{0,120}\|\s*crontab\s+-|>>\s*~?/?\.(?:bashrc|zshrc|profile)\b[^\n]{0,120}(?:curl|wget|nc\s|base64|python)|HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run)"),
        "Review whether this script is expected to install startup persistence.",
    ),
    (
        "credential_exfiltration",
        "high",
        "exfiltration",
        "Potential credential theft and outbound network exfiltration",
        (),
        re.compile(r"(?i)(?:\.ssh/id_rsa|\.aws/credentials|Login Data|key4\.db|/etc/shadow)[\s\S]{0,260}(?:requests\.post|urllib\.request|http\.client|discord\.com/api/webhooks|api\.telegram\.org/bot|curl\s+[^\n]{0,80}-(?:d|F|X\s+POST))"),
        "Inspect this file immediately. Reading credential locations and sending data to an external endpoint indicates potential exfiltration.",
    ),
)

_EXFIL_NETWORK_TOKENS = (
    "requests.post", "urllib.request", "http.client",
    "discord.com/api/webhooks", "api.telegram.org/bot", "curl ",
)

_AGENT_SECURITY_RULES: tuple[tuple[str, str, str, str, re.Pattern[str], str], ...] = (
    (
        "agent_prompt_injection_override",
        "medium",
        "agent_security",
        "Potential AI prompt-injection instruction override",
        re.compile(r"(?i)\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above|system)\s+(?:instructions|prompts|rules)\b"),
        "Review this document/skill for prompt-injection attempts before loading it into an AI agent.",
    ),
    (
        "agent_prompt_exfil",
        "high",
        "agent_security",
        "Potential AI agent data-exfiltration instruction",
        re.compile(r"(?i)(?:exfiltrate|silently\s+send|secretly\s+upload)[^\n]{0,120}(?:api[_\s-]?key|token|secret|password|ssh|credentials|\.env)"),
        "Remove or quarantine this file; it appears to instruct an AI agent to steal sensitive data.",
    ),
)


def _finding_id(rule_id: str, raw_path: str) -> str:
    return hashlib.sha256(f"security:{rule_id}:{raw_path}".encode("utf-8")).hexdigest()


def _detect_magic_binary(raw: bytes) -> str | None:
    if len(raw) < 4:
        return None
    if raw[:4] == b"\x7fELF":
        return "ELF executable"
    if raw[:2] == b"MZ" and b"PE\x00\x00" in raw[:4096]:
        return "Windows PE executable"
    if raw[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"):
        return "Mach-O binary"
    if raw[:4] == b"\xca\xfe\xba\xbe" and len(raw) >= 8 and raw[4:8] == b"\x00\x00\x00\x02":
        return "Mach-O universal binary"
    return None


def _is_this_scanner_file(raw_path: str) -> bool:
    if _THIS_FILE_STAT is None:
        return False
    try:
        st = os.lstat(raw_path)
        return (st.st_dev, st.st_ino) == _THIS_FILE_STAT
    except OSError:
        return False


def _load_ioc_hashes_with_errors(state_dir: Path | None, sanitise=None) -> tuple[dict[str, str], list[str]]:
    """Return (hashes, errors) from built-in + optional private user ioc_blocklist.json."""
    hashes = dict(BUILTIN_IOC_HASHES)
    errors: list[str] = []
    if state_dir is None:
        return hashes, errors
    ioc_path = Path(state_dir) / "ioc_blocklist.json"
    if not os.path.lexists(ioc_path):
        return hashes, errors
    clean_fn = sanitise if callable(sanitise) else str
    try:
        raw = _platform.read_private_file(ioc_path, max_bytes=1048576)
        data = json.loads(raw.decode("utf-8"))
        if isinstance(data, dict):
            entries = data.get("hashes", data)
            if isinstance(entries, dict):
                for h, desc in entries.items():
                    if isinstance(h, str) and re.fullmatch(r"[0-9a-fA-F]{64}", h):
                        hashes[h.lower()] = clean_fn(str(desc))[:200]
            elif isinstance(entries, list):
                for h in entries:
                    if isinstance(h, str) and re.fullmatch(r"[0-9a-fA-F]{64}", h):
                        hashes[h.lower()] = "User IOC blocklist match"
            else:
                errors.append("ioc_blocklist.json has invalid structure")
        elif isinstance(data, list):
            for h in data:
                if isinstance(h, str) and re.fullmatch(r"[0-9a-fA-F]{64}", h):
                    hashes[h.lower()] = "User IOC blocklist match"
        else:
            errors.append("ioc_blocklist.json must be a JSON object or list")
    except (OSError, ValueError, UnicodeError) as exc:
        errors.append(f"Could not load ioc_blocklist.json: {clean_fn(str(exc))}")
    return hashes, errors


def load_ioc_hashes(state_dir: Path | None) -> dict[str, str]:
    """Return built-in + optional user-configured SHA-256 IOC hashes."""
    from . import policy as _policy
    hashes, _ = _load_ioc_hashes_with_errors(state_dir, sanitise=_policy.sanitise_text)
    return hashes


def _decode_text_safe(raw: bytes, is_known_text_ext: bool) -> str | None:
    """Decode text safely, supporting UTF-16 BOMs and handling NUL bytes in script extensions."""
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            text = raw.decode("utf-16", errors="ignore")
            return text.replace("\x00", "")
        except Exception:
            return None
    has_nul = b"\x00" in raw[:8192]
    if has_nul:
        # True binary files have lots of NUL bytes; scripts with injected NUL bytes to evade scanning
        # should still be decoded with NULs stripped.
        if not is_known_text_ext and not raw.startswith(b"#!"):
            return None
        nul_ratio = raw[:8192].count(b"\x00") / max(1, min(len(raw), 8192))
        if nul_ratio > 0.25:
            return None
        raw = raw.replace(b"\x00", b"")
    try:
        return raw.decode("utf-8", errors="ignore")
    except Exception:
        return None


def scan_file_bytes(
    raw_path: str,
    raw: bytes,
    *,
    sha256: str | None = None,
    ioc_hashes: dict[str, str] | None = None,
    started: str = "",
    scope_signature: str = "",
    sanitise=None,
) -> list[dict[str, Any]]:
    """Run all built-in security/AV checks on a single file's bytes.

    Never stores raw file content snippets in evidence to avoid leaking secrets.
    """
    clean_path = sanitise(raw_path) if callable(sanitise) else raw_path
    path_obj = Path(raw_path)
    suffix = path_obj.suffix.lower()
    lower_name = path_obj.name.lower()
    findings: list[dict[str, Any]] = []
    seen_rules: set[str] = set()

    def add_finding(rule_id: str, severity: str, category: str, title: str, evidence: dict[str, Any], recommendation: str) -> None:
        if rule_id in seen_rules:
            return
        seen_rules.add(rule_id)
        findings.append({
            "id": _finding_id(rule_id, raw_path),
            "severity": severity,
            "category": category,
            "title": title,
            "path": clean_path,
            "evidence": {"rule": rule_id, "category": category, **evidence},
            "recommendation": recommendation,
            "first_seen": started,
            "last_seen": started,
            "status": "open",
            "scope_signature": scope_signature,
        })

    # 1. EICAR antivirus test string
    if _EICAR_SIGNATURE in raw:
        add_finding(
            "eicar_test_signature",
            "critical",
            "malware_signature",
            "EICAR antivirus test signature detected",
            {"detector": "builtin_signature", "signature": "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"},
            "This is the standard EICAR antivirus test file. Delete it once you have verified scanner alerts.",
        )

    # 2. SHA-256 IOC blocklist check (skip EICAR hash if already flagged above)
    digest = sha256 or hashlib.sha256(raw).hexdigest()
    blocklist = ioc_hashes if ioc_hashes is not None else BUILTIN_IOC_HASHES
    if digest.lower() in blocklist and not (digest.lower() == _EICAR_SHA256 and "eicar_test_signature" in seen_rules):
        desc = sanitise(blocklist[digest.lower()]) if callable(sanitise) else blocklist[digest.lower()]
        add_finding(
            "ioc_sha256_match",
            "critical",
            "ioc_hash",
            "File matches known-malicious SHA-256 hash (IOC)",
            {"detector": "ioc_blocklist", "sha256": digest.lower(), "description": desc},
            "Quarantine or remove this file immediately and investigate how it arrived on the system.",
        )

    # 3. Disguised executable check (binary header in a text/script extension)
    binary_kind = _detect_magic_binary(raw)
    if binary_kind and suffix in _TEXT_LIKE_EXTENSIONS:
        add_finding(
            "disguised_executable",
            "high",
            "disguised_binary",
            f"Disguised {binary_kind} inside {suffix} file",
            {"detector": "magic_bytes", "detected_type": binary_kind, "extension": suffix},
            "Inspect why a compiled binary is masquerading with a text or script extension.",
        )
        return findings

    is_known_text = (
        suffix in _SCANNABLE_TEXT_EXTENSIONS
        or lower_name in ("dockerfile", "makefile")
        or lower_name.endswith(".env.example")
    )
    has_shebang = raw.startswith(b"#!")
    if not is_known_text and not has_shebang:
        return findings

    text = _decode_text_safe(raw, is_known_text)
    if text is None:
        return findings

    # Bound regex inspection window to prevent slowdowns on giant files
    scan_text = text[:_MAX_REGEX_CHARS]
    scan_lower = scan_text.lower()

    # 4. Trojan Source / Unicode Bidi & zero-width obfuscation check
    bidi_set = _BIDI_ALL_CHARS if (suffix in _CODE_EXTENSIONS or has_shebang) else _BIDI_OVERRIDE_CHARS
    bidi_found = [f"U+{ord(ch):04X}" for ch in bidi_set if ch in scan_text]
    if bidi_found:
        add_finding(
            "trojan_source_bidi",
            "high",
            "trojan_source",
            "Hidden Unicode bidirectional control characters (Trojan Source)",
            {"detector": "unicode_audit", "codepoints": sorted(bidi_found)},
            "Inspect the raw bytes of this file. Bidirectional override characters can hide malicious logic from human reviewers.",
        )
    zw_count = sum(scan_text.count(ch) for ch in _ZERO_WIDTH_SUSPICIOUS)
    if zw_count >= 12:
        add_finding(
            "hidden_zero_width_cluster",
            "medium",
            "trojan_source",
            "Suspicious cluster of invisible zero-width Unicode characters",
            {"detector": "unicode_audit", "zero_width_count": zw_count},
            "Inspect this file for hidden steganographic or prompt-injection payloads encoded with zero-width characters.",
        )

    # Exempt ONLY this installed scanner.py file by device+inode (never by filename/substring)
    if _is_this_scanner_file(raw_path):
        return findings

    # 5. Malware & security heuristic rules (all bounded + pre-checked)
    for rule_id, severity, category, title, required_subs, pattern, recommendation in _HEURISTIC_RULES:
        if required_subs and not all(sub in scan_lower for sub in required_subs):
            continue
        if rule_id == "credential_exfiltration" and not any(tok in scan_lower for tok in _EXFIL_NETWORK_TOKENS):
            continue
        match = pattern.search(scan_text)
        if match:
            line_no = scan_text.count("\n", 0, match.start()) + 1
            eff_severity = "low" if (rule_id == "dropper_curl_pipe_shell" and suffix in _DOC_EXTENSIONS) else severity
            add_finding(
                rule_id,
                eff_severity,
                category,
                title,
                {"detector": "builtin_heuristic", "line": line_no},
                recommendation,
            )

    # 6. AI agent / skill prompt-injection checks
    if suffix in _AGENT_PROMPT_EXTENSIONS:
        for rule_id, severity, category, title, pattern, recommendation in _AGENT_SECURITY_RULES:
            match = pattern.search(scan_text)
            if match:
                line_no = scan_text.count("\n", 0, match.start()) + 1
                add_finding(
                    rule_id,
                    severity,
                    category,
                    title,
                    {"detector": "agent_security", "line": line_no},
                    recommendation,
                )

    return findings


def _trusted_which(name: str, env_cmd: str) -> str | None:
    """Resolve an executable strictly from minimal_env(env_cmd)['PATH'], never parent PATH."""
    trusted_path = minimal_env(env_cmd).get("PATH", "")
    found = shutil.which(name, path=trusted_path)
    if not found:
        return None
    # On POSIX, ensure the binary is not writable by group or others
    if not _platform.IS_WINDOWS:
        try:
            st = os.stat(found)
            if not stat.S_ISREG(st.st_mode) or (st.st_mode & 0o022):
                return None
        except OSError:
            return None
    return found


def _windows_defender_executable() -> str | None:
    """Locate MpCmdRun.exe from fixed system locations without trusting arbitrary env vars."""
    candidates: list[Path] = []
    pf = os.environ.get("ProgramFiles")
    if isinstance(pf, str) and len(pf) >= 3 and pf[1] == ":" and not any(c in pf for c in ';"<>|*?\x00'):
        candidates.append(Path(pf) / "Windows Defender" / "MpCmdRun.exe")
    candidates.append(Path(r"C:\Program Files\Windows Defender\MpCmdRun.exe"))
    for exe in candidates:
        try:
            if exe.is_file() and not exe.is_symlink():
                return str(exe)
        except OSError:
            continue
    return None


def detect_system_av(*, force_refresh: bool = False) -> dict[str, Any]:
    """Detect available local system antivirus engines (cached for 60s)."""
    global _av_detect_cache
    now = time.monotonic()
    if not force_refresh and _av_detect_cache is not None:
        ts, cached = _av_detect_cache
        if now - ts < _AV_DETECT_TTL_SECONDS:
            return dict(cached)

    if _platform.NAME == "windows":
        exe = _windows_defender_executable()
        if exe:
            result = {
                "available": True,
                "engine": "windows_defender",
                "label": "Windows Defender",
                "binary": exe,
                "builtin_heuristics": True,
            }
        else:
            result = {
                "available": False,
                "engine": None,
                "label": "Built-in scanner only",
                "binary": None,
                "builtin_heuristics": True,
                "note": "Windows Defender CLI (MpCmdRun.exe) not found; built-in heuristic & IOC scanner is active.",
            }
        _av_detect_cache = (now, result)
        return dict(result)

    # Linux / macOS: check for ClamAV strictly on trusted system PATH
    for name in ("clamdscan", "clamscan"):
        found = _trusted_which(name, "av")
        if found:
            version = None
            try:
                res = subprocess.run(
                    [found, "--version"],
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                    env=minimal_env("av"),
                )
                if res.returncode == 0 and res.stdout.strip():
                    version = res.stdout.strip().splitlines()[0][:120]
            except (OSError, subprocess.SubprocessError):
                pass
            result = {
                "available": True,
                "engine": name,
                "label": f"ClamAV ({name})",
                "binary": found,
                "version": version,
                "builtin_heuristics": True,
            }
            _av_detect_cache = (now, result)
            return dict(result)

    result = {
        "available": False,
        "engine": None,
        "label": "Built-in scanner only",
        "binary": None,
        "builtin_heuristics": True,
        "note": "ClamAV not installed (install clamav for signature-based AV). Built-in heuristic, IOC & agent security scanner is active.",
    }
    _av_detect_cache = (now, result)
    return dict(result)


def _run_clamav_scan(
    binary: str,
    engine_name: str,
    vetted_paths: list[str],
    *,
    deadline: float,
    started: str,
    scope_signature: str,
    sanitise=None,
) -> tuple[list[dict[str, Any]], list[str], bool]:
    """Run ClamAV strictly on vetted non-sensitive regular files via a private --file-list."""
    if not vetted_paths:
        return [], [], True
    findings: list[dict[str, Any]] = []
    errors: list[str] = []
    scan_ok = True
    vetted_set = set(vetted_paths)
    # Exclude paths with embedded newlines from --file-list to prevent line injection
    safe_list = [p for p in vetted_paths if "\n" not in p and "\r" not in p]
    if len(safe_list) != len(vetted_paths):
        scan_ok = False
        errors.append("Some paths with control characters were skipped by ClamAV file-list")
    if not safe_list:
        return findings, errors, scan_ok

    remaining = max(1.0, deadline - time.monotonic())
    if remaining <= 1.0:
        return [], ["ClamAV skipped: external AV time budget exhausted"], False

    list_path: str | None = None
    try:
        fd, list_path = tempfile.mkstemp(prefix="warden-clamav-", suffix=".txt")
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write("\n".join(safe_list) + "\n")
        except BaseException:
            try:
                os.close(fd)
            except OSError:
                pass
            raise

        if engine_name == "clamdscan":
            argv = [binary, "--no-summary", "--infected", "--fdpass", f"--file-list={list_path}"]
        else:
            argv = [
                binary, "--infected", "--no-summary",
                "--follow-file-symlinks=0", "--follow-dir-symlinks=0",
                "--max-filesize=16M", "--max-scansize=64M",
                f"--file-list={list_path}",
            ]
        try:
            res = subprocess.run(
                argv,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=remaining,
                check=False,
                env=minimal_env("av"),
            )
        except subprocess.TimeoutExpired:
            return [], ["ClamAV scan timed out"], False
        except OSError as exc:
            return [], [f"ClamAV unavailable: {exc}"], False

        # Always parse FOUND lines even if returncode == 2 (ClamAV returns 2 if any file had an error AND another was infected)
        for line in res.stdout.splitlines():
            line = line.strip()
            if not line or not line.endswith(" FOUND"):
                continue
            parts = line.rsplit(":", 1)
            if len(parts) != 2:
                continue
            raw_path = parts[0].strip()
            if raw_path not in vetted_set:
                continue
            sig_name = parts[1].strip()
            if sig_name.endswith(" FOUND"):
                sig_name = sig_name[:-6].strip()
            clean_path = sanitise(raw_path) if callable(sanitise) else raw_path
            findings.append({
                "id": _finding_id(f"clamav:{sig_name}", raw_path),
                "severity": "critical",
                "category": "antivirus",
                "title": f"ClamAV malware detection: {sig_name}",
                "path": clean_path,
                "evidence": {"detector": engine_name, "signature": sig_name, "category": "antivirus"},
                "recommendation": "Quarantine or delete this file immediately and investigate how it entered the system.",
                "first_seen": started,
                "last_seen": started,
                "status": "open",
                "scope_signature": scope_signature,
            })

        if res.returncode == 2:
            if engine_name == "clamdscan" and not findings:
                fallback = _trusted_which("clamscan", "av")
                if fallback and (deadline - time.monotonic()) > 2.0:
                    return _run_clamav_scan(
                        fallback, "clamscan", vetted_paths,
                        deadline=deadline, started=started, scope_signature=scope_signature, sanitise=sanitise,
                    )
            scan_ok = False
            err_lines = (res.stderr or res.stdout or "ClamAV scan error").strip().splitlines()
            errors.append(f"ClamAV error: {err_lines[0][:160] if err_lines else 'exit 2'}")
    finally:
        if list_path:
            try:
                os.unlink(list_path)
            except OSError:
                pass
    return findings, errors, scan_ok


def _run_windows_defender_scan(
    binary: str,
    vetted_paths: list[str],
    *,
    deadline: float,
    started: str,
    scope_signature: str,
    sanitise=None,
) -> tuple[list[dict[str, Any]], list[str], bool]:
    """Run Windows Defender MpCmdRun.exe on vetted non-sensitive regular files."""
    if not vetted_paths:
        return [], [], True
    findings: list[dict[str, Any]] = []
    errors: list[str] = []
    scan_ok = True
    # Bounded per-file Defender scan within shared deadline
    for raw_path in vetted_paths[:200]:
        remaining = deadline - time.monotonic()
        if remaining <= 1.0:
            scan_ok = False
            errors.append("Windows Defender scan time budget exhausted")
            break
        try:
            res = subprocess.run(
                [binary, "-Scan", "-ScanType", "3", "-File", raw_path, "-DisableRemediation"],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=min(remaining, 10.0),
                check=False,
                env=minimal_env("defender"),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            scan_ok = False
            errors.append(f"Windows Defender scan error: {exc}")
            break
        # MpCmdRun exit code 2 indicates threat detected
        if res.returncode == 2:
            clean_path = sanitise(raw_path) if callable(sanitise) else raw_path
            findings.append({
                "id": _finding_id("windows_defender:threat", raw_path),
                "severity": "critical",
                "category": "antivirus",
                "title": "Windows Defender malware detection",
                "path": clean_path,
                "evidence": {"detector": "windows_defender", "category": "antivirus"},
                "recommendation": "Inspect Windows Security threat history and quarantine or remove this file immediately.",
                "first_seen": started,
                "last_seen": started,
                "status": "open",
                "scope_signature": scope_signature,
            })
        elif res.returncode != 0:
            scan_ok = False
            errors.append(f"Windows Defender exited with code {res.returncode}")
    if len(vetted_paths) > 200:
        scan_ok = False
        errors.append("Windows Defender file budget reached (200 files)")
    return findings, errors, scan_ok


def _run_yara_scan(
    state_dir: Path | None,
    vetted_paths: list[str],
    *,
    deadline: float,
    started: str,
    scope_signature: str,
    sanitise=None,
) -> tuple[list[dict[str, Any]], list[str], bool]:
    """Run optional user-supplied YARA rules from <state_dir>/yara_rules/ strictly on vetted files."""
    if state_dir is None or not vetted_paths:
        return [], [], True
    rules_dir = Path(state_dir) / "yara_rules"
    if not os.path.lexists(rules_dir):
        return [], [], True
    yara_bin = _trusted_which("yara", "yara")
    if not yara_bin:
        return [], [], True

    rule_files: list[Path] = []
    try:
        with _platform.open_directory_nofollow(rules_dir) as dir_cap:
            if not _platform.IS_WINDOWS:
                st_dir = os.fstat(dir_cap.fd)
                if st_dir.st_uid != os.getuid() or (st_dir.st_mode & 0o022):
                    return [], ["Refusing to load YARA rules from unsafe directory"], False
            for name in sorted(os.listdir(rules_dir))[:20]:
                if not name.lower().endswith((".yar", ".yara")):
                    continue
                cand = rules_dir / name
                try:
                    # Verify private regular file ownership & no hardlinks before using as rule
                    _platform.read_private_file(cand, max_bytes=1048576)
                    rule_files.append(cand)
                except (OSError, ValueError):
                    continue
    except (OSError, ValueError) as exc:
        return [], [f"YARA rules directory unavailable: {exc}"], False

    if not rule_files:
        return [], [], True

    findings: list[dict[str, Any]] = []
    errors: list[str] = []
    scan_ok = True
    vetted_set = set(vetted_paths)

    for rule_file in rule_files:
        # Chunk vetted paths so argv stays bounded
        for idx in range(0, len(vetted_paths), 100):
            remaining = deadline - time.monotonic()
            if remaining <= 1.0:
                scan_ok = False
                errors.append("YARA scan time budget exhausted")
                return findings, errors, scan_ok
            batch = vetted_paths[idx:idx + 100]
            try:
                res = subprocess.run(
                    [yara_bin, "-N", str(rule_file), "--", *batch],
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    timeout=min(remaining, 10.0),
                    check=False,
                    env=minimal_env("yara"),
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                scan_ok = False
                errors.append(f"YARA scan failed for {rule_file.name}: {exc}")
                continue
            if res.returncode != 0:
                scan_ok = False
                err_line = (res.stderr or f"exit {res.returncode}").strip().splitlines()[:1]
                errors.append(f"YARA rule error ({rule_file.name}): {err_line[0][:160] if err_line else 'failed'}")
                continue
            for line in res.stdout.splitlines():
                parts = line.strip().split(" ", 1)
                if len(parts) != 2:
                    continue
                rule_name, raw_path = parts[0].strip(), parts[1].strip()
                if raw_path not in vetted_set:
                    continue
                clean_path = sanitise(raw_path) if callable(sanitise) else raw_path
                findings.append({
                    "id": _finding_id(f"yara:{rule_name}", raw_path),
                    "severity": "high",
                    "category": "yara",
                    "title": f"YARA rule matched: {rule_name}",
                    "path": clean_path,
                    "evidence": {"detector": "yara", "rule": rule_name, "rule_file": rule_file.name, "category": "yara"},
                    "recommendation": "Inspect this file against the matched YARA rule and quarantine if unauthorized.",
                    "first_seen": started,
                    "last_seen": started,
                    "status": "open",
                    "scope_signature": scope_signature,
                })
    return findings, errors, scan_ok


def _safe_read_file(path: Path, max_bytes: int, expected_item: dict[str, Any] | None = None) -> bytes | None:
    """Safely read a regular, single-linked file pinning every ancestor (no symlink traversal)."""
    try:
        if _platform.IS_WINDOWS:
            return _platform.read_file_nofollow(path, max_bytes=max_bytes)
        with _platform.open_directory_nofollow(path.parent) as parent:
            fd = os.open(
                path.name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0),
                dir_fd=parent.fd,
            )
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size <= 0 or info.st_size > max_bytes:
                    return None
                if expected_item is not None:
                    exp_size = expected_item.get("size")
                    exp_mtime = expected_item.get("mtime_ns")
                    if exp_size is not None and info.st_size != exp_size:
                        return None
                    if exp_mtime is not None and info.st_mtime_ns != exp_mtime:
                        return None
                chunks: list[bytes] = []
                remaining = info.st_size
                while remaining > 0:
                    chunk = os.read(fd, min(65536, remaining))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                after = os.fstat(fd)
                if remaining or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
                    info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns
                ):
                    return None
                return b"".join(chunks)
            finally:
                os.close(fd)
    except (OSError, ValueError):
        return None


def scan_scope(
    roots: list[Path],
    files: dict[str, dict[str, Any]],
    settings: dict[str, Any],
    *,
    state_dir: Path | None = None,
    started: str = "",
    scope_signature: str = "",
    policy_module=None,
) -> tuple[list[dict[str, Any]], list[str], dict[str, Any]]:
    """Run built-in antivirus/security heuristics, IOC checks, YARA, and optional system AV.

    Privacy invariant: fails closed if policy.is_sensitive is missing and never reads
    sensitive files or passes them to external scanners.
    Returns (findings, errors, av_summary) where av_summary includes 'complete' and 'inspected_paths'.
    """
    if policy_module is None:
        from . import policy as policy_module

    # Fail closed if policy_module lacks is_sensitive
    is_sensitive = getattr(policy_module, "is_sensitive", lambda _p: True)
    sanitise = getattr(policy_module, "sanitise_text", str)

    findings: list[dict[str, Any]] = []
    errors: list[str] = []
    scan_complete = True
    ioc_hashes, ioc_errors = _load_ioc_hashes_with_errors(state_dir, sanitise=sanitise)
    if ioc_errors:
        errors.extend(ioc_errors)

    max_file_bytes = min(int(settings.get("max_file_bytes", MAX_SCAN_FILE_BYTES)), MAX_SCAN_FILE_BYTES)
    deadline = time.monotonic() + MAX_SCAN_SECONDS
    bytes_read = 0
    files_inspected = 0
    inspected_paths: set[str] = set()
    vetted_paths: list[str] = []
    sorted_items = sorted(files.items())

    # Pass 1: Metadata-only SUID/SGID check (fast, never opens files, never skipped by content deadline)
    for raw_path, item in sorted_items:
        if item.get("type", "file") != "file":
            continue
        mode = item.get("mode", 0)
        if isinstance(mode, int):
            suid_exec = bool((mode & stat.S_ISUID) and (mode & 0o111))
            sgid_exec = bool((mode & stat.S_ISGID) and (mode & 0o010))
            if suid_exec or sgid_exec:
                clean_path = sanitise(raw_path)
                findings.append({
                    "id": _finding_id("suid_sgid_bit", raw_path),
                    "severity": "high",
                    "category": "privilege_escalation",
                    "title": "Executable file has SUID/SGID privilege-escalation bit set",
                    "path": clean_path,
                    "evidence": {"detector": "metadata_audit", "mode": oct(mode), "category": "privilege_escalation"},
                    "recommendation": "Verify why an executable in your watched scope has SUID/SGID bits set; remove with chmod u-s,g-s if unintended.",
                    "first_seen": started,
                    "last_seen": started,
                    "status": "open",
                    "scope_signature": scope_signature,
                })

    # Pass 2: Built-in content heuristics & IOC hash checks on non-sensitive regular files
    for raw_path, item in sorted_items:
        if item.get("type", "file") != "file":
            continue
        path_obj = Path(raw_path)

        # Privacy invariant: NEVER open sensitive credential/memory/chat files
        if is_sensitive(path_obj):
            continue

        vetted_paths.append(raw_path)

        if time.monotonic() >= deadline:
            scan_complete = False
            errors.append("Security scanner time budget exhausted; remaining files not inspected")
            break
        if bytes_read >= MAX_SCAN_TOTAL_BYTES:
            scan_complete = False
            errors.append("Security scanner aggregate byte budget exhausted; remaining files not inspected")
            break

        # Fast IOC check if snapshot already computed SHA-256 (skip EICAR hash here to avoid duplicate)
        existing_sha = item.get("sha256")
        if existing_sha and existing_sha.lower() in ioc_hashes and existing_sha.lower() != _EICAR_SHA256:
            clean_path = sanitise(raw_path)
            findings.append({
                "id": _finding_id("ioc_sha256_match", raw_path),
                "severity": "critical",
                "category": "ioc_hash",
                "title": "File matches known-malicious SHA-256 hash (IOC)",
                "path": clean_path,
                "evidence": {
                    "detector": "ioc_blocklist",
                    "sha256": existing_sha.lower(),
                    "description": sanitise(ioc_hashes[existing_sha.lower()]),
                    "category": "ioc_hash",
                },
                "recommendation": "Quarantine or delete this file immediately.",
                "first_seen": started,
                "last_seen": started,
                "status": "open",
                "scope_signature": scope_signature,
            })

        size = item.get("size", 0)
        if not isinstance(size, int) or size <= 0:
            inspected_paths.add(raw_path)
            continue
        if size > max_file_bytes:
            # Oversized file was not content-inspected — do NOT add to inspected_paths so open findings aren't auto-resolved
            continue
        if bytes_read + size > MAX_SCAN_TOTAL_BYTES:
            scan_complete = False
            errors.append("Security scanner aggregate byte budget exhausted; remaining files not inspected")
            break

        raw = _safe_read_file(path_obj, max_file_bytes, expected_item=item)
        if raw is None:
            continue
        bytes_read += len(raw)
        files_inspected += 1
        inspected_paths.add(raw_path)

        file_findings = scan_file_bytes(
            raw_path,
            raw,
            sha256=existing_sha,
            ioc_hashes=ioc_hashes,
            started=started,
            scope_signature=scope_signature,
            sanitise=sanitise,
        )
        findings.extend(file_findings)

    # Pass 3: Optional YARA rules & System AV (strictly on vetted_paths, shared time budget)
    ext_deadline = time.monotonic() + MAX_EXTERNAL_AV_SECONDS
    yara_findings, yara_errors, yara_ok = _run_yara_scan(
        state_dir, vetted_paths, deadline=ext_deadline, started=started, scope_signature=scope_signature, sanitise=sanitise
    )
    findings.extend(yara_findings)
    errors.extend(yara_errors)
    if not yara_ok:
        scan_complete = False

    av_used = False
    av_info: dict[str, Any] = {
        "available": False,
        "engine": None,
        "label": "Built-in scanner only",
        "builtin_heuristics": True,
    }
    if settings.get("use_system_av", True):
        av_info = detect_system_av()
        if av_info.get("available"):
            engine_name = av_info.get("engine")
            binary = av_info.get("binary")
            if engine_name in ("clamdscan", "clamscan") and binary:
                av_used = True
                av_findings, av_errors, av_ok = _run_clamav_scan(
                    binary, engine_name, vetted_paths,
                    deadline=ext_deadline, started=started, scope_signature=scope_signature, sanitise=sanitise,
                )
                findings.extend(av_findings)
                errors.extend(av_errors)
                if not av_ok:
                    scan_complete = False
            elif engine_name == "windows_defender" and binary:
                av_used = True
                av_findings, av_errors, av_ok = _run_windows_defender_scan(
                    binary, vetted_paths,
                    deadline=ext_deadline, started=started, scope_signature=scope_signature, sanitise=sanitise,
                )
                findings.extend(av_findings)
                errors.extend(av_errors)
                if not av_ok:
                    scan_complete = False

    # Deduplicate findings by id
    deduped: dict[str, dict[str, Any]] = {}
    for f in findings:
        deduped[f["id"]] = f

    av_summary = {
        **av_info,
        "system_av_used": av_used,
        "files_inspected": files_inspected,
        "ioc_hash_count": len(ioc_hashes),
        "heuristic_rule_count": len(_HEURISTIC_RULES) + len(_AGENT_SECURITY_RULES),
        "complete": scan_complete,
        "inspected_paths": inspected_paths,
    }
    return list(deduped.values()), errors, av_summary
