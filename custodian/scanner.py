"""Built-in antivirus, malware heuristic, agent-security, IOC, and system AV scanner.

Privacy invariant: never opens or reads sensitive credential, memory, or chat-history
files (governed by custodian.policy.is_sensitive). All subprocess calls use fixed
argument vectors, minimal environment, and strict timeouts.
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
import time
from typing import Any

from . import _platform
from ._subprocess_env import minimal_env

# Maximum per-file size for heuristic content scanning (2 MiB)
MAX_SCAN_FILE_BYTES = 2 * 1024 * 1024
# Maximum aggregate bytes read by the heuristic scanner per scan (32 MiB)
MAX_SCAN_TOTAL_BYTES = 32 * 1024 * 1024
# Maximum wall-clock seconds for heuristic content scanning
MAX_SCAN_SECONDS = 10.0

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
    ".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
    ".py", ".js", ".ts", ".jsx", ".tsx", ".sh", ".bash", ".zsh", ".ps1", ".bat",
    ".cmd", ".html", ".htm", ".css", ".xml", ".csv", ".sql", ".rb", ".pl", ".php",
})

# Extensions scanned for text/code malware heuristics
_SCANNABLE_TEXT_EXTENSIONS = _TEXT_LIKE_EXTENSIONS | frozenset({
    ".service", ".timer", ".desktop", ".plist", ".vbs", ".wsf", ".hta", ".lua",
    ".go", ".rs", ".c", ".cpp", ".h", ".java", ".env.example", ".dockerfile",
})

# Extensions scanned for AI agent / prompt-injection patterns
_AGENT_PROMPT_EXTENSIONS = frozenset({".md", ".txt", ".yaml", ".yml", ".json", ".toml"})

# Unicode Bidirectional control characters used in Trojan Source attacks (CVE-2021-42574)
_BIDI_CHARS = frozenset({
    "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
    "\u2066", "\u2067", "\u2068", "\u2069",
})
_ZERO_WIDTH_CHARS = frozenset({"\u200b", "\u200c", "\u200d", "\u2060"})

# Heuristic security rules: (rule_id, severity, category, title, compiled_regex, recommendation)
_HEURISTIC_RULES: tuple[tuple[str, str, str, str, re.Pattern[str], str], ...] = (
    (
        "reverse_shell_dev_tcp",
        "critical",
        "reverse_shell",
        "Potential reverse shell using /dev/tcp or /dev/udp",
        re.compile(r"(?i)(?:bash|sh|zsh)\s+-i\s+>&\s*/dev/(?:tcp|udp)/|>\s*&?\s*/dev/(?:tcp|udp)/[0-9a-zA-Z.-]+/\d+"),
        "Inspect this file immediately. Reverse shell redirections to /dev/tcp or /dev/udp are strong indicators of compromise.",
    ),
    (
        "reverse_shell_netcat",
        "critical",
        "reverse_shell",
        "Potential reverse/bind shell using netcat or mkfifo",
        re.compile(r"(?i)\b(?:nc|ncat|netcat)\b[^\n]{0,80}(?:\s-e\s|\s-c\s|/bin/(?:ba)?sh)|\bmkfifo\s+/tmp/[^\n]{0,60}\|\s*(?:nc|sh|bash)\b"),
        "Inspect this file immediately. Netcat shell execution and named-pipe shells are commonly used for unauthorized remote access.",
    ),
    (
        "reverse_shell_python",
        "critical",
        "reverse_shell",
        "Potential Python socket reverse shell",
        re.compile(r"(?s)socket\.socket\([^)]*\).*?\.connect\([^)]*\).*?(?:os\.dup2|pty\.spawn|subprocess\.(?:call|Popen|run))"),
        "Inspect this file immediately. Connecting a raw socket directly to OS file descriptors or a shell indicates a reverse shell.",
    ),
    (
        "reverse_shell_powershell",
        "critical",
        "reverse_shell",
        "Potential PowerShell TCP reverse shell",
        re.compile(r"(?i)New-Object\s+System\.Net\.Sockets\.TCPClient"),
        "Inspect this file immediately. PowerShell TCPClient shells are commonly used in post-exploitation payloads.",
    ),
    (
        "dropper_curl_pipe_shell",
        "high",
        "dropper",
        "Remote script piped directly into a shell interpreter",
        re.compile(r"(?i)\b(?:curl|wget)\b[^\n|]{1,200}\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b"),
        "Review the remote URL and avoid piping unverified remote content directly into a shell.",
    ),
    (
        "dropper_powershell_encoded",
        "high",
        "dropper",
        "Obfuscated PowerShell download-and-execute pattern",
        re.compile(r"(?i)(?:powershell(?:\.exe)?\s+[^\n]{0,60}-(?:e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/=]{24,}|(?:IEX|Invoke-Expression)\s*\([^\n]{0,120}(?:DownloadString|WebClient|Invoke-WebRequest))"),
        "Decode and inspect the PowerShell payload before allowing it to remain on disk.",
    ),
    (
        "obfuscated_eval_base64",
        "high",
        "obfuscation",
        "Obfuscated dynamic code execution from encoded/compressed payload",
        re.compile(r"(?i)\b(?:eval|exec)\s*\(\s*(?:compile\s*\(\s*)?(?:base64\.b64decode|zlib\.decompress|codecs\.decode|bytes\.fromhex|atob)\s*\("),
        "Inspect the decoded payload. Legitimate software rarely executes base64-encoded or compressed code dynamically via eval/exec.",
    ),
    (
        "cryptominer_indicator",
        "high",
        "cryptominer",
        "Potential cryptocurrency miner configuration or pool URL",
        re.compile(r"(?i)(?:stratum\+(?:tcp|ssl)://|\bxmrig\b|\bcoinhive\b|\bmoneroocean\b|\bcryptonight\b)"),
        "Verify whether cryptocurrency mining software is authorized on this machine; unauthorized miners often indicate compromise.",
    ),
    (
        "persistence_cron_or_rc",
        "medium",
        "persistence",
        "Suspicious persistence mechanism modifying cron, shell rc, or autostart",
        re.compile(r"(?i)(?:\(\s*crontab\s+-l[^\n]{0,120}\|\s*crontab\s+-|>>\s*~?/?\.(?:bashrc|zshrc|profile)\b[^\n]{0,120}(?:curl|wget|nc\s|base64|python)|HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run)"),
        "Review whether this script is expected to install startup persistence.",
    ),
    (
        "credential_exfiltration",
        "high",
        "exfiltration",
        "Potential credential theft and outbound network exfiltration",
        re.compile(r"(?is)(?:\.ssh/id_rsa|\.aws/credentials|Login Data|key4\.db|/etc/shadow|\.env\b)[^\x00]{0,400}(?:requests\.post|urllib\.request|http\.client|discord\.com/api/webhooks|api\.telegram\.org/bot|curl\s+[^\n]{0,80}-(?:d|F|X\s+POST))"),
        "Inspect this file immediately. Reading credential locations and sending data to an external endpoint indicates potential exfiltration.",
    ),
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
    if raw[:2] == b"MZ" and b"PE\x00\x00" in raw[:1024]:
        return "Windows PE executable"
    if raw[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"):
        return "Mach-O binary"
    if raw[:4] == b"\xca\xfe\xba\xbe":
        return "Java class / Mach-O universal binary"
    return None


def load_ioc_hashes(state_dir: Path | None) -> dict[str, str]:
    """Return built-in + optional user-configured SHA-256 IOC hashes."""
    hashes = dict(BUILTIN_IOC_HASHES)
    if state_dir is None:
        return hashes
    ioc_path = Path(state_dir) / "ioc_blocklist.json"
    if not ioc_path.is_file() or ioc_path.is_symlink():
        return hashes
    try:
        raw = ioc_path.read_bytes()[:1048576]
        data = json.loads(raw.decode("utf-8"))
        if isinstance(data, dict):
            entries = data.get("hashes", data)
            if isinstance(entries, dict):
                for h, desc in entries.items():
                    if isinstance(h, str) and re.fullmatch(r"[0-9a-fA-F]{64}", h):
                        hashes[h.lower()] = str(desc)[:200]
            elif isinstance(entries, list):
                for h in entries:
                    if isinstance(h, str) and re.fullmatch(r"[0-9a-fA-F]{64}", h):
                        hashes[h.lower()] = "User IOC blocklist match"
        elif isinstance(data, list):
            for h in data:
                if isinstance(h, str) and re.fullmatch(r"[0-9a-fA-F]{64}", h):
                    hashes[h.lower()] = "User IOC blocklist match"
    except (OSError, ValueError, UnicodeError):
        pass
    return hashes


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
    """Run all built-in security/AV checks on a single file's bytes."""
    clean_path = sanitise(raw_path) if callable(sanitise) else raw_path
    path_obj = Path(raw_path)
    suffix = path_obj.suffix.lower()
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

    # 2. SHA-256 IOC blocklist check
    digest = sha256 or hashlib.sha256(raw).hexdigest()
    blocklist = ioc_hashes if ioc_hashes is not None else BUILTIN_IOC_HASHES
    if digest.lower() in blocklist and "eicar_test_signature" not in seen_rules:
        add_finding(
            "ioc_sha256_match",
            "critical",
            "ioc_hash",
            "File matches known-malicious SHA-256 hash (IOC)",
            {"detector": "ioc_blocklist", "sha256": digest.lower(), "description": blocklist[digest.lower()]},
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

    # Skip text regex heuristics on binary files (null bytes present)
    if b"\x00" in raw[:8192]:
        return findings

    if suffix and suffix not in _SCANNABLE_TEXT_EXTENSIONS:
        # Also allow extensionless scripts that start with a shebang (#!)
        if not raw.startswith(b"#!"):
            return findings

    try:
        text = raw.decode("utf-8", errors="ignore")
    except Exception:
        return findings

    # 4. Trojan Source / Unicode Bidi & zero-width obfuscation check
    bidi_found = [f"U+{ord(ch):04X}" for ch in _BIDI_CHARS if ch in text]
    if bidi_found:
        add_finding(
            "trojan_source_bidi",
            "high",
            "trojan_source",
            "Hidden Unicode bidirectional control characters (Trojan Source)",
            {"detector": "unicode_audit", "codepoints": sorted(bidi_found)},
            "Inspect the raw bytes of this file. Bidirectional override characters can hide malicious logic from human reviewers.",
        )
    zw_count = sum(text.count(ch) for ch in _ZERO_WIDTH_CHARS)
    if zw_count >= 12:
        add_finding(
            "hidden_zero_width_cluster",
            "medium",
            "trojan_source",
            "Suspicious cluster of invisible zero-width Unicode characters",
            {"detector": "unicode_audit", "zero_width_count": zw_count},
            "Inspect this file for hidden steganographic or prompt-injection payloads encoded with zero-width characters.",
        )

    # 5. Malware & security heuristic rules
    # Skip self-scanning custodian/scanner.py rule definitions
    if path_obj.name == "scanner.py" and "_HEURISTIC_RULES" in text:
        return findings

    for rule_id, severity, category, title, pattern, recommendation in _HEURISTIC_RULES:
        match = pattern.search(text)
        if match:
            snippet = match.group(0).strip().replace("\n", " ")[:100]
            line_no = text.count("\n", 0, match.start()) + 1
            add_finding(
                rule_id,
                severity,
                category,
                title,
                {
                    "detector": "builtin_heuristic",
                    "line": line_no,
                    "match_preview": sanitise(snippet) if callable(sanitise) else snippet,
                },
                recommendation,
            )

    # 6. AI agent / skill prompt-injection checks
    if suffix in _AGENT_PROMPT_EXTENSIONS:
        for rule_id, severity, category, title, pattern, recommendation in _AGENT_SECURITY_RULES:
            match = pattern.search(text)
            if match:
                snippet = match.group(0).strip().replace("\n", " ")[:100]
                line_no = text.count("\n", 0, match.start()) + 1
                add_finding(
                    rule_id,
                    severity,
                    category,
                    title,
                    {
                        "detector": "agent_security",
                        "line": line_no,
                        "match_preview": sanitise(snippet) if callable(sanitise) else snippet,
                    },
                    recommendation,
                )

    return findings


def detect_system_av() -> dict[str, Any]:
    """Detect available local system antivirus engines without running a scan."""
    if _platform.NAME == "windows":
        candidates = [
            Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Windows Defender" / "MpCmdRun.exe",
        ]
        for exe in candidates:
            if exe.is_file():
                return {
                    "available": True,
                    "engine": "windows_defender",
                    "label": "Windows Defender",
                    "binary": str(exe),
                    "builtin_heuristics": True,
                }
        return {
            "available": False,
            "engine": None,
            "label": "Built-in scanner only",
            "binary": None,
            "builtin_heuristics": True,
            "note": "Windows Defender CLI (MpCmdRun.exe) not found; built-in heuristic & IOC scanner is active.",
        }

    # Linux / macOS: check for ClamAV (clamdscan preferred, then clamscan)
    for name in ("clamdscan", "clamscan"):
        found = shutil.which(name)
        if not found:
            for prefix in ("/usr/bin", "/usr/local/bin", "/opt/homebrew/bin"):
                cand = Path(prefix) / name
                if cand.is_file() and os.access(cand, os.X_OK):
                    found = str(cand)
                    break
        if found:
            version = None
            try:
                res = subprocess.run(
                    [found, "--version"],
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
            return {
                "available": True,
                "engine": name,
                "label": f"ClamAV ({name})",
                "binary": found,
                "version": version,
                "builtin_heuristics": True,
            }

    return {
        "available": False,
        "engine": None,
        "label": "Built-in scanner only",
        "binary": None,
        "builtin_heuristics": True,
        "note": "ClamAV not installed (install clamav for signature-based AV). Built-in heuristic, IOC & agent security scanner is active.",
    }


def _run_clamav_scan(
    binary: str,
    engine_name: str,
    roots: list[Path],
    *,
    started: str,
    scope_signature: str,
    sanitise=None,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Run ClamAV against approved roots with bounded timeout and safe fixed args."""
    findings: list[dict[str, Any]] = []
    errors: list[str] = []
    for root in roots:
        if engine_name == "clamdscan":
            argv = [binary, "--no-summary", "--infected", "--fdpass", str(root)]
        else:
            argv = [binary, "--recursive", "--infected", "--no-summary", "--max-filesize=16M", "--max-scansize=64M", str(root)]
        try:
            res = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=45,
                check=False,
                env=minimal_env("av"),
            )
        except subprocess.TimeoutExpired:
            errors.append(f"ClamAV scan timed out on {root}")
            continue
        except OSError as exc:
            errors.append(f"ClamAV unavailable: {exc}")
            break
        # ClamAV exit codes: 0 = clean, 1 = virus found, 2 = error
        if res.returncode == 2:
            # If clamdscan daemon isn't running, try falling back to clamscan
            if engine_name == "clamdscan":
                fallback = shutil.which("clamscan") or ("/usr/bin/clamscan" if Path("/usr/bin/clamscan").is_file() else None)
                if fallback:
                    f_sub, e_sub = _run_clamav_scan(
                        fallback, "clamscan", [root], started=started, scope_signature=scope_signature, sanitise=sanitise
                    )
                    findings.extend(f_sub)
                    errors.extend(e_sub)
                    continue
            err_msg = (res.stderr or res.stdout or "ClamAV scan error").strip().splitlines()[:1]
            errors.append(f"ClamAV error: {err_msg[0] if err_msg else 'exit 2'}")
            continue
        for line in res.stdout.splitlines():
            line = line.strip()
            if not line or not line.endswith(" FOUND"):
                continue
            parts = line.rsplit(":", 1)
            if len(parts) != 2:
                continue
            raw_path = parts[0].strip()
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
    return findings, errors


def _run_yara_scan(
    state_dir: Path | None,
    roots: list[Path],
    *,
    started: str,
    scope_signature: str,
    sanitise=None,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Run optional user-supplied YARA rules from <state_dir>/yara_rules/ if yara CLI is installed."""
    if state_dir is None:
        return [], []
    rules_dir = Path(state_dir) / "yara_rules"
    if not rules_dir.is_dir() or rules_dir.is_symlink():
        return [], []
    rule_files = sorted(
        p for p in rules_dir.iterdir()
        if p.is_file() and not p.is_symlink() and p.suffix.lower() in (".yar", ".yara")
    )[:20]
    if not rule_files:
        return [], []
    yara_bin = shutil.which("yara")
    if not yara_bin:
        return [], []
    findings: list[dict[str, Any]] = []
    errors: list[str] = []
    for rule_file in rule_files:
        for root in roots:
            try:
                res = subprocess.run(
                    [yara_bin, "-r", str(rule_file), str(root)],
                    capture_output=True,
                    text=True,
                    timeout=20,
                    check=False,
                    env=minimal_env("yara"),
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                errors.append(f"YARA scan failed for {rule_file.name}: {exc}")
                continue
            for line in res.stdout.splitlines():
                parts = line.strip().split(" ", 1)
                if len(parts) != 2:
                    continue
                rule_name, raw_path = parts[0].strip(), parts[1].strip()
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
    return findings, errors


def _safe_read_file(path: Path, max_bytes: int) -> bytes | None:
    """Safely read a regular, non-symlink file without following links."""
    try:
        if _platform.IS_WINDOWS:
            return _platform.read_file_nofollow(path, max_bytes=max_bytes)
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size <= 0 or info.st_size > max_bytes:
                return None
            chunks: list[bytes] = []
            remaining = info.st_size
            while remaining > 0:
                chunk = os.read(fd, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
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

    Never opens or reads files marked sensitive by policy.is_sensitive().
    Returns (findings, errors, av_summary).
    """
    if policy_module is None:
        from . import policy as policy_module

    is_sensitive = getattr(policy_module, "is_sensitive", lambda _p: False)
    sanitise = getattr(policy_module, "sanitise_text", str)

    findings: list[dict[str, Any]] = []
    errors: list[str] = []
    ioc_hashes = load_ioc_hashes(state_dir)
    max_file_bytes = min(int(settings.get("max_file_bytes", MAX_SCAN_FILE_BYTES)), MAX_SCAN_FILE_BYTES)
    deadline = time.monotonic() + MAX_SCAN_SECONDS
    bytes_read = 0
    files_inspected = 0

    for raw_path, item in sorted(files.items()):
        if time.monotonic() >= deadline or bytes_read >= MAX_SCAN_TOTAL_BYTES:
            break
        if item.get("type", "file") != "file":
            continue
        path_obj = Path(raw_path)

        # Metadata-only SUID/SGID check (never opens file)
        mode = item.get("mode", 0)
        if isinstance(mode, int) and (mode & (stat.S_ISUID | stat.S_ISGID)):
            clean_path = sanitise(raw_path)
            findings.append({
                "id": _finding_id("suid_sgid_bit", raw_path),
                "severity": "high",
                "category": "privilege_escalation",
                "title": "File has SUID/SGID privilege-escalation bit set",
                "path": clean_path,
                "evidence": {"detector": "metadata_audit", "mode": oct(mode), "category": "privilege_escalation"},
                "recommendation": "Verify why a file in your watched scope has SUID/SGID bits set; remove with chmod u-s,g-s if unintended.",
                "first_seen": started,
                "last_seen": started,
                "status": "open",
                "scope_signature": scope_signature,
            })

        # Privacy invariant: NEVER open sensitive credential/memory/chat files
        if is_sensitive(path_obj):
            continue

        # Fast IOC check if snapshot already computed SHA-256
        existing_sha = item.get("sha256")
        if existing_sha and existing_sha.lower() in ioc_hashes:
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
                    "description": ioc_hashes[existing_sha.lower()],
                    "category": "ioc_hash",
                },
                "recommendation": "Quarantine or delete this file immediately.",
                "first_seen": started,
                "last_seen": started,
                "status": "open",
                "scope_signature": scope_signature,
            })

        size = item.get("size", 0)
        if not isinstance(size, int) or size <= 0 or size > max_file_bytes:
            continue
        if bytes_read + size > MAX_SCAN_TOTAL_BYTES:
            continue

        raw = _safe_read_file(path_obj, max_file_bytes)
        if raw is None:
            continue
        bytes_read += len(raw)
        files_inspected += 1

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

    # Optional YARA rules
    yara_findings, yara_errors = _run_yara_scan(
        state_dir, roots, started=started, scope_signature=scope_signature, sanitise=sanitise
    )
    findings.extend(yara_findings)
    errors.extend(yara_errors)

    # Optional system antivirus integration (ClamAV / Windows Defender)
    av_info = detect_system_av()
    av_used = False
    if settings.get("use_system_av", True) and av_info.get("available"):
        engine_name = av_info.get("engine")
        binary = av_info.get("binary")
        if engine_name in ("clamdscan", "clamscan") and binary:
            av_used = True
            av_findings, av_errors = _run_clamav_scan(
                binary, engine_name, roots, started=started, scope_signature=scope_signature, sanitise=sanitise
            )
            findings.extend(av_findings)
            errors.extend(av_errors)

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
    }
    return list(deduped.values()), errors, av_summary
