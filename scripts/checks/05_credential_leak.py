#!/usr/bin/env python3
"""Module 05: Credential Leak Checks (CL-001 ~ CL-008)

Attack Surface: AS-6 (Data exfiltration), AS-7 (Credentials)
Threats: T-EXFIL-003, T-DISC-004
Handbook: §6.2, §6.4, §6.6, §6.7, §6.8, §9.6
"""

import os
import re

from ..utils import (
    CRITICAL, HIGH, MEDIUM, INFO,
    PASS, FAIL, WARN, SKIP, ERROR,
    make_result, run_cmd, grep_files, read_file_safe, get_file_mtime_days_ago,
    parse_grep_hit,
)

MODULE_NAME = "05_credential_leak"

_THREAT_IDS = ["AS-6", "AS-7"]
_THREAT_REFS = ["T-EXFIL-003", "T-DISC-004"]


def run_checks(openclaw_dir, **kwargs):
    """Run all 8 credential leak checks. Returns list of result dicts."""
    results = []
    results.append(_cl001(openclaw_dir))
    results.append(_cl002(openclaw_dir))
    results.append(_cl003(openclaw_dir))
    results.append(_cl004(openclaw_dir))
    results.append(_cl005(openclaw_dir))
    results.append(_cl006(openclaw_dir))
    results.append(_cl007(openclaw_dir))
    results.append(_cl008())
    return results


# ---------------------------------------------------------------------------
# CL-001: API keys in session logs
# ---------------------------------------------------------------------------
def _cl001(openclaw_dir):
    check_id = "CL-001"
    name = "API keys in session logs"
    sessions_dir = os.path.join(openclaw_dir, "sessions")

    if not os.path.isdir(sessions_dir):
        return make_result(check_id, name, CRITICAL, SKIP,
                           "sessions/ directory does not exist",
                           threat_ids=_THREAT_IDS, threat_refs=_THREAT_REFS,
                           handbook_ref="§6.8")

    # Search for common API key prefixes — require sufficient trailing chars
    # to avoid false positives from words like "task-", "risk-", "flask-"
    patterns = [
        ("sk-ant-", []),                                     # Anthropic key (exact prefix, always suspicious)
        ("sk-[A-Za-z0-9]\\{20,\\}", []),                    # OpenAI-style key (sk- + 20+ alnum)
        ("AKIA[A-Z0-9]\\{12,\\}", []),                      # AWS access key (AKIA + 12+ upper/digit)
    ]
    all_matches = []
    for pat, extra in patterns:
        hits = grep_files(pat, sessions_dir, extra_args=extra)
        all_matches.extend(hits)

    if all_matches:
        evidence = _truncate_evidence(all_matches)
        return make_result(check_id, name, CRITICAL, FAIL,
                           f"Found {len(all_matches)} line(s) containing API key patterns in sessions/",
                           threat_ids=_THREAT_IDS, threat_refs=_THREAT_REFS,
                           handbook_ref="§6.8",
                           fix_cmd=f"Review and purge sensitive data from {sessions_dir}",
                           evidence=evidence)

    return make_result(check_id, name, CRITICAL, PASS,
                       "No API key patterns found in session logs",
                       threat_ids=_THREAT_IDS, threat_refs=_THREAT_REFS,
                       handbook_ref="§6.8")


# ---------------------------------------------------------------------------
# CL-002: Passwords/tokens in session logs
# ---------------------------------------------------------------------------
def _cl002(openclaw_dir):
    check_id = "CL-002"
    name = "Passwords/tokens in session logs"
    sessions_dir = os.path.join(openclaw_dir, "sessions")

    if not os.path.isdir(sessions_dir):
        return make_result(check_id, name, HIGH, SKIP,
                           "sessions/ directory does not exist",
                           threat_ids=_THREAT_IDS, threat_refs=_THREAT_REFS,
                           handbook_ref="§6.8")

    # Require assignment context (key=value, key: value, key "value") to avoid
    # false positives from normal discussion text like "password policy" or
    # "the secret to success"
    patterns = [
        (r'password\s*[=:]\s*\S+', ["-E", "-i"]),           # password=xxx or password: xxx
        (r'"password"\s*:\s*"[^"]+"', ["-E"]),               # JSON "password": "value"
        (r'secret\s*[=:]\s*\S+', ["-E", "-i"]),             # secret=xxx or secret: xxx
        (r'"secret"\s*:\s*"[^"]+"', ["-E"]),                 # JSON "secret": "value"
        (r'private[._]key\s*[=:]\s*\S+', ["-E", "-i"]),     # private.key=xxx or private_key: xxx
    ]
    all_matches = []
    for pat, extra in patterns:
        hits = grep_files(pat, sessions_dir, extra_args=extra)
        all_matches.extend(hits)

    if all_matches:
        evidence = _truncate_evidence(all_matches)
        return make_result(check_id, name, HIGH, FAIL,
                           f"Found {len(all_matches)} line(s) with password/secret/key references in sessions/",
                           threat_ids=_THREAT_IDS, threat_refs=_THREAT_REFS,
                           handbook_ref="§6.8",
                           fix_cmd=f"Review and purge sensitive data from {sessions_dir}",
                           evidence=evidence)

    return make_result(check_id, name, HIGH, PASS,
                       "No password/secret/key patterns found in session logs",
                       threat_ids=_THREAT_IDS, threat_refs=_THREAT_REFS,
                       handbook_ref="§6.8")


# ---------------------------------------------------------------------------
# CL-003: Sensitive data in debug logs
# ---------------------------------------------------------------------------
def _cl003(openclaw_dir):
    check_id = "CL-003"
    name = "Sensitive data in debug logs"
    logs_dir = os.path.join(openclaw_dir, "logs")

    if not os.path.isdir(logs_dir):
        return make_result(check_id, name, HIGH, SKIP,
                           "logs/ directory does not exist",
                           threat_ids=_THREAT_IDS, threat_refs=_THREAT_REFS,
                           handbook_ref="§6.2")

    # Use precise patterns with assignment/header context to avoid false positives
    # from normal log text like "cookie policy", "password reset flow", etc.
    patterns = [
        ("sk-ant-", []),                                      # Anthropic API key prefix (always suspicious)
        ("sk-[A-Za-z0-9]\\{20,\\}", []),                     # OpenAI-style key (sk- + 20+ alnum, BRE)
        (r'password\s*[=:]\s*\S+', ["-E", "-i"]),            # password=xxx or password: xxx
        (r'"password"\s*:\s*"[^"]+"', ["-E"]),                # JSON "password": "value"
        (r'[Ss]et-[Cc]ookie:\s*\S+', ["-E"]),                # Set-Cookie: header (actual cookie values)
        (r'cookie\s*[=:]\s*\S+', ["-E", "-i"]),              # cookie=xxx or cookie: xxx (assignment)
        ("Bearer [A-Za-z0-9]", ["-E", "-i"]),                # Authorization bearer tokens
        ("Authorization:", ["-i"]),                           # Authorization headers
        ("access_token=", ["-i"]),                            # OAuth access tokens in URLs/params
        ("refresh_token=", ["-i"]),                           # OAuth refresh tokens
    ]
    all_matches = []
    for pat, extra in patterns:
        hits = grep_files(pat, logs_dir, extra_args=extra)
        all_matches.extend(hits)

    if all_matches:
        evidence = _truncate_evidence(all_matches)
        return make_result(check_id, name, HIGH, FAIL,
                           f"Found {len(all_matches)} line(s) with sensitive patterns in logs/",
                           threat_ids=_THREAT_IDS, threat_refs=_THREAT_REFS,
                           handbook_ref="§6.2",
                           fix_cmd=f"Review and purge sensitive data from {logs_dir}; configure log redaction",
                           evidence=evidence)

    return make_result(check_id, name, HIGH, PASS,
                       "No sensitive patterns found in debug logs",
                       threat_ids=_THREAT_IDS, threat_refs=_THREAT_REFS,
                       handbook_ref="§6.2")


# ---------------------------------------------------------------------------
# CL-004: .env plaintext key format
# ---------------------------------------------------------------------------
_RAW_KEY_PATTERNS = [
    re.compile(r'^sk-[A-Za-z0-9_-]{20,}'),        # OpenAI / Anthropic style
    re.compile(r'^AKIA[A-Z0-9]{12,}'),             # AWS access key
    re.compile(r'^sk-ant-[A-Za-z0-9_-]{20,}'),     # Anthropic API key
    re.compile(r'^ghp_[A-Za-z0-9]{30,}'),          # GitHub PAT
    re.compile(r'^gho_[A-Za-z0-9]{30,}'),          # GitHub OAuth
    re.compile(r'^xox[bporas]-[A-Za-z0-9-]{10,}'), # Slack token
]


def _cl004(openclaw_dir):
    check_id = "CL-004"
    name = ".env plaintext key format"
    env_path = os.path.join(openclaw_dir, ".env")

    content = read_file_safe(env_path)
    if content is None:
        return make_result(check_id, name, MEDIUM, SKIP,
                           ".env file not found or unreadable",
                           threat_ids=_THREAT_IDS, threat_refs=_THREAT_REFS,
                           handbook_ref="§2.1")

    plaintext_keys = []
    for line_num, line in enumerate(content.splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip().strip('"').strip("'")

        # Skip if using env reference or secretRef patterns
        if value.startswith("${") or value.startswith("env:") or value.startswith("secretRef:"):
            continue

        for pat in _RAW_KEY_PATTERNS:
            if pat.match(value):
                # Redact the value for evidence — show first 8 chars only
                redacted = value[:8] + "..." if len(value) > 8 else value
                plaintext_keys.append(f"line {line_num}: {key.strip()}={redacted}")
                break

    if plaintext_keys:
        evidence = "; ".join(plaintext_keys[:10])
        if len(plaintext_keys) > 10:
            evidence += f" ... and {len(plaintext_keys) - 10} more"
        return make_result(check_id, name, MEDIUM, WARN,
                           f"Found {len(plaintext_keys)} plaintext API key(s) in .env — "
                           "recommend using secretRef or env: references",
                           threat_ids=_THREAT_IDS, threat_refs=_THREAT_REFS,
                           handbook_ref="§2.1",
                           fix_cmd="Replace plaintext keys with secretRef: or env: references in .env",
                           evidence=evidence)

    return make_result(check_id, name, MEDIUM, PASS,
                       "No plaintext API keys detected in .env values",
                       threat_ids=_THREAT_IDS, threat_refs=_THREAT_REFS,
                       handbook_ref="§2.1")


# ---------------------------------------------------------------------------
# CL-005: OAuth token rotation check
# ---------------------------------------------------------------------------
_TOKEN_ROTATION_THRESHOLD_DAYS = 90


def _cl005(openclaw_dir):
    check_id = "CL-005"
    name = "OAuth token rotation check"
    creds_dir = os.path.join(openclaw_dir, "credentials")

    if not os.path.isdir(creds_dir):
        return make_result(check_id, name, MEDIUM, SKIP,
                           "credentials/ directory does not exist",
                           threat_ids=_THREAT_IDS, threat_refs=_THREAT_REFS,
                           handbook_ref="§6.7")

    stale_files = []
    total_files = 0

    for root, _dirs, files in os.walk(creds_dir):
        for fname in files:
            fpath = os.path.join(root, fname)
            total_files += 1
            days_ago = get_file_mtime_days_ago(fpath)
            if days_ago is not None and days_ago > _TOKEN_ROTATION_THRESHOLD_DAYS:
                stale_files.append(f"{fpath} ({days_ago}d)")

    if total_files == 0:
        return make_result(check_id, name, MEDIUM, SKIP,
                           "No credential files found in credentials/",
                           threat_ids=_THREAT_IDS, threat_refs=_THREAT_REFS,
                           handbook_ref="§6.7")

    if stale_files:
        evidence = "; ".join(stale_files[:10])
        if len(stale_files) > 10:
            evidence += f" ... and {len(stale_files) - 10} more"
        return make_result(check_id, name, MEDIUM, WARN,
                           f"{len(stale_files)}/{total_files} credential file(s) not modified in "
                           f">{_TOKEN_ROTATION_THRESHOLD_DAYS} days — consider rotating tokens",
                           threat_ids=_THREAT_IDS, threat_refs=_THREAT_REFS,
                           handbook_ref="§6.7",
                           fix_cmd="Rotate OAuth tokens and regenerate credential files",
                           evidence=evidence)

    return make_result(check_id, name, MEDIUM, PASS,
                       f"All {total_files} credential file(s) modified within {_TOKEN_ROTATION_THRESHOLD_DAYS} days",
                       threat_ids=_THREAT_IDS, threat_refs=_THREAT_REFS,
                       handbook_ref="§6.7")


# ---------------------------------------------------------------------------
# CL-006: Hardcoded token in config file
# ---------------------------------------------------------------------------
# Match quoted hex strings of 32+ chars (common token format)
_HARDCODED_TOKEN_RE = re.compile(r'''["']([0-9a-fA-F]{32,})["']''')


def _cl006(openclaw_dir):
    check_id = "CL-006"
    name = "Hardcoded token in config files"

    # Note: openclaw.json is already scanned by GW-004 for hardcoded tokens.
    # We skip it here to avoid duplicate findings.
    config_files = [
        os.path.join(openclaw_dir, "config.json"),
        os.path.join(openclaw_dir, "config.yaml"),
        os.path.join(openclaw_dir, "config.yml"),
        os.path.join(openclaw_dir, "settings.json"),
    ]

    # Also scan any .json / .yaml / .yml in the openclaw dir (non-recursive)
    # Exclude openclaw.json — already covered by GW-004
    openclaw_json_path = os.path.join(openclaw_dir, "openclaw.json")
    try:
        for entry in os.scandir(openclaw_dir):
            if entry.is_file() and entry.path != openclaw_json_path:
                lower = entry.name.lower()
                if lower.endswith((".json", ".yaml", ".yml", ".toml")):
                    if entry.path not in config_files:
                        config_files.append(entry.path)
    except OSError:
        pass

    found_tokens = []
    scanned = 0

    for cfg_path in config_files:
        content = read_file_safe(cfg_path)
        if content is None:
            continue
        scanned += 1
        for line_num, line in enumerate(content.splitlines(), start=1):
            for m in _HARDCODED_TOKEN_RE.finditer(line):
                token_val = m.group(1)
                redacted = token_val[:8] + "..." + token_val[-4:]
                found_tokens.append(
                    f"{os.path.basename(cfg_path)}:{line_num} → {redacted}"
                )

    if scanned == 0:
        return make_result(check_id, name, HIGH, SKIP,
                           "No config files found to scan",
                           threat_ids=_THREAT_IDS, threat_refs=_THREAT_REFS,
                           handbook_ref="§2.1")

    if found_tokens:
        evidence = "; ".join(found_tokens[:10])
        if len(found_tokens) > 10:
            evidence += f" ... and {len(found_tokens) - 10} more"
        return make_result(check_id, name, HIGH, FAIL,
                           f"Found {len(found_tokens)} hardcoded hex token(s) in config files",
                           threat_ids=_THREAT_IDS, threat_refs=_THREAT_REFS,
                           handbook_ref="§2.1",
                           fix_cmd="Move tokens to .env or a secrets manager; reference via env: or secretRef:",
                           evidence=evidence)

    return make_result(check_id, name, HIGH, PASS,
                       f"No hardcoded hex tokens found in {scanned} config file(s)",
                       threat_ids=_THREAT_IDS, threat_refs=_THREAT_REFS,
                       handbook_ref="§2.1")


# ---------------------------------------------------------------------------
# CL-007: base64 encoded values in .env
# ---------------------------------------------------------------------------
# Match base64 strings: 20+ chars of [A-Za-z0-9+/] ending with optional = padding
_BASE64_RE = re.compile(r'^[A-Za-z0-9+/]{20,}={0,2}$')


def _cl007(openclaw_dir):
    check_id = "CL-007"
    name = "base64 encoded values in .env"
    env_path = os.path.join(openclaw_dir, ".env")

    content = read_file_safe(env_path)
    if content is None:
        return make_result(check_id, name, MEDIUM, SKIP,
                           ".env file not found or unreadable",
                           threat_ids=_THREAT_IDS, threat_refs=_THREAT_REFS,
                           handbook_ref="§9.6")

    b64_entries = []
    for line_num, line in enumerate(content.splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip().strip('"').strip("'")

        if not value:
            continue

        # Check if value looks like base64
        if _BASE64_RE.match(value):
            # Heuristic: reject values that are just plain hex (already caught by CL-006)
            # and values that look like normal words
            if re.match(r'^[A-Za-z0-9_-]+$', value) and not value.endswith("="):
                # Could be a normal identifier; require at least mixed case + digits + length
                has_upper = any(c.isupper() for c in value)
                has_lower = any(c.islower() for c in value)
                has_digit = any(c.isdigit() for c in value)
                if not (has_upper and has_lower and has_digit and len(value) >= 24):
                    continue
            redacted = value[:12] + "..." if len(value) > 12 else value
            b64_entries.append(f"line {line_num}: {key.strip()}={redacted}")

    if b64_entries:
        evidence = "; ".join(b64_entries[:10])
        if len(b64_entries) > 10:
            evidence += f" ... and {len(b64_entries) - 10} more"
        return make_result(check_id, name, MEDIUM, WARN,
                           f"Found {len(b64_entries)} base64-encoded value(s) in .env — "
                           "these can bypass sanitize-env-vars.ts pattern matching",
                           threat_ids=_THREAT_IDS, threat_refs=_THREAT_REFS,
                           handbook_ref="§9.6",
                           fix_cmd="Decode and validate base64 values; ensure sanitize-env-vars.ts handles encoded secrets",
                           evidence=evidence)

    return make_result(check_id, name, MEDIUM, PASS,
                       "No base64-encoded values detected in .env",
                       threat_ids=_THREAT_IDS, threat_refs=_THREAT_REFS,
                       handbook_ref="§9.6")


# ---------------------------------------------------------------------------
# CL-008: Token leak in shell history
# ---------------------------------------------------------------------------
_HISTORY_PATTERNS = [
    r"OPENCLAW.*TOKEN",
    r"sk-ant-",
    r"sk-[A-Za-z0-9]\{20,\}",                    # sk- + 20+ alnum (BRE) — avoids "task-", "risk-" etc.
    r"AKIA[A-Z0-9]\{12,\}",                       # AWS key — require 12+ chars after AKIA
    r"OPENCLAW_API_KEY",
]


def _cl008():
    check_id = "CL-008"
    name = "Token leak in shell history"

    home = os.path.expanduser("~")
    history_files = [
        os.path.join(home, ".zsh_history"),
        os.path.join(home, ".bash_history"),
    ]

    all_matches = []
    files_checked = 0

    for hist_path in history_files:
        if not os.path.isfile(hist_path):
            continue
        files_checked += 1
        for pat in _HISTORY_PATTERNS:
            hits = grep_files(pat, hist_path, recursive=False)
            # Redact matched lines to avoid printing actual secrets
            for hit in hits:
                parsed = parse_grep_hit(hit)
                if parsed is not None:
                    fpath, lineno, content = parsed
                    # Redact anything that looks like a key value
                    redacted = re.sub(
                        r'(sk-ant-|sk-|AKIA)[A-Za-z0-9_-]+',
                        r'\1***REDACTED***',
                        content,
                    )
                    all_matches.append(f"{fpath}:{lineno}:{redacted}")
                else:
                    all_matches.append(hit)

    if files_checked == 0:
        return make_result(check_id, name, HIGH, SKIP,
                           "No shell history files found (~/.zsh_history, ~/.bash_history)",
                           threat_ids=_THREAT_IDS, threat_refs=_THREAT_REFS,
                           handbook_ref="§6.4")

    if all_matches:
        # Deduplicate
        unique_matches = list(dict.fromkeys(all_matches))
        evidence = _truncate_evidence(unique_matches)
        return make_result(check_id, name, HIGH, FAIL,
                           f"Found {len(unique_matches)} line(s) with token/key patterns in shell history — "
                           "setup.sh may print tokens that persist in history",
                           threat_ids=_THREAT_IDS, threat_refs=_THREAT_REFS,
                           handbook_ref="§6.4",
                           fix_cmd="Remove sensitive lines from shell history; "
                                   "prefix commands with a space to avoid history recording",
                           evidence=evidence)

    return make_result(check_id, name, HIGH, PASS,
                       f"No token/key patterns found in {files_checked} shell history file(s)",
                       threat_ids=_THREAT_IDS, threat_refs=_THREAT_REFS,
                       handbook_ref="§6.4")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _truncate_evidence(matches, max_lines=5, max_line_len=200):
    """Truncate evidence list for readable output."""
    lines = []
    for m in matches[:max_lines]:
        if len(m) > max_line_len:
            lines.append(m[:max_line_len] + "...")
        else:
            lines.append(m)
    if len(matches) > max_lines:
        lines.append(f"... and {len(matches) - max_lines} more match(es)")
    return "\n".join(lines)
