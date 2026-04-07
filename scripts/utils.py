#!/usr/bin/env python3
"""OpenClaw Security Audit - Utility functions and shared types."""

import json
import os
import platform
import re
import subprocess
import sys
import time
from pathlib import Path

# --- Severity levels ---
CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"
INFO = "info"

# --- Status values ---
PASS = "PASS"
FAIL = "FAIL"
WARN = "WARN"
SKIP = "SKIP"
ERROR = "ERROR"

# --- Terminal colors ---
COLORS = {
    "critical": "\033[91m",  # Red
    "high": "\033[93m",      # Orange/Yellow bright
    "medium": "\033[33m",    # Yellow
    "info": "\033[94m",      # Blue
    "pass": "\033[92m",      # Green
    "skip": "\033[90m",      # Gray
    "error": "\033[95m",     # Magenta
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
}

TOOL_VERSION = "1.0.0"


# --- Confidence levels ---
CONFIDENCE_HIGH = "high"       # Deterministic proof / concrete config state
CONFIDENCE_MEDIUM = "medium"   # Strong heuristic match
CONFIDENCE_LOW = "low"         # Pattern match / manual review recommended

# Default confidence by status: FAIL/ERROR → high (concrete finding),
# WARN → medium (heuristic), PASS/SKIP → high (deterministic check).
_DEFAULT_CONFIDENCE = {
    FAIL: CONFIDENCE_HIGH,
    ERROR: CONFIDENCE_HIGH,
    WARN: CONFIDENCE_MEDIUM,
    PASS: CONFIDENCE_HIGH,
    SKIP: CONFIDENCE_HIGH,
}


def make_result(check_id, name, severity, status, detail,
                threat_ids=None, threat_refs=None, handbook_ref="",
                fix_cmd="", evidence="", confidence=None):
    """Create a standardized check result dict.

    confidence: "high" | "medium" | "low" | None (auto-assigned by status).
    """
    if confidence is None:
        # Auto-assign: [Advisory] items get low confidence
        if "[Advisory]" in detail:
            confidence = CONFIDENCE_LOW
        else:
            confidence = _DEFAULT_CONFIDENCE.get(status, CONFIDENCE_MEDIUM)

    return {
        "id": check_id,
        "name": name,
        "severity": severity,
        "status": status,
        "detail": detail,
        "threat_ids": threat_ids or [],
        "threat_refs": threat_refs or [],
        "handbook_ref": handbook_ref,
        "fix_cmd": fix_cmd,
        "evidence": evidence,
        "confidence": confidence,
    }


def run_cmd(cmd, timeout=15, shell=False, cwd=None):
    """Run a command and return (returncode, stdout, stderr).

    Returns (returncode, stdout, stderr). On timeout or error, returncode=-1.
    """
    try:
        r = subprocess.run(
            cmd if shell else cmd,
            capture_output=True, text=True, timeout=timeout,
            shell=shell, cwd=cwd,
        )
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0] if isinstance(cmd, list) else cmd}"
    except subprocess.TimeoutExpired:
        return -1, "", f"Command timed out after {timeout}s"
    except Exception as e:
        return -1, "", str(e)


def parse_grep_hit(line):
    """Parse a grep -n output line into (filepath, line_number, content).

    Handles Windows paths with drive letters (e.g. C:\\path\\file.py:123:content)
    where a naive split(":", 2) would break on the drive letter colon.

    Returns (filepath, lineno_str, content) or None if parsing fails.
    """
    # Windows drive letter: single letter followed by ':'
    if len(line) >= 2 and line[1] == ':' and line[0].isalpha():
        # Skip drive letter prefix, parse the rest
        rest = line[2:]
        parts = rest.split(":", 2)
        if len(parts) >= 3:
            return (line[0:2] + parts[0], parts[1], parts[2])
        return None
    parts = line.split(":", 2)
    if len(parts) >= 3:
        return (parts[0], parts[1], parts[2])
    return None


def grep_files(pattern, path, recursive=True, extra_args=None):
    """Run grep and return list of matching lines.

    Returns list of strings (each line is 'filename:lineno:content').
    """
    if not os.path.exists(path):
        return []
    cmd = ["grep", "-rn" if recursive else "-n"]
    if extra_args:
        cmd.extend(extra_args)
    cmd.extend([pattern, path])
    rc, out, _ = run_cmd(cmd, timeout=30)
    if rc == 0 and out:
        return out.splitlines()
    return []


def grep_files_with_context(pattern, path, context_lines=5, recursive=True, extra_args=None):
    """Run grep and return matches with surrounding context.

    Returns list of dicts: {file, line_no, match_line, context}
    where context is the full block of lines around the match.
    """
    if not os.path.exists(path):
        return []
    cmd = ["grep", f"-{'r' if recursive else ''}n", f"-C{context_lines}"]
    if extra_args:
        cmd.extend(extra_args)
    cmd.extend([pattern, path])
    rc, out, _ = run_cmd(cmd, timeout=30)
    if rc != 0 or not out:
        return []

    results = []
    # grep -C output separates groups with '--'
    groups = re.split(r'^--$', out, flags=re.MULTILINE)
    for group in groups:
        lines = group.strip().splitlines()
        if not lines:
            continue
        match_line = ""
        match_file = ""
        match_line_no = 0
        context_block = []
        for line in lines:
            # grep -n -C format: file:linenum:content (match) or file:linenum-content (context)
            m = re.match(r'^(.+?):(\d+)([:-])(.*)$', line)
            if m:
                fname, lno, sep, content = m.group(1), int(m.group(2)), m.group(3), m.group(4)
                context_block.append(content)
                if sep == ':':  # actual match line
                    match_line = content
                    match_file = fname
                    match_line_no = lno
        if match_file:
            results.append({
                "file": match_file,
                "line_no": match_line_no,
                "match_line": match_line,
                "context": "\n".join(context_block),
            })
    return results


def is_macos():
    return platform.system() == "Darwin"


def is_linux():
    return platform.system() == "Linux"


def is_windows():
    return platform.system() == "Windows"


def get_os_name():
    s = platform.system()
    if s == "Darwin":
        return "macOS"
    return s


def get_file_permission_octal(filepath):
    """Return file permission as octal string (e.g. '700', '600').

    Returns None if file doesn't exist.
    """
    try:
        st = os.stat(filepath)
        mode = oct(st.st_mode & 0o777)
        return mode[2:]  # strip '0o'
    except FileNotFoundError:
        return None
    except Exception:
        return None


def get_file_mtime_days_ago(filepath):
    """Return how many days ago the file was last modified.

    Returns None if file doesn't exist.
    """
    try:
        mtime = os.path.getmtime(filepath)
        days = (time.time() - mtime) / 86400
        return int(days)
    except Exception:
        return None


def load_json_file(filepath):
    """Load and return a JSON file, stripping JS-style comments.

    Returns None on error.
    """
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
        # Strip single-line JS comments (// ...) that are common in config files
        # Be careful not to strip URLs (http:// or https://)
        content = re.sub(r'(?<!:)//.*?$', '', content, flags=re.MULTILINE)
        return json.loads(content)
    except (FileNotFoundError, json.JSONDecodeError, Exception):
        return None


def get_nested(d, *keys, default=None):
    """Safely traverse nested dict keys."""
    for k in keys:
        if not isinstance(d, dict):
            return default
        d = d.get(k, default)
    return d


def read_file_safe(filepath, max_size=10 * 1024 * 1024):
    """Read file content safely. Returns None if file doesn't exist or is too large."""
    try:
        size = os.path.getsize(filepath)
        if size > max_size:
            return None
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return None


def get_dir_total_size(dirpath):
    """Return total size of all files in a directory in bytes."""
    total = 0
    try:
        for root, dirs, files in os.walk(dirpath):
            for f in files:
                try:
                    total += os.path.getsize(os.path.join(root, f))
                except OSError:
                    pass
    except Exception:
        pass
    return total


def format_size(size_bytes):
    """Format bytes to human readable string."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"


def resolve_openclaw_dir(user_specified=None):
    """Resolve the OpenClaw directory path."""
    if user_specified:
        return os.path.expanduser(user_specified)
    return os.path.expanduser("~/.openclaw")


def check_command_exists(cmd_name):
    """Check if a command exists in PATH."""
    rc, _, _ = run_cmd(["which", cmd_name] if not is_windows() else ["where", cmd_name])
    return rc == 0


def get_env_var(name):
    """Get environment variable value, return None if not set."""
    return os.environ.get(name)
