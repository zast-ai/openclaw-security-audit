#!/usr/bin/env python3
"""Module 08: Session & Memory Checks (SM-001 ~ SM-005)

Attack Surface: AS-3 (Prompt Injection → Memory Poisoning), AS-7 (File system)
Threats: Memory poisoning persistence, session log leakage
Handbook: §5.7, §6.8, §1.3
"""

import os
import re
import time

from ..utils import (
    CRITICAL, HIGH, MEDIUM, INFO,
    PASS, FAIL, WARN, SKIP, ERROR,
    make_result, read_file_safe, get_file_mtime_days_ago,
    get_dir_total_size, format_size,
)

MODULE_NAME = "08_session_memory"


def run_checks(openclaw_dir, **kwargs):
    """Run all 5 session/memory checks. Returns list of result dicts."""
    results = []
    results.append(_sm001(openclaw_dir))
    results.append(_sm002(openclaw_dir))
    results.append(_sm003(openclaw_dir))
    results.append(_sm004(openclaw_dir))
    results.append(_sm005(openclaw_dir))
    return results


# SM-001: MEMORY.md suspicious injection patterns (§5.7)
def _sm001(openclaw_dir):
    check_id = "SM-001"
    name = "MEMORY.md suspicious injection patterns"

    memory_paths = [
        os.path.join(openclaw_dir, "MEMORY.md"),
        os.path.join(openclaw_dir, "memory", "MEMORY.md"),
    ]

    content = None
    found_path = None
    for p in memory_paths:
        content = read_file_safe(p)
        if content is not None:
            found_path = p
            break

    if content is None:
        return make_result(check_id, name, HIGH, SKIP,
                           "MEMORY.md not found",
                           threat_ids=["AS-3"], handbook_ref="§5.7")

    # Suspicious patterns indicating memory poisoning
    injection_patterns = [
        (r'ignore\s*(all\s*)?(previous\s*)?instruction', "ignore instruction pattern"),
        (r'system\s*prompt', "system prompt reference"),
        (r'curl\s+https?://', "curl with URL"),
        (r'fetch\s*\(\s*["\']https?://', "fetch() with URL"),
        (r'wget\s+https?://', "wget with URL"),
        (r'<script', "HTML script tag"),
        (r'eval\s*\(', "eval() call"),
        (r'exec\s*\(', "exec() call"),
        (r'child_process', "child_process reference"),
        (r'subprocess', "subprocess reference"),
        (r'\\x[0-9a-f]{2}', "hex escape sequences"),
        (r'base64\s*[\.\-]*(decode|encode)', "base64 encode/decode"),
    ]

    # Strip markdown code blocks and inline code before scanning —
    # technical notes in code blocks are not injection attempts
    stripped_content = re.sub(r'```[\s\S]*?```', '', content)  # fenced code blocks
    stripped_content = re.sub(r'`[^`]+`', '', stripped_content)  # inline code

    found_suspicious = []
    for pattern, desc in injection_patterns:
        matches = re.findall(pattern, stripped_content, re.IGNORECASE)
        if matches:
            found_suspicious.append(f"{desc} ({len(matches)} match(es))")

    if not found_suspicious:
        return make_result(check_id, name, HIGH, PASS,
                           "No suspicious injection patterns found in MEMORY.md",
                           threat_ids=["AS-3"], handbook_ref="§5.7",
                           evidence=f"file={found_path}")

    detail = f"Found {len(found_suspicious)} suspicious pattern type(s) in MEMORY.md — possible memory poisoning"
    evidence = "; ".join(found_suspicious[:5])
    if len(found_suspicious) > 5:
        evidence += f" ... and {len(found_suspicious) - 5} more"

    return make_result(check_id, name, HIGH, FAIL, detail,
                       threat_ids=["AS-3"], handbook_ref="§5.7",
                       fix_cmd=f"Manually review {found_path} for injected content",
                       evidence=evidence)


# SM-002: memory/ directory anomalous files (§5.7)
def _sm002(openclaw_dir):
    check_id = "SM-002"
    name = "Memory directory anomalous files"

    memory_dir = os.path.join(openclaw_dir, "memory")
    if not os.path.isdir(memory_dir):
        return make_result(check_id, name, MEDIUM, SKIP,
                           "memory/ directory not found",
                           threat_ids=["AS-3"], handbook_ref="§5.7")

    seven_days_ago = time.time() - (7 * 86400)
    recent_files = []

    try:
        for f in os.listdir(memory_dir):
            fpath = os.path.join(memory_dir, f)
            if os.path.isfile(fpath):
                try:
                    mtime = os.path.getmtime(fpath)
                    if mtime > seven_days_ago:
                        days = int((time.time() - mtime) / 86400)
                        recent_files.append(f"{f} ({days}d ago)")
                except OSError:
                    pass
    except Exception:
        return make_result(check_id, name, MEDIUM, ERROR,
                           "Failed to scan memory directory",
                           threat_ids=["AS-3"], handbook_ref="§5.7")

    if not recent_files:
        return make_result(check_id, name, MEDIUM, PASS,
                           "No recently modified files in memory/ directory",
                           threat_ids=["AS-3"], handbook_ref="§5.7")

    detail = f"Found {len(recent_files)} file(s) modified in the last 7 days — verify they are legitimate"
    evidence = "; ".join(recent_files[:10])
    if len(recent_files) > 10:
        evidence += f" ... and {len(recent_files) - 10} more"

    return make_result(check_id, name, MEDIUM, WARN, detail,
                       threat_ids=["AS-3"], handbook_ref="§5.7",
                       evidence=evidence)


# SM-003: Old session log cleanup (§6.8)
def _sm003(openclaw_dir):
    check_id = "SM-003"
    name = "Old session log cleanup"

    sessions_dir = os.path.join(openclaw_dir, "sessions")
    if not os.path.isdir(sessions_dir):
        return make_result(check_id, name, INFO, SKIP,
                           "sessions/ directory not found",
                           threat_ids=["AS-7"], handbook_ref="§6.8")

    old_files = []
    try:
        for root, dirs, files in os.walk(sessions_dir):
            for f in files:
                if f.endswith(".jsonl") or f.endswith(".json") or f.endswith(".log"):
                    fpath = os.path.join(root, f)
                    days = get_file_mtime_days_ago(fpath)
                    if days is not None and days > 30:
                        old_files.append(f"{f} ({days}d old)")
    except Exception:
        return make_result(check_id, name, INFO, ERROR,
                           "Failed to scan sessions directory",
                           threat_ids=["AS-7"], handbook_ref="§6.8")

    if not old_files:
        return make_result(check_id, name, INFO, PASS,
                           "No session logs older than 30 days",
                           threat_ids=["AS-7"], handbook_ref="§6.8")

    detail = f"Found {len(old_files)} session log(s) older than 30 days — should be cleaned up"
    evidence = "; ".join(old_files[:10])
    if len(old_files) > 10:
        evidence += f" ... and {len(old_files) - 10} more"

    return make_result(check_id, name, INFO, WARN, detail,
                       threat_ids=["AS-7"], handbook_ref="§6.8",
                       fix_cmd=f'find {sessions_dir} -name "*.jsonl" -mtime +30 -delete',
                       evidence=evidence)


# SM-004: Session log total size (§6.8)
def _sm004(openclaw_dir):
    check_id = "SM-004"
    name = "Session log total size"

    sessions_dir = os.path.join(openclaw_dir, "sessions")
    if not os.path.isdir(sessions_dir):
        return make_result(check_id, name, INFO, SKIP,
                           "sessions/ directory not found",
                           threat_ids=["AS-7"], handbook_ref="§6.8")

    total = get_dir_total_size(sessions_dir)
    size_str = format_size(total)

    if total > 100 * 1024 * 1024:  # > 100MB
        return make_result(check_id, name, INFO, WARN,
                           f"Session logs total {size_str} — consider cleanup",
                           threat_ids=["AS-7"], handbook_ref="§6.8",
                           fix_cmd=f'find {sessions_dir} -name "*.jsonl" -mtime +30 -delete',
                           evidence=f"total_size={size_str}")

    return make_result(check_id, name, INFO, PASS,
                       f"Session logs total {size_str}",
                       threat_ids=["AS-7"], handbook_ref="§6.8",
                       evidence=f"total_size={size_str}")


# SM-005: Workspace isolation check (§1.3)
def _sm005(openclaw_dir):
    check_id = "SM-005"
    name = "Workspace isolation check"

    if not os.path.isdir(openclaw_dir):
        return make_result(check_id, name, INFO, SKIP,
                           "OpenClaw directory not found",
                           threat_ids=["AS-7"], handbook_ref="§1.3")

    workspace_indicators = ["workspaces", "projects", "workspace"]
    workspace_dirs = []

    try:
        for item in os.listdir(openclaw_dir):
            item_path = os.path.join(openclaw_dir, item)
            if os.path.isdir(item_path):
                if item.lower() in workspace_indicators:
                    # Count subdirectories as workspaces
                    try:
                        subs = [d for d in os.listdir(item_path)
                                if os.path.isdir(os.path.join(item_path, d))]
                        workspace_dirs.extend(subs)
                    except OSError:
                        pass
    except Exception:
        return make_result(check_id, name, INFO, ERROR,
                           "Failed to scan for workspaces",
                           threat_ids=["AS-7"], handbook_ref="§1.3")

    if len(workspace_dirs) <= 1:
        return make_result(check_id, name, INFO, PASS,
                           f"Found {len(workspace_dirs)} workspace(s) — isolation not needed or already separate",
                           threat_ids=["AS-7"], handbook_ref="§1.3",
                           evidence=f"workspaces={workspace_dirs}" if workspace_dirs else "no workspace dirs found")

    return make_result(check_id, name, INFO, WARN,
                       f"[Advisory] Found {len(workspace_dirs)} workspace(s) — "
                       "consider using independent config per workspace for multi-project isolation",
                       threat_ids=["AS-7"], handbook_ref="§1.3",
                       evidence=f"workspaces: {', '.join(workspace_dirs[:10])}")
