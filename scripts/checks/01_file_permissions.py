#!/usr/bin/env python3
"""Module 01: File System & Permission Checks (FP-001 ~ FP-010)

Attack Surface: AS-7 (File system & credentials)
Threats: Config hot-reload tampering, credential file permissions, cloud sync leak
Handbook: §1.2, §3.10, §6.1, §6.5, §6.9
"""

import os
import re
import stat
import subprocess

from ..utils import (
    CRITICAL, HIGH, MEDIUM, INFO,
    PASS, FAIL, WARN, SKIP, ERROR,
    make_result, run_cmd, is_macos, is_linux, get_file_permission_octal,
)

MODULE_NAME = "01_file_permissions"


def run_checks(openclaw_dir, **kwargs):
    """Run all 10 file permission checks. Returns list of result dicts."""
    results = []
    results.append(_fp001(openclaw_dir))
    results.append(_fp002(openclaw_dir))
    results.append(_fp003(openclaw_dir))
    results.append(_fp004(openclaw_dir))
    results.append(_fp005(openclaw_dir))
    results.append(_fp006(openclaw_dir))
    results.append(_fp007(openclaw_dir))
    results.append(_fp008(openclaw_dir))
    results.append(_fp009(openclaw_dir))
    results.append(_fp010())
    return results


def _check_path_permission(check_id, name, path, expected, severity, handbook_ref, fix_cmd):
    """Generic permission check for a path."""
    if not os.path.exists(path):
        return make_result(check_id, name, severity, SKIP,
                           f"Path does not exist: {path}",
                           threat_ids=["AS-7"], handbook_ref=handbook_ref)
    perm = get_file_permission_octal(path)
    if perm is None:
        return make_result(check_id, name, severity, ERROR,
                           f"Cannot read permission for: {path}",
                           threat_ids=["AS-7"], handbook_ref=handbook_ref)
    if perm == expected:
        return make_result(check_id, name, severity, PASS,
                           f"Permission is {perm} (expected {expected})",
                           threat_ids=["AS-7"], handbook_ref=handbook_ref,
                           evidence=f"mode={perm}")
    return make_result(check_id, name, severity, FAIL,
                       f"Permission is {perm}, should be {expected}",
                       threat_ids=["AS-7"], handbook_ref=handbook_ref,
                       fix_cmd=fix_cmd, evidence=f"mode={perm}")


# FP-001: ~/.openclaw/ directory permission must be 700
def _fp001(openclaw_dir):
    return _check_path_permission(
        "FP-001", "OpenClaw directory permission (~/.openclaw/)",
        openclaw_dir, "700", CRITICAL, "§6.1",
        f"chmod 700 {openclaw_dir}")


# FP-002: credentials/ directory permission must be 700
def _fp002(openclaw_dir):
    return _check_path_permission(
        "FP-002", "Credentials directory permission",
        os.path.join(openclaw_dir, "credentials"), "700", CRITICAL, "§6.1",
        f"chmod 700 {openclaw_dir}/credentials")


# FP-003: .env file permission must be 600
def _fp003(openclaw_dir):
    return _check_path_permission(
        "FP-003", ".env file permission",
        os.path.join(openclaw_dir, ".env"), "600", CRITICAL, "§6.1",
        f"chmod 600 {openclaw_dir}/.env")


# FP-004: openclaw.json file permission must be 600 (prevent hot-reload tampering §6.5)
def _fp004(openclaw_dir):
    return _check_path_permission(
        "FP-004", "openclaw.json file permission (hot-reload risk)",
        os.path.join(openclaw_dir, "openclaw.json"), "600", CRITICAL, "§6.5",
        f"chmod 600 {openclaw_dir}/openclaw.json")


# FP-005: sessions/ directory permission must be 700
def _fp005(openclaw_dir):
    return _check_path_permission(
        "FP-005", "Sessions directory permission",
        os.path.join(openclaw_dir, "sessions"), "700", HIGH, "§6.1",
        f"chmod 700 {openclaw_dir}/sessions")


# FP-006: Attachment files should not be group/other readable (§3.10)
#
# Scope: only scan directories that hold user-generated or exported content
# (sessions, attachments, uploads, exports, shared, media).
# Ordinary workspace/config directories are excluded to avoid flagging
# normal local working documents.
_FP006_SENSITIVE_DIRS = {
    "sessions", "attachments", "uploads", "exports", "shared", "media",
    "output", "downloads", "artifacts",
}


def _fp006(openclaw_dir):
    check_id = "FP-006"
    name = "Attachment file permissions (sensitive directories)"
    extensions = {".jpg", ".jpeg", ".png", ".gif", ".pdf", ".doc", ".docx", ".xls", ".xlsx"}
    overly_open = []

    if not os.path.isdir(openclaw_dir):
        return make_result(check_id, name, MEDIUM, SKIP,
                           f"OpenClaw directory not found: {openclaw_dir}",
                           threat_ids=["AS-7"], handbook_ref="§3.10")

    # Only scan sensitive subdirectories that may contain exported/shared content
    scanned_dirs = []
    for subdir in sorted(os.listdir(openclaw_dir)):
        if subdir.lower() in _FP006_SENSITIVE_DIRS:
            scanned_dirs.append(subdir)

    if not scanned_dirs:
        return make_result(check_id, name, MEDIUM, PASS,
                           "No sensitive attachment directories found to scan "
                           f"(checked for: {', '.join(sorted(_FP006_SENSITIVE_DIRS)[:5])}...)",
                           threat_ids=["AS-7"], handbook_ref="§3.10")

    try:
        for subdir in scanned_dirs:
            scan_root = os.path.join(openclaw_dir, subdir)
            for root, dirs, files in os.walk(scan_root):
                for f in files:
                    if any(f.lower().endswith(ext) for ext in extensions):
                        fpath = os.path.join(root, f)
                        try:
                            st = os.stat(fpath)
                            mode = st.st_mode
                            if mode & (stat.S_IRGRP | stat.S_IROTH):
                                perm = oct(mode & 0o777)[2:]
                                relpath = os.path.relpath(fpath, openclaw_dir)
                                overly_open.append(f"{relpath} ({perm})")
                        except OSError:
                            pass
    except Exception:
        return make_result(check_id, name, MEDIUM, ERROR,
                           "Failed to scan attachment files",
                           threat_ids=["AS-7"], handbook_ref="§3.10")

    if not overly_open:
        return make_result(check_id, name, MEDIUM, PASS,
                           f"No overly permissive attachment files in {', '.join(scanned_dirs)}",
                           threat_ids=["AS-7"], handbook_ref="§3.10",
                           evidence=f"scanned_dirs={scanned_dirs}")

    detail = (f"Found {len(overly_open)} attachment file(s) readable by group/other "
              f"in sensitive directories ({', '.join(scanned_dirs)})")
    evidence = "; ".join(overly_open[:10])
    if len(overly_open) > 10:
        evidence += f" ... and {len(overly_open) - 10} more"
    dirs_pattern = " -o ".join(f'-path "*/{d}/*"' for d in scanned_dirs)
    fix = (f'find {openclaw_dir} -type f '
           f'\\( -name "*.jpg" -o -name "*.png" -o -name "*.pdf" -o -name "*.doc*" \\) '
           f'\\( {dirs_pattern} \\) '
           f'-exec chmod 600 {{}} \\;')
    return make_result(check_id, name, MEDIUM, FAIL, detail,
                       threat_ids=["AS-7"], handbook_ref="§3.10",
                       fix_cmd=fix, evidence=evidence)


# FP-007: Config file immutable flag (§6.5)
def _fp007(openclaw_dir):
    check_id = "FP-007"
    name = "Config file immutable flag (chattr/uchg)"
    config_path = os.path.join(openclaw_dir, "openclaw.json")

    if not os.path.exists(config_path):
        return make_result(check_id, name, INFO, SKIP,
                           "openclaw.json not found",
                           threat_ids=["AS-7"], handbook_ref="§6.5")

    immutable = False
    if is_macos():
        rc, out, _ = run_cmd(["ls", "-lO", config_path])
        if rc == 0 and "uchg" in out:
            immutable = True
        fix = f"chflags uchg {config_path}"
    elif is_linux():
        rc, out, _ = run_cmd(["lsattr", config_path])
        if rc == 0 and "i" in out.split()[0] if out else False:
            immutable = True
        fix = f"sudo chattr +i {config_path}"
    else:
        return make_result(check_id, name, INFO, SKIP,
                           "Immutable flag check not supported on this OS",
                           threat_ids=["AS-7"], handbook_ref="§6.5")

    if immutable:
        return make_result(check_id, name, INFO, PASS,
                           "Config file has immutable flag set",
                           threat_ids=["AS-7"], handbook_ref="§6.5")
    return make_result(check_id, name, INFO, WARN,
                       "Config file does not have immutable flag — recommended to prevent hot-reload tampering",
                       threat_ids=["AS-7"], handbook_ref="§6.5",
                       fix_cmd=fix)


# FP-008: .openclaw/ not in cloud sync directory (§6.9)
def _fp008(openclaw_dir):
    check_id = "FP-008"
    name = "OpenClaw directory not in cloud sync path"

    real_path = os.path.realpath(openclaw_dir).lower()
    home = os.path.expanduser("~").lower()

    cloud_dirs = [
        os.path.join(home, "library/mobile documents"),  # iCloud
        os.path.join(home, "onedrive"),
        os.path.join(home, "google drive"),
        os.path.join(home, "dropbox"),
        os.path.join(home, "library/cloudstorage"),
    ]

    for cloud_dir in cloud_dirs:
        if real_path.startswith(cloud_dir):
            return make_result(check_id, name, HIGH, FAIL,
                               f"OpenClaw directory is inside cloud sync: {cloud_dir}",
                               threat_ids=["AS-7"], handbook_ref="§6.9",
                               fix_cmd=f"Move {openclaw_dir} outside of cloud-synced directories",
                               evidence=f"realpath={os.path.realpath(openclaw_dir)}")

    return make_result(check_id, name, HIGH, PASS,
                       "OpenClaw directory is not in a cloud sync path",
                       threat_ids=["AS-7"], handbook_ref="§6.9")


# FP-009: .openclaw/ not tracked by git (§6.9)
def _fp009(openclaw_dir):
    check_id = "FP-009"
    name = "OpenClaw directory not tracked by git"

    # Check if .git exists inside openclaw dir
    if os.path.isdir(os.path.join(openclaw_dir, ".git")):
        return make_result(check_id, name, HIGH, FAIL,
                           f"{openclaw_dir} is itself a git repository",
                           threat_ids=["AS-7"], handbook_ref="§6.9",
                           fix_cmd=f"rm -rf {openclaw_dir}/.git",
                           evidence=".git directory found")

    # Check if openclaw dir is inside a git repo
    rc, out, _ = run_cmd(["git", "-C", openclaw_dir, "rev-parse", "--is-inside-work-tree"])
    if rc == 0 and out.strip() == "true":
        return make_result(check_id, name, HIGH, FAIL,
                           f"{openclaw_dir} is inside a git repository work tree",
                           threat_ids=["AS-7"], handbook_ref="§6.9",
                           fix_cmd=f"Add {openclaw_dir} to .gitignore",
                           evidence="git rev-parse confirms inside work tree")

    return make_result(check_id, name, HIGH, PASS,
                       "OpenClaw directory is not tracked by git",
                       threat_ids=["AS-7"], handbook_ref="§6.9")


# FP-010: Running user should not be in docker/sudo/wheel group (§1.2)
def _fp010():
    check_id = "FP-010"
    name = "Running user group membership"

    rc, out, _ = run_cmd(["id"])
    if rc != 0:
        return make_result(check_id, name, HIGH, ERROR,
                           "Failed to run 'id' command",
                           threat_ids=["AS-7"], handbook_ref="§1.2")

    # On macOS, "admin" is a default group for all users and does not grant
    # the same elevated privileges as Linux "sudo" or "wheel". Exclude it on macOS.
    dangerous_groups = {"docker", "sudo", "wheel", "root"}
    if not is_macos():
        dangerous_groups.add("admin")
    # Parse groups from id output: groups=20(staff),12(everyone),...
    groups_match = re.search(r'groups=(.+)', out)
    if not groups_match:
        return make_result(check_id, name, HIGH, ERROR,
                           "Cannot parse group membership from 'id' output",
                           threat_ids=["AS-7"], handbook_ref="§1.2",
                           evidence=out[:200])

    found_dangerous = []
    groups_str = groups_match.group(1)
    for g in re.findall(r'\((\w+)\)', groups_str):
        if g.lower() in dangerous_groups:
            found_dangerous.append(g)

    if found_dangerous:
        return make_result(check_id, name, HIGH, WARN,
                           f"Current user is in privileged group(s): {', '.join(found_dangerous)} — "
                           f"OpenClaw should run as a dedicated low-privilege user",
                           threat_ids=["AS-7"], handbook_ref="§1.2",
                           fix_cmd="sudo useradd -m -s /bin/bash openclaw-user && sudo su - openclaw-user",
                           evidence=f"groups: {groups_str[:200]}")

    return make_result(check_id, name, HIGH, PASS,
                       "Current user is not in privileged groups (docker/sudo/wheel)",
                       threat_ids=["AS-7"], handbook_ref="§1.2",
                       evidence=f"groups: {groups_str[:200]}")
