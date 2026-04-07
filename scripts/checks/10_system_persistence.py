#!/usr/bin/env python3
"""Module 10: System Persistence Checks (SP-001 ~ SP-004)

Attack Surface: Malicious Skill persistence backdoors
Threats: T-PERSIST-001
Handbook: §11.4
"""

import os
import re

from ..utils import (
    CRITICAL, HIGH, MEDIUM, INFO,
    PASS, FAIL, WARN, SKIP, ERROR,
    make_result, run_cmd, read_file_safe, is_macos, is_linux,
)

MODULE_NAME = "10_system_persistence"


def run_checks(openclaw_dir, **kwargs):
    """Run all 4 system persistence checks. Returns list of result dicts."""
    results = []
    results.append(_sp001())
    results.append(_sp002())
    results.append(_sp003())
    results.append(_sp004())
    return results


# SP-001: crontab entries related to openclaw (§11.4)
def _sp001():
    check_id = "SP-001"
    name = "Crontab OpenClaw-related entries"

    rc, out, err = run_cmd(["crontab", "-l"])
    if rc != 0:
        # No crontab or access denied
        if "no crontab" in err.lower() or "no crontab" in out.lower():
            return make_result(check_id, name, HIGH, PASS,
                               "No crontab entries found",
                               threat_ids=["AS-5"], handbook_ref="§11.4")
        return make_result(check_id, name, HIGH, ERROR,
                           f"Failed to read crontab: {err[:200]}",
                           threat_ids=["AS-5"], handbook_ref="§11.4")

    suspicious = []
    patterns = [r'openclaw', r'\bclaw\b', r'\.openclaw']
    for line_no, line in enumerate(out.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#") or not stripped:
            continue
        for pattern in patterns:
            if re.search(pattern, stripped, re.IGNORECASE):
                suspicious.append(f"line {line_no}: {stripped[:120]}")
                break

    if not suspicious:
        return make_result(check_id, name, HIGH, PASS,
                           "No OpenClaw-related crontab entries found",
                           threat_ids=["AS-5"], handbook_ref="§11.4")

    detail = f"Found {len(suspicious)} crontab entry(ies) referencing OpenClaw — verify they are legitimate"
    evidence = "; ".join(suspicious[:5])
    if len(suspicious) > 5:
        evidence += f" ... and {len(suspicious) - 5} more"

    return make_result(check_id, name, HIGH, WARN, detail,
                       threat_ids=["AS-5"], handbook_ref="§11.4",
                       fix_cmd="crontab -e  # Review and remove suspicious entries",
                       evidence=evidence)


# SP-002: macOS launchd services (§11.4)
def _sp002():
    check_id = "SP-002"
    name = "macOS launchd OpenClaw-related services"

    if not is_macos():
        return make_result(check_id, name, HIGH, SKIP,
                           "Not macOS — launchd check skipped",
                           threat_ids=["AS-5"], handbook_ref="§11.4")

    suspicious = []

    # Check user LaunchAgents
    home = os.path.expanduser("~")
    launch_dirs = [
        os.path.join(home, "Library", "LaunchAgents"),
        "/Library/LaunchAgents",
        "/Library/LaunchDaemons",
    ]

    for launch_dir in launch_dirs:
        if not os.path.isdir(launch_dir):
            continue
        try:
            for f in os.listdir(launch_dir):
                if re.search(r'\bopenclaw\b|\bclaw\b', f, re.IGNORECASE):
                    suspicious.append(f"{launch_dir}/{f}")
        except OSError:
            pass

    # Also check launchctl list output
    rc, out, _ = run_cmd(["launchctl", "list"])
    if rc == 0:
        for line in out.splitlines():
            if re.search(r'\bopenclaw\b|\bclaw\b', line, re.IGNORECASE):
                suspicious.append(f"launchctl: {line.strip()[:120]}")

    if not suspicious:
        return make_result(check_id, name, HIGH, PASS,
                           "No OpenClaw-related launchd services found",
                           threat_ids=["AS-5"], handbook_ref="§11.4")

    detail = f"Found {len(suspicious)} launchd entry(ies) referencing OpenClaw — verify they are legitimate"
    evidence = "; ".join(suspicious[:5])
    if len(suspicious) > 5:
        evidence += f" ... and {len(suspicious) - 5} more"

    return make_result(check_id, name, HIGH, WARN, detail,
                       threat_ids=["AS-5"], handbook_ref="§11.4",
                       fix_cmd="launchctl unload <plist_path>  # Remove suspicious services",
                       evidence=evidence)


# SP-003: Linux systemd services (§11.4)
def _sp003():
    check_id = "SP-003"
    name = "Linux systemd OpenClaw-related services"

    if not is_linux():
        return make_result(check_id, name, INFO, SKIP,
                           "Not Linux — systemd check skipped",
                           threat_ids=["AS-5"], handbook_ref="§11.4")

    suspicious = []

    # Check user systemd units
    rc, out, _ = run_cmd(["systemctl", "--user", "list-units", "--all", "--no-pager"])
    if rc == 0:
        for line in out.splitlines():
            if re.search(r'\bopenclaw\b|\bclaw\b', line, re.IGNORECASE):
                suspicious.append(f"user unit: {line.strip()[:120]}")

    # Check system-wide units
    rc, out, _ = run_cmd(["systemctl", "list-units", "--all", "--no-pager"])
    if rc == 0:
        for line in out.splitlines():
            if re.search(r'\bopenclaw\b|\bclaw\b', line, re.IGNORECASE):
                suspicious.append(f"system unit: {line.strip()[:120]}")

    # Check systemd unit files in common paths
    systemd_dirs = [
        os.path.expanduser("~/.config/systemd/user/"),
        "/etc/systemd/system/",
        "/usr/lib/systemd/system/",
    ]
    for sd_dir in systemd_dirs:
        if not os.path.isdir(sd_dir):
            continue
        try:
            for f in os.listdir(sd_dir):
                if re.search(r'\bopenclaw\b|\bclaw\b', f, re.IGNORECASE):
                    suspicious.append(f"{sd_dir}{f}")
        except OSError:
            pass

    if not suspicious:
        return make_result(check_id, name, INFO, PASS,
                           "No OpenClaw-related systemd services found",
                           threat_ids=["AS-5"], handbook_ref="§11.4")

    detail = (f"Found {len(suspicious)} systemd entry(ies) referencing OpenClaw — "
              f"this is normal for an active installation; review if unexpected")
    evidence = "; ".join(suspicious[:5])

    return make_result(check_id, name, INFO, WARN, detail,
                       threat_ids=["AS-5"], handbook_ref="§11.4",
                       fix_cmd="systemctl --user disable <service>  # Remove if unexpected",
                       evidence=evidence)


# SP-004: Shell startup file checks (§11.4)
def _sp004():
    check_id = "SP-004"
    name = "Shell startup file OpenClaw-related entries"

    home = os.path.expanduser("~")
    shell_files = [
        os.path.join(home, ".bashrc"),
        os.path.join(home, ".bash_profile"),
        os.path.join(home, ".profile"),
        os.path.join(home, ".zshrc"),
        os.path.join(home, ".zprofile"),
        os.path.join(home, ".zshenv"),
    ]

    suspicious = []
    for sf in shell_files:
        content = read_file_safe(sf)
        if content is None:
            continue
        for line_no, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if re.search(r'\bopenclaw\b|\.openclaw|\bclaw\b', stripped, re.IGNORECASE):
                fname = os.path.basename(sf)
                suspicious.append(f"{fname}:{line_no}: {stripped[:100]}")

    if not suspicious:
        return make_result(check_id, name, INFO, PASS,
                           "No OpenClaw-related entries in shell startup files",
                           threat_ids=["AS-5"], handbook_ref="§11.4")

    detail = (f"Found {len(suspicious)} shell startup entry(ies) referencing OpenClaw — "
              f"this is normal for PATH/completion setup; review if unexpected")
    evidence = "; ".join(suspicious[:5])
    if len(suspicious) > 5:
        evidence += f" ... and {len(suspicious) - 5} more"

    return make_result(check_id, name, INFO, WARN, detail,
                       threat_ids=["AS-5"], handbook_ref="§11.4",
                       fix_cmd="Review and remove if unexpected",
                       evidence=evidence)
