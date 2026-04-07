#!/usr/bin/env python3
"""Module 11: Windows-Specific Checks (WIN-001 ~ WIN-002)

Attack Surface: AS-12 (Windows-specific)
Threats: CVE-2024-27980
Handbook: §9.4
"""

import os
import re

from ..utils import (
    CRITICAL, HIGH, MEDIUM, INFO,
    PASS, FAIL, WARN, SKIP, ERROR,
    make_result, run_cmd, is_windows,
)

MODULE_NAME = "11_windows_checks"


def run_checks(openclaw_dir, **kwargs):
    """Run all 2 Windows-specific checks. Returns list of result dicts."""
    if not is_windows():
        return [
            make_result("WIN-001", "Node.js version (Windows)", CRITICAL, SKIP,
                        "Not Windows — check skipped",
                        threat_ids=["AS-12"], handbook_ref="§9.4"),
            make_result("WIN-002", "Suspicious .bat/.cmd in PATH (Windows)", MEDIUM, SKIP,
                        "Not Windows — check skipped",
                        threat_ids=["AS-12"], handbook_ref="§9.4"),
        ]

    results = []
    results.append(_win001())
    results.append(_win002())
    return results


def _parse_version(version_str):
    """Parse version string like 'v20.11.1' into tuple (20, 11, 1)."""
    match = re.search(r'v?(\d+)\.(\d+)\.(\d+)', version_str)
    if match:
        return (int(match.group(1)), int(match.group(2)), int(match.group(3)))
    return None


# WIN-001: Node.js version >= 20.11.1 (CVE-2024-27980)
def _win001():
    check_id = "WIN-001"
    name = "Node.js version (CVE-2024-27980 fix)"

    rc, out, _ = run_cmd(["node", "--version"])
    if rc != 0:
        return make_result(check_id, name, CRITICAL, SKIP,
                           "Node.js not found — cannot check version",
                           threat_ids=["AS-12"], handbook_ref="§9.4")

    version = _parse_version(out.strip())
    if version is None:
        return make_result(check_id, name, CRITICAL, ERROR,
                           f"Cannot parse Node.js version: {out[:50]}",
                           threat_ids=["AS-12"], handbook_ref="§9.4",
                           evidence=f"output={out[:100]}")

    # CVE-2024-27980 fixed in Node.js 20.11.1
    min_version = (20, 11, 1)

    if version >= min_version:
        return make_result(check_id, name, CRITICAL, PASS,
                           f"Node.js {out.strip()} >= 20.11.1 (CVE-2024-27980 patched)",
                           threat_ids=["AS-12"], handbook_ref="§9.4",
                           evidence=f"version={out.strip()}")

    return make_result(check_id, name, CRITICAL, FAIL,
                       f"Node.js {out.strip()} < 20.11.1 — vulnerable to CVE-2024-27980 "
                       f"(command injection via .bat/.cmd child_process)",
                       threat_ids=["AS-12"], handbook_ref="§9.4",
                       fix_cmd="Update Node.js: nvm install 20.11.1 or download from nodejs.org",
                       evidence=f"version={out.strip()}")


# WIN-002: Suspicious .bat/.cmd files in PATH (§9.4)
def _win002():
    check_id = "WIN-002"
    name = "Suspicious .bat/.cmd in PATH"

    path_dirs = os.environ.get("PATH", "").split(os.pathsep)
    suspicious = []

    # Known safe directories
    safe_prefixes = [
        os.environ.get("SYSTEMROOT", r"C:\Windows").lower(),
        os.environ.get("PROGRAMFILES", r"C:\Program Files").lower(),
        os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)").lower(),
    ]

    for d in path_dirs:
        d_lower = d.lower()
        # Skip known safe directories
        if any(d_lower.startswith(safe) for safe in safe_prefixes):
            continue

        if not os.path.isdir(d):
            continue

        try:
            for f in os.listdir(d):
                f_lower = f.lower()
                if f_lower.endswith(".bat") or f_lower.endswith(".cmd"):
                    suspicious.append(os.path.join(d, f))
        except OSError:
            pass

    if not suspicious:
        return make_result(check_id, name, MEDIUM, PASS,
                           "No suspicious .bat/.cmd files found in non-system PATH directories",
                           threat_ids=["AS-12"], handbook_ref="§9.4")

    detail = (f"Found {len(suspicious)} .bat/.cmd file(s) in non-system PATH directories — "
              f"could be exploited via CVE-2024-27980 child_process injection")
    evidence = "; ".join(suspicious[:10])
    if len(suspicious) > 10:
        evidence += f" ... and {len(suspicious) - 10} more"

    return make_result(check_id, name, MEDIUM, WARN, detail,
                       threat_ids=["AS-12"], handbook_ref="§9.4",
                       fix_cmd="Review and remove untrusted .bat/.cmd files from PATH directories",
                       evidence=evidence)
