#!/usr/bin/env python3
"""OpenClaw Security Audit - Main Script

Usage:
  python3 openclaw_audit.py [options]

Options:
  --openclaw-dir PATH       OpenClaw directory (default: ~/.openclaw/)
  --modules MOD1,MOD2       Only run specified modules (01,02,...11)
  --skip MOD1,MOD2          Skip specified modules
  --remote HOST[:PORT]      Check remote instance port exposure (can repeat)
  --docker-name NAME        Docker container name (default: openclaw-sandbox)
  --compose-file PATH       Path to docker-compose.yml
  --output-dir PATH         Report output directory (default: ./openclaw-audit-report/)
  --format terminal|md|both Output format (default: both)
  --severity LEVEL          Minimum display level: critical|high|medium|info (default: info)
  --fix                     Include fix command suggestions
  --json                    Also output JSON format (for CI/CD)
  --checklist               Include §9.3 periodic checklist table
"""

import argparse
import os
import platform
import re
import sys
from datetime import datetime

# Setup import paths — works whether invoked as `python3 scripts/openclaw_audit.py`
# from the skill root, or as `python3 /full/path/to/scripts/openclaw_audit.py` from anywhere.
script_dir = os.path.dirname(os.path.abspath(__file__))
skill_root = os.path.dirname(script_dir)
if skill_root not in sys.path:
    sys.path.insert(0, skill_root)

from scripts.utils import (
    CRITICAL, HIGH, MEDIUM, INFO,
    PASS, FAIL, WARN, SKIP, ERROR,
    COLORS, TOOL_VERSION,
    run_cmd, resolve_openclaw_dir, check_command_exists,
    get_os_name, is_macos, is_linux, is_windows,
)
from scripts.report_generator import write_reports, generate_terminal_report


# All available check modules
ALL_MODULES = {
    "01": ("01_file_permissions", "File System & Permissions"),
    "02": ("02_gateway_config", "Gateway Configuration"),
    "03": ("03_network_exposure", "Network Exposure"),
    "04": ("04_channel_config", "Channel Configuration"),
    "05": ("05_credential_leak", "Credential Leak Detection"),
    "06": ("06_skill_audit", "Skill Supply Chain Audit"),
    "07": ("07_sandbox_docker", "Sandbox & Docker"),
    "08": ("08_session_memory", "Session & Memory"),
    "09": ("09_agent_behavior", "Agent Behavior Configuration"),
    "10": ("10_system_persistence", "System Persistence"),
    "11": ("11_windows_checks", "Windows-Specific Checks"),
}


def detect_environment(openclaw_dir, docker_name):
    """Detect the runtime environment and return metadata dict."""
    meta = {
        "audit_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "target_dir": openclaw_dir,
        "os": get_os_name(),
        "os_version": platform.platform(),
        "openclaw_version": "unknown",
        "docker_available": False,
        "docker_name": docker_name,
        "openclaw_dir_exists": os.path.isdir(openclaw_dir),
    }

    # Detect OpenClaw version
    rc, out, _ = run_cmd(["openclaw", "--version"])
    if rc == 0 and out:
        meta["openclaw_version"] = out.strip()
    else:
        # Try npm
        rc, out, _ = run_cmd(["npm", "list", "-g", "openclaw", "--depth=0"])
        if rc == 0 and "openclaw@" in out:
            m = re.search(r'openclaw@([\d.]+)', out)
            if m:
                meta["openclaw_version"] = m.group(1)

    # Detect Docker
    rc, _, _ = run_cmd(["docker", "info"], timeout=5)
    meta["docker_available"] = (rc == 0)

    return meta


def load_module(module_id):
    """Dynamically import a check module by ID."""
    if module_id not in ALL_MODULES:
        return None

    module_name = ALL_MODULES[module_id][0]
    try:
        mod = __import__(f"scripts.checks.{module_name}", fromlist=["run_checks"])
        return mod
    except ImportError as e:
        print(f"  Warning: Cannot import module {module_id} ({module_name}): {e}",
              file=sys.stderr)
        return None


def run_audit(args):
    """Main audit execution."""
    openclaw_dir = resolve_openclaw_dir(args.openclaw_dir)
    docker_name = args.docker_name or "openclaw-sandbox"

    bold = COLORS.get("bold", "")
    reset = COLORS.get("reset", "")
    dim = COLORS.get("dim", "")

    print(f"\n{bold}OpenClaw Security Audit v{TOOL_VERSION}{reset}")
    print(f"{dim}Based on ZAST.AI Security Handbook{reset}\n")

    # Environment detection
    print(f"  Detecting environment...")
    meta = detect_environment(openclaw_dir, docker_name)

    print(f"  Target:   {meta['target_dir']}")
    print(f"  OS:       {meta['os']} ({meta['os_version']})")
    print(f"  OpenClaw: {meta['openclaw_version']}")
    print(f"  Docker:   {'available' if meta['docker_available'] else 'not available'}")
    print(f"  Dir exists: {'yes' if meta['openclaw_dir_exists'] else 'NO'}")
    print()

    # Determine which modules to run
    if args.modules:
        module_ids = [m.strip().zfill(2) for m in args.modules.split(",")]
    else:
        module_ids = sorted(ALL_MODULES.keys())

    if args.skip:
        skip_ids = {m.strip().zfill(2) for m in args.skip.split(",")}
        module_ids = [m for m in module_ids if m not in skip_ids]

    # Parse whitelist once before the loop
    whitelist = [s.strip() for s in (args.whitelist or "").split(",") if s.strip()]

    # Run checks
    all_results = []
    for mid in module_ids:
        if mid not in ALL_MODULES:
            print(f"  Warning: Unknown module '{mid}', skipping", file=sys.stderr)
            continue

        mod_name, mod_desc = ALL_MODULES[mid]
        print(f"  [{mid}] {mod_desc}...", end=" ", flush=True)

        mod = load_module(mid)
        if mod is None:
            print("SKIP (import failed)")
            continue

        try:
            kwargs = {
                "docker_name": docker_name,
                "compose_file": args.compose_file,
                "remote_hosts": args.remote or [],
                "whitelist": whitelist,
            }
            results = mod.run_checks(openclaw_dir, **kwargs)
            all_results.extend(results)

            # Count pass/fail for this module
            passes = sum(1 for r in results if r.get("status") == PASS)
            fails = sum(1 for r in results if r.get("status") == FAIL)
            warns = sum(1 for r in results if r.get("status") == WARN)
            skips = sum(1 for r in results if r.get("status") == SKIP)

            status_parts = []
            if passes:
                status_parts.append(f"{passes} pass")
            if fails:
                status_parts.append(f"{fails} fail")
            if warns:
                status_parts.append(f"{warns} warn")
            if skips:
                status_parts.append(f"{skips} skip")

            print(f"({', '.join(status_parts)})")

        except Exception as e:
            print(f"ERROR: {e}")
            from scripts.utils import make_result
            all_results.append(make_result(
                f"MOD-{mid}", f"Module {mid} execution",
                HIGH, ERROR,
                f"Module {mid} ({mod_desc}) failed: {str(e)}",
                evidence=str(e)[:200],
            ))

    print(f"\n  Total checks: {len(all_results)}")
    print()

    # Generate reports
    output_dir = args.output_dir or os.path.join(os.getcwd(), "openclaw-audit-report")

    paths = write_reports(
        all_results,
        meta,
        output_dir=output_dir,
        fmt=args.format,
        show_fix=args.fix,
        write_json=args.json,
        checklist=args.checklist,
        min_severity=args.severity,
    )

    # Print report paths
    bold = COLORS.get("bold", "")
    reset = COLORS.get("reset", "")
    if paths:
        print(f"\n{bold}Report files:{reset}")
        for kind, path in paths.items():
            print(f"  {kind}: {path}")

    # Exit code: 1 if any CRITICAL FAIL, 0 otherwise
    has_critical_fail = any(
        r.get("severity") == CRITICAL and r.get("status") == FAIL
        for r in all_results
    )
    return 1 if has_critical_fail else 0


def main():
    parser = argparse.ArgumentParser(
        description="OpenClaw Security Audit Tool v" + TOOL_VERSION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Based on ZAST.AI Security Handbook. "
               "Covers 12 attack surfaces, 80 deterministic checks, "
               "27 official threat ID mappings."
    )

    parser.add_argument("--openclaw-dir", type=str, default=None,
                        help="OpenClaw directory (default: ~/.openclaw/)")
    parser.add_argument("--modules", type=str, default=None,
                        help="Only run specified modules (comma-separated: 01,02,03)")
    parser.add_argument("--skip", type=str, default=None,
                        help="Skip specified modules (comma-separated: 07,11)")
    parser.add_argument("--remote", type=str, action="append", default=None,
                        help="Remote host:port to check (can repeat)")
    parser.add_argument("--docker-name", type=str, default=None,
                        help="Docker container name (default: openclaw-sandbox)")
    parser.add_argument("--compose-file", type=str, default=None,
                        help="Path to docker-compose.yml")
    parser.add_argument("--output-dir", type=str, default=None,
                        help="Report output directory (default: ./openclaw-audit-report/)")
    parser.add_argument("--format", type=str, default="both",
                        choices=["terminal", "md", "both"],
                        help="Output format (default: both)")
    parser.add_argument("--severity", type=str, default=None,
                        choices=["critical", "high", "medium", "info"],
                        help="Minimum severity to display (default: info)")
    parser.add_argument("--fix", action="store_true",
                        help="Include fix command suggestions")
    parser.add_argument("--json", action="store_true",
                        help="Also output JSON format")
    parser.add_argument("--checklist", action="store_true",
                        help="Include §9.3 periodic checklist table")
    parser.add_argument("--whitelist", type=str, default="openclaw-security-audit",
                        help="Skill whitelist to exclude from supply chain scan "
                             "(comma-separated, default: openclaw-security-audit)")

    args = parser.parse_args()
    sys.exit(run_audit(args))


if __name__ == "__main__":
    main()
