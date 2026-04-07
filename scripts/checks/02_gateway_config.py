#!/usr/bin/env python3
"""Module 02: Gateway Configuration Checks (GW-001 ~ GW-013)

Attack Surface: AS-1 (Gateway Exposure)
Threats: Unauthenticated gateway access, plaintext tokens, LAN binding,
         debug mode leaks, outdated versions, token reuse
Handbook: §2.1-§2.6, §6.2, §8.3, §9.1, §9.3
"""

import os
import re

from ..utils import (
    CRITICAL, HIGH, MEDIUM, INFO,
    PASS, FAIL, WARN, SKIP, ERROR,
    make_result, run_cmd, load_json_file, get_file_mtime_days_ago, get_env_var,
    get_nested,
)

MODULE_NAME = "02_gateway_config"


def run_checks(openclaw_dir, **kwargs):
    """Run all 13 gateway configuration checks. Returns list of result dicts."""
    results = []
    results.append(_gw001(openclaw_dir))
    results.append(_gw002(openclaw_dir))
    results.append(_gw003(openclaw_dir))
    results.append(_gw004(openclaw_dir))
    results.append(_gw005(openclaw_dir))
    results.append(_gw006())
    results.append(_gw007(openclaw_dir))
    results.append(_gw008(openclaw_dir))
    results.append(_gw009(openclaw_dir))
    results.append(_gw010())
    results.append(_gw011())
    results.append(_gw012(openclaw_dir))
    results.append(_gw013(openclaw_dir))
    return results


def _load_config(openclaw_dir):
    """Load openclaw.json and return parsed dict or None."""
    return load_json_file(os.path.join(openclaw_dir, "openclaw.json"))


# GW-001: auth.mode must not be "none" (§2.1)
def _gw001(openclaw_dir):
    check_id = "GW-001"
    name = "Gateway auth.mode not 'none'"
    config = _load_config(openclaw_dir)
    if config is None:
        return make_result(check_id, name, CRITICAL, SKIP,
                           "Cannot load openclaw.json — skipping config-dependent check",
                           threat_ids=["AS-1"], handbook_ref="§2.1")

    mode = get_nested(config, "gateway", "auth", "mode", default="")
    if mode == "none":
        return make_result(check_id, name, CRITICAL, FAIL,
                           "Gateway auth.mode is 'none' — gateway is completely unauthenticated",
                           threat_ids=["AS-1"], handbook_ref="§2.1",
                           fix_cmd='Set gateway.auth.mode to "token" in openclaw.json',
                           evidence=f"auth.mode={mode}")
    return make_result(check_id, name, CRITICAL, PASS,
                       f"Gateway auth.mode is '{mode}' (not 'none')",
                       threat_ids=["AS-1"], handbook_ref="§2.1",
                       evidence=f"auth.mode={mode}")


# GW-002: auth.mode is "token" (recommended) (§2.1)
def _gw002(openclaw_dir):
    check_id = "GW-002"
    name = "Gateway auth.mode is 'token' (recommended)"
    config = _load_config(openclaw_dir)
    if config is None:
        return make_result(check_id, name, MEDIUM, SKIP,
                           "Cannot load openclaw.json — skipping config-dependent check",
                           threat_ids=["AS-1"], handbook_ref="§2.1")

    mode = get_nested(config, "gateway", "auth", "mode", default="")
    if mode == "token":
        return make_result(check_id, name, MEDIUM, PASS,
                           "Gateway auth.mode is 'token' (strongest recommended mode)",
                           threat_ids=["AS-1"], handbook_ref="§2.1",
                           evidence=f"auth.mode={mode}")
    return make_result(check_id, name, MEDIUM, WARN,
                       f"Gateway auth.mode is '{mode}' — 'token' is the recommended mode",
                       threat_ids=["AS-1"], handbook_ref="§2.1",
                       fix_cmd='Set gateway.auth.mode to "token" in openclaw.json',
                       evidence=f"auth.mode={mode}")


# GW-003: token uses secretRef, not plaintext (§2.1)
def _gw003(openclaw_dir):
    check_id = "GW-003"
    name = "Gateway token uses secretRef (not plaintext)"
    config = _load_config(openclaw_dir)
    if config is None:
        return make_result(check_id, name, HIGH, SKIP,
                           "Cannot load openclaw.json — skipping config-dependent check",
                           threat_ids=["AS-1"], handbook_ref="§2.1")

    mode = get_nested(config, "gateway", "auth", "mode", default="")
    if mode != "token":
        return make_result(check_id, name, HIGH, SKIP,
                           f"auth.mode is '{mode}', not 'token' — secretRef check not applicable",
                           threat_ids=["AS-1"], handbook_ref="§2.1")

    token_obj = get_nested(config, "gateway", "auth", "token", default=None)
    if isinstance(token_obj, dict) and token_obj.get("secretRef"):
        return make_result(check_id, name, HIGH, PASS,
                           "Gateway token uses secretRef (environment variable reference)",
                           threat_ids=["AS-1"], handbook_ref="§2.1",
                           evidence=f"secretRef={token_obj['secretRef']}")
    # Token could be a raw string (plaintext) or dict without secretRef
    return make_result(check_id, name, HIGH, FAIL,
                       "Gateway token does not use secretRef — token may be stored in plaintext",
                       threat_ids=["AS-1"], handbook_ref="§2.1",
                       fix_cmd='Use {"secretRef": "OPENCLAW_GATEWAY_TOKEN"} instead of a plaintext value',
                       evidence=f"token_type={type(token_obj).__name__}")


# GW-004: No plaintext hex token in config (§2.1)
def _gw004(openclaw_dir):
    check_id = "GW-004"
    name = "No hardcoded hex token in gateway config"
    config_path = os.path.join(openclaw_dir, "openclaw.json")

    if not os.path.exists(config_path):
        return make_result(check_id, name, HIGH, SKIP,
                           "openclaw.json not found",
                           threat_ids=["AS-1"], handbook_ref="§2.1")

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception as e:
        return make_result(check_id, name, HIGH, ERROR,
                           f"Cannot read openclaw.json: {e}",
                           threat_ids=["AS-1"], handbook_ref="§2.1")

    # Search for hex strings of 32+ characters that look like hardcoded tokens
    hex_matches = re.findall(r'["\']([0-9a-fA-F]{32,})["\']', content)
    if hex_matches:
        # Redact most of the token for evidence
        redacted = [m[:8] + "..." + m[-4:] for m in hex_matches]
        return make_result(check_id, name, HIGH, FAIL,
                           f"Found {len(hex_matches)} potential hardcoded hex token(s) in openclaw.json",
                           threat_ids=["AS-1"], handbook_ref="§2.1",
                           fix_cmd="Move tokens to .env and use secretRef in config",
                           evidence=f"matches(redacted)={redacted}")
    return make_result(check_id, name, HIGH, PASS,
                       "No hardcoded hex tokens detected in openclaw.json",
                       threat_ids=["AS-1"], handbook_ref="§2.1")


# GW-005: bind is "loopback" (§2.2)
def _gw005(openclaw_dir):
    check_id = "GW-005"
    name = "Gateway bind is 'loopback'"
    config = _load_config(openclaw_dir)
    if config is None:
        return make_result(check_id, name, CRITICAL, SKIP,
                           "Cannot load openclaw.json — skipping config-dependent check",
                           threat_ids=["AS-1"], handbook_ref="§2.2")

    bind = get_nested(config, "gateway", "bind", default=None)
    # Also check environment variable override
    env_bind = get_env_var("OPENCLAW_GATEWAY_BIND")
    effective_bind = env_bind if env_bind else bind

    if effective_bind is None:
        return make_result(check_id, name, CRITICAL, WARN,
                           "Gateway bind not explicitly set — verify default behavior is loopback",
                           threat_ids=["AS-1"], handbook_ref="§2.2",
                           fix_cmd='Set gateway.bind to "loopback" in openclaw.json',
                           evidence="bind=not_set")

    if effective_bind == "loopback":
        return make_result(check_id, name, CRITICAL, PASS,
                           "Gateway bind is 'loopback' — not exposed to network",
                           threat_ids=["AS-1"], handbook_ref="§2.2",
                           evidence=f"bind={effective_bind}, source={'env' if env_bind else 'config'}")

    return make_result(check_id, name, CRITICAL, FAIL,
                       f"Gateway bind is '{effective_bind}' — gateway may be exposed to the network",
                       threat_ids=["AS-1"], handbook_ref="§2.2",
                       fix_cmd='Set gateway.bind to "loopback" in openclaw.json',
                       evidence=f"bind={effective_bind}, source={'env' if env_bind else 'config'}")


# GW-006: OPENCLAW_GATEWAY_BIND env var must not be "lan" (§2.2)
def _gw006():
    check_id = "GW-006"
    name = "OPENCLAW_GATEWAY_BIND env var not 'lan'"
    env_bind = get_env_var("OPENCLAW_GATEWAY_BIND")

    if env_bind is None:
        return make_result(check_id, name, CRITICAL, PASS,
                           "OPENCLAW_GATEWAY_BIND not set (no env override)",
                           threat_ids=["AS-1"], handbook_ref="§2.2",
                           evidence="env_var=unset")

    if env_bind.lower() == "lan":
        return make_result(check_id, name, CRITICAL, FAIL,
                           "OPENCLAW_GATEWAY_BIND is 'lan' — gateway exposed to local network",
                           threat_ids=["AS-1"], handbook_ref="§2.2",
                           fix_cmd='unset OPENCLAW_GATEWAY_BIND or set to "loopback"',
                           evidence=f"OPENCLAW_GATEWAY_BIND={env_bind}")

    return make_result(check_id, name, CRITICAL, PASS,
                       f"OPENCLAW_GATEWAY_BIND is '{env_bind}' (not 'lan')",
                       threat_ids=["AS-1"], handbook_ref="§2.2",
                       evidence=f"OPENCLAW_GATEWAY_BIND={env_bind}")


# GW-007: trusted-proxy mode warning (§2.3)
def _gw007(openclaw_dir):
    check_id = "GW-007"
    name = "Trusted-proxy mode source IP verification warning"
    config = _load_config(openclaw_dir)
    if config is None:
        return make_result(check_id, name, HIGH, SKIP,
                           "Cannot load openclaw.json — skipping config-dependent check",
                           threat_ids=["AS-1"], handbook_ref="§2.3")

    mode = get_nested(config, "gateway", "auth", "mode", default="")
    if mode == "trusted-proxy":
        return make_result(check_id, name, HIGH, WARN,
                           "auth.mode is 'trusted-proxy' — OpenClaw has no built-in source IP "
                           "verification; ensure a firewall or reverse proxy enforces source restrictions",
                           threat_ids=["AS-1"], handbook_ref="§2.3",
                           fix_cmd="Configure firewall rules to restrict source IPs, or switch to 'token' mode",
                           evidence=f"auth.mode={mode}")

    return make_result(check_id, name, HIGH, PASS,
                       f"auth.mode is '{mode}' (not 'trusted-proxy')",
                       threat_ids=["AS-1"], handbook_ref="§2.3",
                       evidence=f"auth.mode={mode}")


# GW-008: Webhook token independent from gateway token (§2.6)
def _gw008(openclaw_dir):
    check_id = "GW-008"
    name = "Webhook token independent from gateway token"
    config = _load_config(openclaw_dir)
    if config is None:
        return make_result(check_id, name, MEDIUM, SKIP,
                           "Cannot load openclaw.json — skipping config-dependent check",
                           threat_ids=["AS-1"], handbook_ref="§2.6")

    gw_secret_ref = get_nested(config, "gateway", "auth", "token", "secretRef", default=None)
    hook_secret_ref = get_nested(config, "hooks", "token", "secretRef", default=None)

    # If neither uses secretRef, or one is absent, nothing to compare
    if gw_secret_ref is None or hook_secret_ref is None:
        return make_result(check_id, name, MEDIUM, SKIP,
                           "Cannot compare — gateway and/or webhook token secretRef not configured",
                           threat_ids=["AS-1"], handbook_ref="§2.6",
                           evidence=f"gw_secretRef={gw_secret_ref}, hook_secretRef={hook_secret_ref}")

    if gw_secret_ref == hook_secret_ref:
        return make_result(check_id, name, MEDIUM, FAIL,
                           f"Gateway and webhook tokens reference the same env var '{gw_secret_ref}' "
                           "— compromise of one exposes the other",
                           threat_ids=["AS-1"], handbook_ref="§2.6",
                           fix_cmd="Use separate environment variables for gateway and webhook tokens",
                           evidence=f"gw_secretRef={gw_secret_ref}, hook_secretRef={hook_secret_ref}")

    return make_result(check_id, name, MEDIUM, PASS,
                       "Gateway and webhook tokens use different secretRef env vars",
                       threat_ids=["AS-1"], handbook_ref="§2.6",
                       evidence=f"gw_secretRef={gw_secret_ref}, hook_secretRef={hook_secret_ref}")


# GW-009: debug/verbose mode off in production (§6.2)
def _gw009(openclaw_dir):
    check_id = "GW-009"
    name = "Debug/verbose mode is off"
    findings = []

    config = _load_config(openclaw_dir)
    if config is not None:
        debug_val = get_nested(config, "debug", default=None)
        if debug_val is True:
            findings.append("config debug=true")
        verbose_val = get_nested(config, "verbose", default=None)
        if verbose_val is True:
            findings.append("config verbose=true")
        gw_debug = get_nested(config, "gateway", "debug", default=None)
        if gw_debug is True:
            findings.append("gateway.debug=true")

    # Check environment variables
    for env_name in ("OPENCLAW_DEBUG", "OPENCLAW_VERBOSE", "DEBUG"):
        val = get_env_var(env_name)
        if val and val.lower() in ("1", "true", "yes"):
            findings.append(f"env {env_name}={val}")

    if findings:
        return make_result(check_id, name, MEDIUM, FAIL,
                           "Debug/verbose mode is enabled — may leak sensitive information in production",
                           threat_ids=["AS-1"], handbook_ref="§6.2",
                           fix_cmd="Disable debug/verbose flags in openclaw.json and unset debug env vars",
                           evidence="; ".join(findings))

    return make_result(check_id, name, MEDIUM, PASS,
                       "No debug/verbose flags detected in config or environment",
                       threat_ids=["AS-1"], handbook_ref="§6.2")


# GW-010: Telemetry disabled (§8.3)
def _gw010():
    check_id = "GW-010"
    name = "Telemetry disabled"
    val = get_env_var("DISABLE_TELEMETRY")

    if val == "1":
        return make_result(check_id, name, INFO, PASS,
                           "DISABLE_TELEMETRY is set to '1'",
                           threat_ids=["AS-1"], handbook_ref="§8.3",
                           evidence="DISABLE_TELEMETRY=1")

    return make_result(check_id, name, INFO, WARN,
                       f"DISABLE_TELEMETRY is {'set to ' + repr(val) if val else 'not set'} — "
                       "telemetry may be active",
                       threat_ids=["AS-1"], handbook_ref="§8.3",
                       fix_cmd='export DISABLE_TELEMETRY=1',
                       evidence=f"DISABLE_TELEMETRY={val!r}")


# GW-011: OpenClaw version is latest (§9.1, §2.4)
def _gw011():
    check_id = "GW-011"
    name = "OpenClaw version is latest"

    # Get installed version
    rc_local, local_ver, _ = run_cmd(["openclaw", "--version"])
    if rc_local != 0:
        return make_result(check_id, name, MEDIUM, SKIP,
                           "Cannot determine installed OpenClaw version ('openclaw --version' failed)",
                           threat_ids=["AS-1"], handbook_ref="§9.1")

    # Normalize: sometimes --version outputs "openclaw v1.2.3" or just "1.2.3"
    local_ver = local_ver.strip()
    local_ver_clean = re.sub(r'^[^\d]*', '', local_ver)  # strip leading non-digits

    # Get latest version from npm registry
    rc_npm, npm_ver, _ = run_cmd(["npm", "view", "openclaw", "version"])
    if rc_npm != 0 or not npm_ver.strip():
        return make_result(check_id, name, MEDIUM, SKIP,
                           f"Installed version: {local_ver_clean}, but cannot fetch latest "
                           "from npm registry ('npm view openclaw version' failed)",
                           threat_ids=["AS-1"], handbook_ref="§9.1",
                           evidence=f"local={local_ver_clean}")

    latest_ver = npm_ver.strip()

    if local_ver_clean == latest_ver:
        return make_result(check_id, name, HIGH, PASS,
                           f"OpenClaw is up to date (v{local_ver_clean})",
                           threat_ids=["AS-1"], handbook_ref="§9.1",
                           evidence=f"local={local_ver_clean}, latest={latest_ver}")

    return make_result(check_id, name, MEDIUM, WARN,
                       f"OpenClaw v{local_ver_clean} is installed, but v{latest_ver} is available — "
                       "consider updating unless pinned for compatibility",
                       threat_ids=["AS-1"], handbook_ref="§9.1",
                       fix_cmd="npm update -g openclaw",
                       evidence=f"local={local_ver_clean}, latest={latest_ver}")


# GW-012: Paired device count from filesystem (informational)
# See also CH-009 for per-channel paired device count from config
def _gw012(openclaw_dir):
    check_id = "GW-012"
    name = "Paired device count (filesystem)"

    # Check common locations for paired device / session info
    device_count = 0
    checked_paths = []
    for subdir in ("paired", "sessions", "devices"):
        dir_path = os.path.join(openclaw_dir, subdir)
        if os.path.isdir(dir_path):
            checked_paths.append(subdir)
            try:
                entries = [e for e in os.listdir(dir_path)
                           if not e.startswith(".")]
                device_count += len(entries)
            except OSError:
                pass

    if not checked_paths:
        return make_result(check_id, name, INFO, SKIP,
                           "No paired/sessions/devices directory found",
                           threat_ids=["AS-1"], handbook_ref="§2.5",
                           evidence="dirs_checked=paired,sessions,devices")

    if device_count > 1:
        return make_result(check_id, name, INFO, WARN,
                           f"{device_count} paired device/session entries found — "
                           "verify all are authorized and remove stale entries",
                           threat_ids=["AS-1"], handbook_ref="§2.5",
                           fix_cmd="Review and remove unrecognized devices from paired/sessions directory",
                           evidence=f"count={device_count}, dirs={','.join(checked_paths)}")

    return make_result(check_id, name, INFO, PASS,
                       f"{device_count} paired device/session entry found",
                       threat_ids=["AS-1"], handbook_ref="§2.5",
                       evidence=f"count={device_count}, dirs={','.join(checked_paths)}")


# GW-013: Gateway token rotation period (§9.3)
def _gw013(openclaw_dir):
    check_id = "GW-013"
    name = "Gateway token rotation period"
    env_path = os.path.join(openclaw_dir, ".env")

    days = get_file_mtime_days_ago(env_path)
    if days is None:
        return make_result(check_id, name, MEDIUM, SKIP,
                           ".env file not found — cannot assess token rotation",
                           threat_ids=["AS-1"], handbook_ref="§9.3")

    if days > 90:
        return make_result(check_id, name, MEDIUM, WARN,
                           f".env file last modified {days} days ago (>90 days) — "
                           "consider rotating gateway and webhook tokens",
                           threat_ids=["AS-1"], handbook_ref="§9.3",
                           fix_cmd="Regenerate tokens, update .env, and restart OpenClaw",
                           evidence=f"env_mtime_days_ago={days}")

    return make_result(check_id, name, MEDIUM, PASS,
                       f".env file last modified {days} days ago (within 90-day rotation window)",
                       threat_ids=["AS-1"], handbook_ref="§9.3",
                       evidence=f"env_mtime_days_ago={days}")
