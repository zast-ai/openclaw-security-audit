#!/usr/bin/env python3
"""Module 09: Agent Behavior Configuration Checks (AB-001 ~ AB-008)

Attack Surface: AS-10 (Agent behavior abuse), AS-4 (Business document injection),
                AS-6 (Data exfiltration)
Threats: T-IMPACT-001~005, T-EXEC-006, T-EXFIL-001
Handbook: §3.12, §5.3, §5.5, §8.2, §10.1-§10.4, §9.6
"""

import os
import re

from ..utils import (
    CRITICAL, HIGH, MEDIUM, INFO,
    PASS, FAIL, WARN, SKIP, ERROR,
    make_result, load_json_file, get_env_var, read_file_safe,
    get_nested,
)

MODULE_NAME = "09_agent_behavior"


def run_checks(openclaw_dir, **kwargs):
    """Run all 8 agent behavior checks. Returns list of result dicts."""
    config = load_json_file(os.path.join(openclaw_dir, "openclaw.json"))
    results = []
    results.append(_ab001(config))
    results.append(_ab002(config))
    results.append(_ab003(config))
    results.append(_ab004())
    results.append(_ab005(openclaw_dir, config))
    results.append(_ab006(config))
    results.append(_ab007(config))
    results.append(_ab008())
    return results


# AB-001: exec.mode must be "ask" (§5.5)
def _ab001(config):
    check_id = "AB-001"
    name = "Agent exec.mode is 'ask'"

    if config is None:
        return make_result(check_id, name, CRITICAL, SKIP,
                           "openclaw.json not found or invalid",
                           threat_ids=["AS-10"], handbook_ref="§5.5")

    # Check multiple possible config paths
    exec_mode = None
    for path in [
        ("agents", "defaults", "exec", "mode"),
        ("agent", "exec", "mode"),
        ("exec", "mode"),
        ("agents", "exec", "mode"),
    ]:
        val = get_nested(config, *path)
        if val is not None:
            exec_mode = val
            break

    if exec_mode is None:
        return make_result(check_id, name, MEDIUM, WARN,
                           "exec.mode not explicitly configured — verify effective runtime default",
                           threat_ids=["AS-10"], handbook_ref="§5.5",
                           fix_cmd='Set agents.defaults.exec.mode to "ask" in openclaw.json')

    if str(exec_mode).lower() == "ask":
        return make_result(check_id, name, CRITICAL, PASS,
                           "exec.mode is 'ask' — user approval required for command execution",
                           threat_ids=["AS-10"], handbook_ref="§5.5",
                           evidence=f"exec.mode={exec_mode}")

    if str(exec_mode).lower() == "allow":
        return make_result(check_id, name, CRITICAL, FAIL,
                           "exec.mode is 'allow' — Agent can execute commands without user approval!",
                           threat_ids=["AS-10"], handbook_ref="§5.5",
                           fix_cmd='Set agents.defaults.exec.mode to "ask" in openclaw.json',
                           evidence=f"exec.mode={exec_mode}")

    return make_result(check_id, name, CRITICAL, WARN,
                       f"exec.mode is '{exec_mode}' — verify this provides adequate protection",
                       threat_ids=["AS-10"], handbook_ref="§5.5",
                       evidence=f"exec.mode={exec_mode}")


# AB-002: sandbox.mode configuration (§7.1)
def _ab002(config):
    check_id = "AB-002"
    name = "Agent sandbox.mode configuration"

    if config is None:
        return make_result(check_id, name, HIGH, SKIP,
                           "openclaw.json not found or invalid",
                           threat_ids=["AS-10"], handbook_ref="§7.1")

    sandbox_mode = None
    for path in [
        ("agents", "defaults", "sandbox", "mode"),
        ("agent", "sandbox", "mode"),
        ("sandbox", "mode"),
    ]:
        val = get_nested(config, *path)
        if val is not None:
            sandbox_mode = val
            break

    if sandbox_mode is None:
        return make_result(check_id, name, MEDIUM, WARN,
                           "sandbox.mode not explicitly configured — verify effective runtime default",
                           threat_ids=["AS-10"], handbook_ref="§7.1",
                           fix_cmd='Configure agents.defaults.sandbox.mode in openclaw.json')

    if str(sandbox_mode).lower() in ("docker", "sandbox", "container", "isolated"):
        return make_result(check_id, name, HIGH, PASS,
                           f"sandbox.mode is '{sandbox_mode}'",
                           threat_ids=["AS-10"], handbook_ref="§7.1",
                           evidence=f"sandbox.mode={sandbox_mode}")

    if str(sandbox_mode).lower() in ("none", "disabled", "off"):
        return make_result(check_id, name, HIGH, FAIL,
                           f"sandbox.mode is '{sandbox_mode}' — commands execute on host without sandbox",
                           threat_ids=["AS-10"], handbook_ref="§7.1",
                           fix_cmd='Enable sandbox or ensure exec.mode is "ask"',
                           evidence=f"sandbox.mode={sandbox_mode}")

    return make_result(check_id, name, HIGH, WARN,
                       f"sandbox.mode is '{sandbox_mode}' — verify it provides adequate isolation",
                       threat_ids=["AS-10"], handbook_ref="§7.1",
                       evidence=f"sandbox.mode={sandbox_mode}")


# AB-003: Message sending limits (§10.4)
def _ab003(config):
    check_id = "AB-003"
    name = "Agent message sending limits"

    if config is None:
        return make_result(check_id, name, MEDIUM, SKIP,
                           "openclaw.json not found or invalid",
                           threat_ids=["AS-10"], handbook_ref="§10.4")

    # Check for rate limiting or message sending restrictions
    rate_limit = None
    for path in [
        ("agents", "defaults", "rateLimit",),
        ("agents", "defaults", "rate_limit",),
        ("agent", "rateLimit",),
        ("rateLimit",),
        ("agents", "defaults", "messaging", "limit"),
    ]:
        val = get_nested(config, *path)
        if val is not None:
            rate_limit = val
            break

    if rate_limit is not None:
        return make_result(check_id, name, MEDIUM, PASS,
                           "Message rate limiting is configured",
                           threat_ids=["AS-10"], handbook_ref="§10.4",
                           evidence=f"rateLimit={rate_limit}")

    return make_result(check_id, name, MEDIUM, WARN,
                       "No message sending rate limit configured — Agent could send unlimited messages to contacts",
                       threat_ids=["AS-10"], handbook_ref="§10.4",
                       fix_cmd="Configure message rate limits in openclaw.json to prevent spam/abuse")


# AB-004: API consumption cap reminder (§10.3)
def _ab004():
    check_id = "AB-004"
    name = "API consumption cap reminder"

    # Check for common API key env vars that indicate model provider usage
    api_key_vars = [
        "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY",
        "GEMINI_API_KEY", "AZURE_OPENAI_API_KEY", "COHERE_API_KEY",
        "MISTRAL_API_KEY", "DEEPSEEK_API_KEY",
    ]

    found_keys = []
    for var in api_key_vars:
        val = get_env_var(var)
        if val:
            found_keys.append(var)

    if not found_keys:
        return make_result(check_id, name, INFO, PASS,
                           "No model provider API keys detected in environment",
                           threat_ids=["AS-10"], handbook_ref="§10.3")

    return make_result(check_id, name, INFO, WARN,
                       f"Found {len(found_keys)} model provider API key(s) — "
                       f"ensure monthly spending caps are set at each provider's dashboard",
                       threat_ids=["AS-10"], handbook_ref="§10.3",
                       evidence=f"keys: {', '.join(found_keys)}")


# AB-005: MCP Server connection audit (§5.3, §9.6)
def _ab005(openclaw_dir, config):
    check_id = "AB-005"
    name = "MCP Server connection audit"

    if config is None:
        return make_result(check_id, name, HIGH, SKIP,
                           "openclaw.json not found or invalid",
                           threat_ids=["AS-10"], handbook_ref="§5.3")

    # Look for MCP server configurations
    mcp_servers = None
    for path in [
        ("mcpServers",),
        ("mcp_servers",),
        ("mcp",),
        ("agents", "defaults", "mcpServers"),
    ]:
        val = get_nested(config, *path)
        if val is not None and isinstance(val, (dict, list)):
            mcp_servers = val
            break

    if mcp_servers is None:
        return make_result(check_id, name, HIGH, PASS,
                           "No MCP servers configured",
                           threat_ids=["AS-10"], handbook_ref="§5.3")

    if isinstance(mcp_servers, dict):
        server_names = list(mcp_servers.keys())
    elif isinstance(mcp_servers, list):
        server_names = [s.get("name", f"server_{i}") if isinstance(s, dict) else str(s)
                        for i, s in enumerate(mcp_servers)]
    else:
        server_names = []

    detail = (f"Found {len(server_names)} MCP server(s) configured — "
              f"each MCP tool is a potential execution surface. Review permissions.")
    evidence = f"servers: {', '.join(server_names[:10])}"
    if len(server_names) > 10:
        evidence += f" ... and {len(server_names) - 10} more"

    severity = HIGH if len(server_names) > 3 else MEDIUM

    return make_result(check_id, name, severity, WARN, detail,
                       threat_ids=["AS-10"], handbook_ref="§5.3",
                       evidence=evidence)


# AB-006: Document processing configuration (§3.12)
def _ab006(config):
    check_id = "AB-006"
    name = "Document processing configuration"

    if config is None:
        return make_result(check_id, name, HIGH, SKIP,
                           "openclaw.json not found or invalid",
                           threat_ids=["AS-4"], handbook_ref="§3.12")

    # Check for document/attachment processing settings
    doc_config = None
    for path in [
        ("agents", "defaults", "documents",),
        ("agent", "documents",),
        ("documents",),
        ("attachments",),
        ("agent", "attachments",),
    ]:
        val = get_nested(config, *path)
        if val is not None:
            doc_config = val
            break

    if doc_config is None:
        return make_result(check_id, name, INFO, WARN,
                           "[Advisory] No document processing configuration found — "
                           "consider configuring format stripping if agents process shared documents",
                           threat_ids=["AS-4"], handbook_ref="§3.12",
                           fix_cmd="Configure document handling with format stripping and read-only execution policy")

    # Check if strip formatting is enabled
    strip_format = False
    if isinstance(doc_config, dict):
        strip_format = doc_config.get("stripFormatting", doc_config.get("strip_formatting", False))

    if strip_format:
        return make_result(check_id, name, HIGH, PASS,
                           "Document processing has format stripping enabled",
                           threat_ids=["AS-4"], handbook_ref="§3.12",
                           evidence=f"config={doc_config}")

    return make_result(check_id, name, MEDIUM, WARN,
                       "[Advisory] Document format stripping not enabled — "
                       "consider enabling to reduce hidden injection risk via white text/comments/OCR",
                       threat_ids=["AS-4"], handbook_ref="§3.12",
                       fix_cmd="Enable stripFormatting in document processing config")


# AB-007: web_fetch URL whitelist (§8.2)
def _ab007(config):
    check_id = "AB-007"
    name = "Outbound URL whitelist (web_fetch)"

    if config is None:
        return make_result(check_id, name, HIGH, SKIP,
                           "openclaw.json not found or invalid",
                           threat_ids=["AS-6"], handbook_ref="§8.2")

    # Check for URL whitelist/allowlist configuration
    url_whitelist = None
    for path in [
        ("agents", "defaults", "web", "allowedUrls"),
        ("agents", "defaults", "web", "urlWhitelist"),
        ("agent", "web", "allowedUrls"),
        ("web", "allowedUrls"),
        ("outbound", "allowedUrls"),
        ("agents", "defaults", "allowedUrls"),
    ]:
        val = get_nested(config, *path)
        if val is not None:
            url_whitelist = val
            break

    if url_whitelist and isinstance(url_whitelist, list) and len(url_whitelist) > 0:
        return make_result(check_id, name, HIGH, PASS,
                           f"Outbound URL whitelist configured with {len(url_whitelist)} entries",
                           threat_ids=["AS-6"], handbook_ref="§8.2",
                           evidence=f"allowedUrls count={len(url_whitelist)}")

    return make_result(check_id, name, INFO, WARN,
                       "[Advisory] No outbound URL whitelist configured — "
                       "consider adding allowedUrls to limit agent web access scope",
                       threat_ids=["AS-6"], handbook_ref="§8.2",
                       fix_cmd="Configure agents.defaults.web.allowedUrls in openclaw.json")


# AB-008: Financial operation API key reminder (§10.1)
def _ab008():
    check_id = "AB-008"
    name = "Financial operation API key reminder"

    financial_vars = [
        "STRIPE_API_KEY", "STRIPE_SECRET_KEY",
        "PAYPAL_CLIENT_ID", "PAYPAL_SECRET",
        "WALLET_PRIVATE_KEY", "CRYPTO_API_KEY",
        "COINBASE_API_KEY", "BINANCE_API_KEY",
        "ALIPAY_APP_PRIVATE_KEY", "WECHAT_PAY_KEY",
        "BRAINTREE_PRIVATE_KEY", "SQUARE_ACCESS_TOKEN",
        "PLAID_SECRET", "WISE_API_TOKEN",
    ]

    found_keys = []
    for var in financial_vars:
        val = get_env_var(var)
        if val:
            found_keys.append(var)

    if not found_keys:
        return make_result(check_id, name, INFO, PASS,
                           "No financial/payment API keys detected in environment",
                           threat_ids=["AS-10"], handbook_ref="§10.1")

    return make_result(check_id, name, CRITICAL, WARN,
                       f"Found {len(found_keys)} financial/payment API key(s) in environment — "
                       f"CRITICAL: Agent with financial API access MUST require 'dual signature' (two-person approval)",
                       threat_ids=["AS-10"], handbook_ref="§10.1",
                       fix_cmd="Remove financial API keys from OpenClaw environment or implement dual-approval workflow",
                       evidence=f"keys: {', '.join(found_keys)}")
