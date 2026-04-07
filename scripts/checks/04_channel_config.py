#!/usr/bin/env python3
"""Module 04: Message Channel Configuration Checks (CH-001 ~ CH-009)

Attack Surface: AS-2 (Message channels)
Threats: T-RECON-002, T-RECON-003, T-ACCESS-006, T-EXEC-001, T-EXEC-002
Handbook: §3.1-§3.11
"""

import os
import re

from ..utils import (
    CRITICAL, HIGH, MEDIUM, INFO,
    PASS, FAIL, WARN, SKIP, ERROR,
    make_result, load_json_file,
)

MODULE_NAME = "04_channel_config"

# Common threat identifiers for this module
_AS = ["AS-2"]

# Known unofficial/risky connector types (§3.7)
_UNOFFICIAL_CONNECTORS = {"whatsapp", "whatsapp-web", "wechat", "line"}

# Keywords indicating group/server/channel mode rather than DM (§3.3)
_GROUP_INDICATORS = {"group", "server", "channel", "supergroup", "guild"}


def run_checks(openclaw_dir, **kwargs):
    """Run all 9 message channel configuration checks. Returns list of result dicts."""
    config_path = os.path.join(openclaw_dir, "openclaw.json")
    config = load_json_file(config_path)

    # If config or channels section is missing, skip all checks
    if config is None:
        return _skip_all("openclaw.json not found or unreadable")

    channels = config.get("channels", None)
    if channels is None:
        return _skip_all("No 'channels' section found in openclaw.json")

    if not isinstance(channels, dict) or len(channels) == 0:
        return _skip_all("'channels' section is empty or not a dict")

    results = []
    results.append(_ch001(channels))
    results.append(_ch002(channels))
    results.append(_ch003(channels))
    results.append(_ch004(channels))
    results.append(_ch005(channels))
    results.append(_ch006(channels))
    results.append(_ch007(channels))
    results.append(_ch008(channels))
    results.append(_ch009(channels))
    return results


def _skip_all(reason):
    """Return SKIP results for all 9 checks when config is unavailable."""
    checks = [
        ("CH-001", "Every channel has allowFrom whitelist", CRITICAL),
        ("CH-002", "allowFrom uses numeric IDs", MEDIUM),
        ("CH-003", "dmPolicy is pairing", HIGH),
        ("CH-004", "Email channel connection warning", HIGH),
        ("CH-005", "Cross-channel info leak risk", MEDIUM),
        ("CH-006", "Bot not in groups/channels", CRITICAL),
        ("CH-007", "Discord Message Content Intent", HIGH),
        ("CH-008", "Unofficial connector warning", MEDIUM),
        ("CH-009", "Paired device count (per-channel config)", INFO),
    ]
    return [
        make_result(cid, name, sev, SKIP, reason,
                    threat_ids=_AS, handbook_ref="§3.1")
        for cid, name, sev in checks
    ]


def _is_effectively_configured_channel(name, cfg):
    """Return True if this entry looks like a real, configured channel instance.

    Excludes template/default blocks and provider placeholders that are not
    actually configured for use yet.
    """
    if not isinstance(cfg, dict):
        return False
    if name == "defaults":
        return False
    if cfg.get("enabled", True) is False:
        return False

    # Provider-specific readiness checks
    if name == "telegram":
        return bool(cfg.get("botToken"))
    if name == "discord":
        return bool(cfg.get("token"))
    if name == "openclaw-weixin":
        accounts = cfg.get("accounts")
        return isinstance(accounts, dict) and len(accounts) > 0

    # Generic fallback: require at least one non-empty connectivity/auth hint.
    for key in ("token", "botToken", "accounts", "session", "sessions", "auth", "url"):
        val = cfg.get(key)
        if val not in (None, "", {}, []):
            return True
    return False


def _get_enabled_channels(channels):
    """Yield (channel_name, channel_config) for effectively configured channels."""
    for name, cfg in channels.items():
        if _is_effectively_configured_channel(name, cfg):
            yield name, cfg


# ---------------------------------------------------------------------------
# CH-001: Every channel has allowFrom whitelist (§3.2)
# ---------------------------------------------------------------------------
def _ch001(channels):
    check_id = "CH-001"
    name = "Every channel has allowFrom whitelist"

    missing = []
    for ch_name, ch_cfg in _get_enabled_channels(channels):
        allow_from = ch_cfg.get("allowFrom")
        if allow_from is None or (isinstance(allow_from, list) and len(allow_from) == 0):
            missing.append(ch_name)

    if not missing:
        return make_result(check_id, name, CRITICAL, PASS,
                           "All enabled channels have allowFrom configured",
                           threat_ids=_AS,
                           threat_refs=["T-ACCESS-006"],
                           handbook_ref="§3.2")

    return make_result(check_id, name, CRITICAL, FAIL,
                       f"Channel(s) missing allowFrom whitelist: {', '.join(missing)}",
                       threat_ids=_AS,
                       threat_refs=["T-ACCESS-006"],
                       handbook_ref="§3.2",
                       fix_cmd='Add "allowFrom": ["<your_user_id>"] to each channel config',
                       evidence=f"missing_channels={missing}")


# ---------------------------------------------------------------------------
# CH-002: allowFrom uses numeric IDs, not usernames (§3.4)
# ---------------------------------------------------------------------------
def _ch002(channels):
    check_id = "CH-002"
    name = "allowFrom uses numeric IDs"

    non_numeric = []
    wildcards = []
    checked = 0
    for ch_name, ch_cfg in _get_enabled_channels(channels):
        allow_from = ch_cfg.get("allowFrom")
        if not isinstance(allow_from, list):
            continue
        for entry in allow_from:
            checked += 1
            entry_str = str(entry).strip()
            if re.match(r'^\d+$', entry_str):
                continue
            if entry_str in {"*", "all", "any"}:
                wildcards.append(f"{ch_name}:{entry_str}")
            else:
                non_numeric.append(f"{ch_name}:{entry_str}")

    if checked == 0:
        return make_result(check_id, name, MEDIUM, SKIP,
                           "No allowFrom entries found to validate",
                           threat_ids=_AS,
                           threat_refs=["T-RECON-002"],
                           handbook_ref="§3.4")

    if not non_numeric and not wildcards:
        return make_result(check_id, name, MEDIUM, PASS,
                           f"All {checked} allowFrom entries are numeric IDs",
                           threat_ids=_AS,
                           threat_refs=["T-RECON-002"],
                           handbook_ref="§3.4")

    detail_parts = []
    if wildcards:
        detail_parts.append(
            "Wildcard allowFrom entries found (broad authorization scope): " +
            ", ".join(wildcards[:10])
        )
    if non_numeric:
        detail_parts.append(
            "Non-numeric allowFrom entries found (usernames/handles can be spoofed): " +
            ", ".join(non_numeric[:10])
        )

    return make_result(check_id, name, MEDIUM, WARN,
                       "; ".join(detail_parts),
                       threat_ids=_AS,
                       threat_refs=["T-RECON-002"],
                       handbook_ref="§3.4",
                       fix_cmd="Replace usernames/wildcards with numeric user IDs in allowFrom",
                       evidence=f"wildcards={wildcards[:10]}, non_numeric_entries={non_numeric[:10]}")


# ---------------------------------------------------------------------------
# CH-003: dmPolicy is "pairing" (§3.2)
# ---------------------------------------------------------------------------
def _ch003(channels):
    check_id = "CH-003"
    name = "dmPolicy is pairing"

    issues = []
    for ch_name, ch_cfg in _get_enabled_channels(channels):
        dm_policy = ch_cfg.get("dmPolicy")
        if dm_policy is not None and dm_policy != "pairing":
            issues.append(f"{ch_name}={dm_policy}")

    if not issues:
        return make_result(check_id, name, HIGH, PASS,
                           'All channels have dmPolicy set to "pairing" or unset (default)',
                           threat_ids=_AS,
                           threat_refs=["T-ACCESS-006"],
                           handbook_ref="§3.2")

    return make_result(check_id, name, HIGH, WARN,
                       f'Baseline deviation: dmPolicy is not "pairing": {", ".join(issues)} — '
                       f'this may be intentional for interactive workflows, but "pairing" is the recommended hardened mode',
                       threat_ids=_AS,
                       threat_refs=["T-ACCESS-006"],
                       handbook_ref="§3.2",
                       fix_cmd='Set "dmPolicy": "pairing" in each channel config if you want the strictest baseline',
                       evidence=f"non_pairing={issues}")


# ---------------------------------------------------------------------------
# CH-004: Email channel connection warning (§3.11)
# ---------------------------------------------------------------------------
def _ch004(channels):
    check_id = "CH-004"
    name = "Email channel connection warning"

    email_channels = []
    for ch_name, ch_cfg in _get_enabled_channels(channels):
        ch_type = str(ch_cfg.get("type", "")).lower()
        # Detect email channels by type or name heuristic
        if ch_type in ("email", "imap", "smtp") or "email" in ch_name.lower():
            email_channels.append(ch_name)

    if not email_channels:
        return make_result(check_id, name, HIGH, PASS,
                           "No email-type channels detected",
                           threat_ids=_AS,
                           threat_refs=["T-RECON-003", "T-EXEC-001"],
                           handbook_ref="§3.11")

    return make_result(check_id, name, HIGH, WARN,
                       f"Email channel(s) detected: {', '.join(email_channels)}. "
                       f"Do NOT connect your primary mailbox. Ensure bot cannot process "
                       f"verification codes or password reset emails.",
                       threat_ids=_AS,
                       threat_refs=["T-RECON-003", "T-EXEC-001"],
                       handbook_ref="§3.11",
                       fix_cmd="Use a dedicated mailbox for bot email channels; "
                               "filter out security-sensitive emails",
                       evidence=f"email_channels={email_channels}")


# ---------------------------------------------------------------------------
# CH-005: Cross-channel info leak risk (§3.5)
# ---------------------------------------------------------------------------
def _ch005(channels):
    check_id = "CH-005"
    name = "Cross-channel info leak risk"

    enabled_count = sum(1 for _ in _get_enabled_channels(channels))

    if enabled_count < 2:
        return make_result(check_id, name, MEDIUM, PASS,
                           f"Only {enabled_count} channel(s) enabled — no cross-channel risk",
                           threat_ids=_AS,
                           threat_refs=["T-RECON-003"],
                           handbook_ref="§3.5")

    return make_result(check_id, name, MEDIUM, WARN,
                       f"{enabled_count} channels connected to the same agent. "
                       f"Information from one channel may leak to another through "
                       f"shared context/memory.",
                       threat_ids=_AS,
                       threat_refs=["T-RECON-003"],
                       handbook_ref="§3.5",
                       fix_cmd="Consider using separate agent instances per channel, "
                               "or configure strict context isolation",
                       evidence=f"enabled_channel_count={enabled_count}")


# ---------------------------------------------------------------------------
# CH-006: Bot not in groups/channels (§3.3 core danger)
# ---------------------------------------------------------------------------
def _ch006(channels):
    check_id = "CH-006"
    name = "Bot not in groups/channels"

    group_entries = []
    for ch_name, ch_cfg in _get_enabled_channels(channels):
        # Check channel type for group indicators
        ch_type = str(ch_cfg.get("type", "")).lower()
        ch_mode = str(ch_cfg.get("mode", "")).lower()
        ch_scope = str(ch_cfg.get("scope", "")).lower()

        indicators_found = []

        # Check type field
        for indicator in _GROUP_INDICATORS:
            if indicator in ch_type:
                indicators_found.append(f"type={ch_type}")
                break

        # Check mode field
        for indicator in _GROUP_INDICATORS:
            if indicator in ch_mode:
                indicators_found.append(f"mode={ch_mode}")
                break

        # Check scope field
        for indicator in _GROUP_INDICATORS:
            if indicator in ch_scope:
                indicators_found.append(f"scope={ch_scope}")
                break

        # Check channel name for group hints
        ch_name_lower = ch_name.lower()
        for indicator in _GROUP_INDICATORS:
            if indicator in ch_name_lower:
                indicators_found.append(f"name={ch_name}")
                break

        # Check for group-related config keys
        for key in ("groupId", "group_id", "serverId", "server_id",
                     "channelId", "channel_id", "guildId", "guild_id"):
            if key in ch_cfg:
                indicators_found.append(f"key={key}")

        if indicators_found:
            group_entries.append(f"{ch_name} ({'; '.join(indicators_found)})")

    if not group_entries:
        return make_result(check_id, name, CRITICAL, PASS,
                           "No group/server/channel mode entries detected — DM only",
                           threat_ids=_AS,
                           threat_refs=["T-RECON-002", "T-ACCESS-006", "T-EXEC-002"],
                           handbook_ref="§3.3")

    return make_result(check_id, name, CRITICAL, FAIL,
                       f"Bot appears to be configured for group/channel mode: "
                       f"{', '.join(group_entries[:5])}. "
                       f"Any group member can inject prompts.",
                       threat_ids=_AS,
                       threat_refs=["T-RECON-002", "T-ACCESS-006", "T-EXEC-002"],
                       handbook_ref="§3.3",
                       fix_cmd="Remove bot from all groups/servers; use DM mode only "
                               "with allowFrom whitelist",
                       evidence=f"group_entries={group_entries}")


# ---------------------------------------------------------------------------
# CH-007: Discord Message Content Intent (§3.3)
# ---------------------------------------------------------------------------
def _ch007(channels):
    check_id = "CH-007"
    name = "Discord Message Content Intent"

    discord_channels = []
    intent_issues = []

    for ch_name, ch_cfg in _get_enabled_channels(channels):
        ch_type = str(ch_cfg.get("type", "")).lower()
        if ch_type != "discord" and "discord" not in ch_name.lower():
            continue
        discord_channels.append(ch_name)

        # Check for Message Content Intent configuration
        intents = ch_cfg.get("intents", ch_cfg.get("intent", []))
        permissions = ch_cfg.get("permissions", ch_cfg.get("permission", []))
        message_content = ch_cfg.get("messageContentIntent",
                          ch_cfg.get("message_content_intent",
                          ch_cfg.get("messageContent")))

        if isinstance(intents, list):
            for intent in intents:
                intent_str = str(intent).lower()
                if "message" in intent_str and "content" in intent_str:
                    intent_issues.append(f"{ch_name}: intents contains message content")

        if isinstance(intents, (int, str)):
            # Numeric intent bitmask — bit 15 (32768) is MESSAGE_CONTENT
            try:
                if int(intents) & 32768:
                    intent_issues.append(f"{ch_name}: intents bitmask includes MESSAGE_CONTENT")
            except (ValueError, TypeError):
                pass

        if message_content is True:
            intent_issues.append(f"{ch_name}: messageContentIntent explicitly enabled")

        # Check permissions for overly broad values
        if isinstance(permissions, (int, str)):
            try:
                perm_val = int(permissions)
                # 8 = Administrator
                if perm_val & 8:
                    intent_issues.append(f"{ch_name}: Administrator permission set")
            except (ValueError, TypeError):
                pass

    if not discord_channels:
        return make_result(check_id, name, HIGH, SKIP,
                           "No Discord channels detected",
                           threat_ids=_AS,
                           threat_refs=["T-RECON-002", "T-EXEC-002"],
                           handbook_ref="§3.3")

    if not intent_issues:
        return make_result(check_id, name, HIGH, PASS,
                           f"Discord channel(s) ({', '.join(discord_channels)}) "
                           f"do not have Message Content Intent enabled",
                           threat_ids=_AS,
                           threat_refs=["T-RECON-002", "T-EXEC-002"],
                           handbook_ref="§3.3")

    return make_result(check_id, name, HIGH, FAIL,
                       f"Discord Message Content Intent or overly broad permissions "
                       f"detected: {'; '.join(intent_issues)}. "
                       f"This allows the bot to read all messages in any channel it can see.",
                       threat_ids=_AS,
                       threat_refs=["T-RECON-002", "T-EXEC-002"],
                       handbook_ref="§3.3",
                       fix_cmd="Disable Message Content Intent in Discord Developer Portal; "
                               "use slash commands or DM-only mode instead",
                       evidence=f"issues={intent_issues}")


# ---------------------------------------------------------------------------
# CH-008: Unofficial connector warning (§3.7)
# ---------------------------------------------------------------------------
def _ch008(channels):
    check_id = "CH-008"
    name = "Unofficial connector warning"

    unofficial = []
    for ch_name, ch_cfg in _get_enabled_channels(channels):
        ch_type = str(ch_cfg.get("type", "")).lower().strip()
        ch_name_lower = ch_name.lower()

        for connector in _UNOFFICIAL_CONNECTORS:
            if connector in ch_type or connector in ch_name_lower:
                unofficial.append(f"{ch_name} (type={ch_type})")
                break

    if not unofficial:
        return make_result(check_id, name, MEDIUM, PASS,
                           "No unofficial/risky connectors detected",
                           threat_ids=_AS,
                           threat_refs=["T-EXEC-001"],
                           handbook_ref="§3.7")

    return make_result(check_id, name, MEDIUM, WARN,
                       f"Unofficial connector(s) detected: {', '.join(unofficial)}. "
                       f"These use reverse-engineered protocols and risk account bans.",
                       threat_ids=_AS,
                       threat_refs=["T-EXEC-001"],
                       handbook_ref="§3.7",
                       fix_cmd="Consider switching to officially supported channels; "
                               "use a dedicated/burner account for unofficial connectors",
                       evidence=f"unofficial_connectors={unofficial}")


# ---------------------------------------------------------------------------
# CH-009: Paired device count (§3.8)
# ---------------------------------------------------------------------------
# See also GW-012 for filesystem-based paired device count
def _ch009(channels):
    check_id = "CH-009"
    name = "Paired device count (per-channel config)"

    device_entries = []
    for ch_name, ch_cfg in _get_enabled_channels(channels):
        # Look for device/session related keys
        devices = ch_cfg.get("devices", ch_cfg.get("sessions", []))
        device_count = ch_cfg.get("deviceCount",
                       ch_cfg.get("device_count",
                       ch_cfg.get("pairedDevices",
                       ch_cfg.get("paired_devices"))))

        count = 0
        if isinstance(devices, list):
            count = len(devices)
        elif isinstance(device_count, int):
            count = device_count

        if count > 0:
            device_entries.append(f"{ch_name}: {count} device(s)/session(s)")

    if not device_entries:
        return make_result(check_id, name, INFO, PASS,
                           "No paired device/session entries found in channel config",
                           threat_ids=_AS,
                           threat_refs=["T-RECON-003"],
                           handbook_ref="§3.8")

    total_devices = sum(
        int(e.split(": ")[1].split(" ")[0]) for e in device_entries
    )

    if total_devices > 1:
        return make_result(check_id, name, INFO, WARN,
                           f"Multiple paired devices/sessions detected: "
                           f"{'; '.join(device_entries)}. "
                           f"Confirm all devices are authorized.",
                           threat_ids=_AS,
                           threat_refs=["T-RECON-003"],
                           handbook_ref="§3.8",
                           fix_cmd="Review paired devices in each messaging platform; "
                                   "revoke any unrecognized sessions",
                           evidence=f"device_entries={device_entries}")

    return make_result(check_id, name, INFO, PASS,
                       f"Paired device count is within expected range: "
                       f"{'; '.join(device_entries)}",
                       threat_ids=_AS,
                       threat_refs=["T-RECON-003"],
                       handbook_ref="§3.8",
                       evidence=f"device_entries={device_entries}")
