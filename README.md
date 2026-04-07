<div align="center">

# OpenClaw Security Audit Skill

**Comprehensive security audit tool for OpenClaw instances**

[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)]()
[![Zero LLM Dependency](https://img.shields.io/badge/LLM_dependency-zero-brightgreen.svg)]()
[![ZAST.AI](https://img.shields.io/badge/based_on-ZAST.AI_Handbook-orange.svg)]()

Based on the [ZAST.AI Security Handbook](https://github.com/zast-ai/openclaw-security) &mdash; 100% deterministic, fully reproducible results.

</div>

> **Disclaimer:** This skill is designed solely to help OpenClaw users discover potential security misconfigurations and usage risks. It does **not** support automatic hardening, and it is **strongly discouraged** to use an agent to auto-remediate based on the audit results — doing so may crash your OpenClaw instance!

---

## Highlights

- **12 Attack Surfaces** &mdash; Gateway exposure, prompt injection, sandbox escape, supply chain, and more
- **80 Deterministic Checks** &mdash; Every check is scripted, no LLM judgment involved
- **27 Threat ID Mappings** &mdash; Mapped to official ZAST.AI threat identifiers
- **Multiple Targets** &mdash; Local instance, Docker container, and remote port scanning
- **Multiple Outputs** &mdash; Terminal colored summary, Markdown report, JSON (CI/CD integration)
- **Zero Dependencies** &mdash; Python standard library + CLI commands only

---

## Quick Start

```bash
# Full audit with fix suggestions (default: ~/.openclaw/)
python3 scripts/openclaw_audit.py --fix

# Only critical issues
python3 scripts/openclaw_audit.py --fix --severity critical

# Docker container audit
python3 scripts/openclaw_audit.py --docker-name my-openclaw --fix

# Remote port exposure check
python3 scripts/openclaw_audit.py --remote 192.168.1.100:18789 --fix
```

> **Claude Code users**: Run `/openclaw-security-audit` directly &mdash; no path needed.

---

## Coverage: 12 Attack Surfaces, 80 Check Items, 27 Threat ID Mappings

```
  The following is the complete 80-item checklist, organized by 12 attack surfaces and 11 modules


  12 Attack Surfaces

  ┌───────┬──────────────────────────┬──────────────┬─────────────┐
  │  ID   │     Attack Surface       │ Handbook Ref │ Check Count │
  ├───────┼──────────────────────────┼──────────────┼─────────────┤
  │ AS-1  │ Gateway Exposure         │ §2           │ 22          │
  ├───────┼──────────────────────────┼──────────────┼─────────────┤
  │ AS-2  │ Message Channels         │ §3           │ 9           │
  ├───────┼──────────────────────────┼──────────────┼─────────────┤
  │ AS-3  │ Prompt Injection         │ §5           │ 3           │
  ├───────┼──────────────────────────┼──────────────┼─────────────┤
  │ AS-4  │ Business Document Inject │ §3.12        │ 1           │
  ├───────┼──────────────────────────┼──────────────┼─────────────┤
  │ AS-5  │ Skill Supply Chain       │ §4, §9       │ 12          │
  ├───────┼──────────────────────────┼──────────────┼─────────────┤
  │ AS-6  │ Data Leakage             │ §5.3, §8.2   │ 10          │
  ├───────┼──────────────────────────┼──────────────┼─────────────┤
  │ AS-7  │ File System & Credentials│ §6           │ 10          │
  ├───────┼──────────────────────────┼──────────────┼─────────────┤
  │ AS-8  │ Sandbox Escape           │ §7, §8.1     │ 11          │
  ├───────┼──────────────────────────┼──────────────┼─────────────┤
  │ AS-9  │ Network/SSRF             │ §8, §9.6     │ 3           │
  ├───────┼──────────────────────────┼──────────────┼─────────────┤
  │ AS-10 │ Agent Behavior Abuse     │ §10          │ 8           │
  ├───────┼──────────────────────────┼──────────────┼─────────────┤
  │ AS-11 │ CI/CD Supply Chain       │ §9.6         │ 2           │
  ├───────┼──────────────────────────┼──────────────┼─────────────┤
  │ AS-12 │ Windows-Specific         │ §9.4         │ 2           │
  └───────┴──────────────────────────┴──────────────┴─────────────┘


  Complete 80-Item Security Checklist

  Module 01: File System & Permissions (FP-001 ~ FP-010) — Attack Surface AS-7

  ┌─────────┬──────────────────────────┬──────────┬──────────────┬──────────────────────────────────────────────────────────────┐
  │ Check ID│         Name             │ Severity │ Handbook Ref │                       Check Description                      │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼──────────────────────────────────────────────────────────────┤
  │ FP-001  │ OpenClaw Dir Permissions │ CRITICAL │ §6.1         │ ~/.openclaw/ directory permissions must be 700               │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼──────────────────────────────────────────────────────────────┤
  │ FP-002  │ Credentials Dir Perms    │ CRITICAL │ §6.1         │ credentials/ directory permissions must be 700               │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼──────────────────────────────────────────────────────────────┤
  │ FP-003  │ .env File Permissions    │ CRITICAL │ §6.1         │ .env file permissions must be 600                            │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼──────────────────────────────────────────────────────────────┤
  │ FP-004  │ openclaw.json Perms      │ CRITICAL │ §6.5         │ Config file permissions 600, prevent hot-reload tampering    │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼──────────────────────────────────────────────────────────────┤
  │ FP-005  │ Sessions Dir Permissions │ HIGH     │ §6.1         │ sessions/ directory permissions must be 700                  │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼──────────────────────────────────────────────────────────────┤
  │ FP-006  │ Attachment File Perms    │ MEDIUM   │ §3.10        │ Media attachments must not be readable by group/other        │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼──────────────────────────────────────────────────────────────┤
  │ FP-007  │ Config Immutable Flag    │ INFO     │ §6.5         │ Whether openclaw.json has chattr/uchg immutable flag set     │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼──────────────────────────────────────────────────────────────┤
  │ FP-008  │ Not in Cloud Sync Dir    │ HIGH     │ §6.9         │ .openclaw/ not inside iCloud/OneDrive/Dropbox/Google Drive   │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼──────────────────────────────────────────────────────────────┤
  │ FP-009  │ Not Tracked by Git       │ HIGH     │ §6.9         │ .openclaw/ not inside a git repository working tree          │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼──────────────────────────────────────────────────────────────┤
  │ FP-010  │ Running User Groups      │ HIGH     │ §1.2         │ Running user should not belong to docker/sudo/wheel/admin    │
  └─────────┴──────────────────────────┴──────────┴──────────────┴──────────────────────────────────────────────────────────────┘

  Module 02: Gateway Configuration (GW-001 ~ GW-013) — Attack Surface AS-1

  ┌─────────┬──────────────────────────┬──────────┬──────────────┬────────────────────────────────────────────────────────┐
  │ Check ID│         Name             │ Severity │ Handbook Ref │                   Check Description                    │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼────────────────────────────────────────────────────────┤
  │ GW-001  │ auth.mode Not none       │ CRITICAL │ §2.1         │ Gateway auth mode must not be "none"                   │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼────────────────────────────────────────────────────────┤
  │ GW-002  │ auth.mode Recommend token│ MEDIUM   │ §2.1         │ Recommended to use "token" mode                        │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼────────────────────────────────────────────────────────┤
  │ GW-003  │ Token Uses secretRef     │ HIGH     │ §2.1         │ Token not stored in plaintext, uses env var reference  │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼────────────────────────────────────────────────────────┤
  │ GW-004  │ No Hardcoded hex token   │ HIGH     │ §2.1         │ No 32+ char hardcoded hex tokens in config files       │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼────────────────────────────────────────────────────────┤
  │ GW-005  │ bind Is loopback         │ CRITICAL │ §2.2         │ Gateway bind address must be "loopback"                │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼────────────────────────────────────────────────────────┤
  │ GW-006  │ Env bind Not lan         │ CRITICAL │ §2.2         │ OPENCLAW_GATEWAY_BIND is not "lan"                     │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼────────────────────────────────────────────────────────┤
  │ GW-007  │ trusted-proxy Warning    │ HIGH     │ §2.3         │ When using trusted-proxy mode, firewall must limit IPs │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼────────────────────────────────────────────────────────┤
  │ GW-008  │ Webhook Token Separate   │ MEDIUM   │ §2.6         │ Gateway token and Webhook token use different env vars │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼────────────────────────────────────────────────────────┤
  │ GW-009  │ debug/verbose Disabled   │ MEDIUM   │ §6.2         │ debug/verbose mode disabled in production              │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼────────────────────────────────────────────────────────┤
  │ GW-010  │ Telemetry Disabled       │ INFO     │ §8.3         │ DISABLE_TELEMETRY=1 is set                             │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼────────────────────────────────────────────────────────┤
  │ GW-011  │ OpenClaw Version Latest  │ HIGH     │ §9.1         │ Compare against npm registry for latest version        │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼────────────────────────────────────────────────────────┤
  │ GW-012  │ Paired Device Count      │ INFO     │ §2.5         │ Check device count in paired/sessions/devices dirs     │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼────────────────────────────────────────────────────────┤
  │ GW-013  │ Token Rotation Period    │ MEDIUM   │ §9.3         │ .env file modification time not exceeding 90 days      │
  └─────────┴──────────────────────────┴──────────┴──────────────┴────────────────────────────────────────────────────────┘

  Module 03: Network Exposure (NE-001 ~ NE-009) — Attack Surfaces AS-1, AS-8, AS-9

  ┌─────────┬──────────────────────────┬──────────┬──────────────┬────────────────────────────────────────────────────────┐
  │ Check ID│         Name             │ Severity │ Handbook Ref │                   Check Description                    │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼────────────────────────────────────────────────────────┤
  │ NE-001  │ Gateway Port 18789       │ CRITICAL │ §2.2         │ Port bind address must be 127.0.0.1                    │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼────────────────────────────────────────────────────────┤
  │ NE-002  │ CDP Port 9222            │ CRITICAL │ §7.4         │ Chrome DevTools Protocol port not exposed              │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼────────────────────────────────────────────────────────┤
  │ NE-003  │ VNC Port 5900            │ HIGH     │ §7.4         │ VNC port not exposed to network                        │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼────────────────────────────────────────────────────────┤
  │ NE-004  │ Extra Ports 18790/6080   │ MEDIUM   │ §2.2         │ Extra port bind address check                          │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼────────────────────────────────────────────────────────┤
  │ NE-005  │ External Reachability    │ CRITICAL │ §2.3         │ Remote --remote HOST:PORT HTTP reachability probe      │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼────────────────────────────────────────────────────────┤
  │ NE-006  │ docker-compose Binding   │ CRITICAL │ §1.4         │ No 0.0.0.0 bindings or bare port mappings in compose   │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼────────────────────────────────────────────────────────┤
  │ NE-007  │ SSH Tunnel/Tailscale     │ INFO     │ §2.3         │ Detect SSH tunnel forwarding 18789 or active Tailscale │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼────────────────────────────────────────────────────────┤
  │ NE-008  │ ACP Port Binding         │ HIGH     │ §9.6         │ Ports 3000/3001/8080/8443 not exposed                  │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼────────────────────────────────────────────────────────┤
  │ NE-009  │ HTTP Proxy Env Vars      │ MEDIUM   │ §8.4         │ Proxy vars inherited by child processes affect sandbox │
  └─────────┴──────────────────────────┴──────────┴──────────────┴────────────────────────────────────────────────────────┘

  Module 04: Message Channel Config (CH-001 ~ CH-009) — Attack Surface AS-2

  ┌─────────┬──────────────────────────┬──────────┬──────────────┬────────────────────────────────────────────────────────────┐
  │ Check ID│         Name             │ Severity │ Handbook Ref │                      Check Description                     │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼────────────────────────────────────────────────────────────┤
  │ CH-001  │ allowFrom Whitelist      │ CRITICAL │ §3.2         │ Each channel must have allowFrom whitelist configured      │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼────────────────────────────────────────────────────────────┤
  │ CH-002  │ Use Numeric IDs          │ MEDIUM   │ §3.4         │ allowFrom uses numeric IDs not usernames (anti-spoof)      │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼────────────────────────────────────────────────────────────┤
  │ CH-003  │ dmPolicy Is pairing      │ HIGH     │ §3.2         │ DM policy must be "pairing" mode                           │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼────────────────────────────────────────────────────────────┤
  │ CH-004  │ Email Channel Warning    │ HIGH     │ §3.11        │ Don't connect primary email, prevent handling OTP/reset    │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼────────────────────────────────────────────────────────────┤
  │ CH-005  │ Cross-Channel Info Leak  │ MEDIUM   │ §3.5         │ Info leak risk when multiple channels connect same Agent   │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼────────────────────────────────────────────────────────────┤
  │ CH-006  │ Bot Not in Groups        │ CRITICAL │ §3.3         │ Bot should not be in group/channel mode(any member injects)│
  ├─────────┼──────────────────────────┼──────────┼──────────────┼────────────────────────────────────────────────────────────┤
  │ CH-007  │ Discord Message Intent   │ HIGH     │ §3.3         │ Message Content Intent not enabled / no admin permissions  │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼────────────────────────────────────────────────────────────┤
  │ CH-008  │ Unofficial Connectors    │ MEDIUM   │ §3.7         │ WhatsApp/WeChat/Line reverse-protocol connector risks      │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼────────────────────────────────────────────────────────────┤
  │ CH-009  │ Paired Device Count      │ INFO     │ §3.8         │ Paired device/session count in channel                     │
  └─────────┴──────────────────────────┴──────────┴──────────────┴────────────────────────────────────────────────────────────┘

  Module 05: Credential Leak Detection (CL-001 ~ CL-008) — Attack Surfaces AS-6, AS-7

  ┌─────────┬──────────────────────────┬──────────┬──────────────┬────────────────────────────────────────────────────────────┐
  │ Check ID│         Name             │ Severity │ Handbook Ref │                      Check Description                     │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼────────────────────────────────────────────────────────────┤
  │ CL-001  │ API Keys in Session Logs │ CRITICAL │ §6.8         │ Search sessions/ for sk-/AKIA/sk-ant- patterns             │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼────────────────────────────────────────────────────────────┤
  │ CL-002  │ Passwords in Session Logs│ HIGH     │ §6.8         │ Search sessions/ for password/secret/private.key           │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼────────────────────────────────────────────────────────────┤
  │ CL-003  │ Sensitive Data in Debug  │ HIGH     │ §6.2         │ Search logs/ for sk-/password/token/cookie                 │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼────────────────────────────────────────────────────────────┤
  │ CL-004  │ .env Plaintext Key Format│ MEDIUM   │ §2.1         │ Detect plaintext API keys for OpenAI/AWS/GitHub/Slack etc  │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼────────────────────────────────────────────────────────────┤
  │ CL-005  │ OAuth Token Rotation     │ MEDIUM   │ §6.7         │ Files in credentials/ not modified for over 90 days        │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼────────────────────────────────────────────────────────────┤
  │ CL-006  │ Hardcoded Token in Config│ HIGH     │ §2.1         │ Scan all .json/.yaml/.yml/.toml for hardcoded hex tokens   │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼────────────────────────────────────────────────────────────┤
  │ CL-007  │ Base64 Values in .env    │ MEDIUM   │ §9.6         │ Base64 encoding can bypass sanitize-env-vars.ts matching   │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼────────────────────────────────────────────────────────────┤
  │ CL-008  │ Shell History Leak       │ HIGH     │ §6.4         │ Search .zsh_history/.bash_history for token/key patterns   │
  └─────────┴──────────────────────────┴──────────┴──────────────┴────────────────────────────────────────────────────────────┘

  Module 06: Skill Supply Chain Audit (SK-001 ~ SK-012) — Attack Surface AS-5

  ┌─────────┬──────────────────────────┬──────────┬──────────────┬────────────────────────────────────────────────────────────┐
  │ Check ID│         Name             │ Severity │ Handbook Ref │                      Check Description                     │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼────────────────────────────────────────────────────────────┤
  │ SK-001  │ Skill Inventory & Dates  │ INFO     │ §4.1         │ List all installed Skills with mod times, flag new in 7d   │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼────────────────────────────────────────────────────────────┤
  │ SK-002  │ Dangerous Function Ptrns │ HIGH     │ §4.2         │ Search for exec/eval/spawn/child_process/new Function      │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼────────────────────────────────────────────────────────────┤
  │ SK-003  │ Credential Theft Ptrns   │ CRITICAL │ §4.2         │ Detect env read + network send combo (process.env+fetch)   │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼────────────────────────────────────────────────────────────┤
  │ SK-004  │ Cryptomining Signatures  │ CRITICAL │ §4.2         │ Search for xmrig/coinhive/cryptonight/stratum+tcp etc      │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼────────────────────────────────────────────────────────────┤
  │ SK-005  │ Covert Comm Channels     │ MEDIUM   │ §4.2         │ Detect WebSocket/ws:///wss:// C2 channel patterns          │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼────────────────────────────────────────────────────────────┤
  │ SK-006  │ Code Obfuscation Detect  │ HIGH     │ §4.2         │ Shannon entropy >5.5 + Unicode homoglyphs (Cyrillic spoof) │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼────────────────────────────────────────────────────────────┤
  │ SK-007  │ Auto-Start Events        │ MEDIUM   │ §4.3         │ Detect onStartup/activationEvents/autostart registration   │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼────────────────────────────────────────────────────────────┤
  │ SK-008  │ Network Request Patterns │ HIGH     │ §4.4         │ Detect fetch/axios/urllib/requests/curl (staged payloads)  │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼────────────────────────────────────────────────────────────┤
  │ SK-009  │ Version Lock/Auto-Update │ MEDIUM   │ §4.5         │ Whether version lock file exists, auto-update enabled      │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼────────────────────────────────────────────────────────────┤
  │ SK-010  │ curl|bash Install History│ HIGH     │ §9.5         │ Search shell history for curl|bash/ wget|sh unsafe installs│
  ├─────────┼──────────────────────────┼──────────┼──────────────┼────────────────────────────────────────────────────────────┤
  │ SK-011  │ npm audit CVE            │ HIGH     │ §9.1         │ Run npm audit on Skill npm deps, detect known vulns        │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼────────────────────────────────────────────────────────────┤
  │ SK-012  │ Unused Skills            │ INFO     │ §9.3         │ Skills not accessed for 90+ days, reduce attack surface    │
  └─────────┴──────────────────────────┴──────────┴──────────────┴────────────────────────────────────────────────────────────┘

  Module 07: Sandbox & Docker (SB-001 ~ SB-011) — Attack Surface AS-8

  ┌─────────┬──────────────────────────┬──────────┬──────────────┬──────────────────────────────────────────────────────────────────┐
  │ Check ID│         Name             │ Severity │ Handbook Ref │                        Check Description                         │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼──────────────────────────────────────────────────────────────────┤
  │ SB-001  │ Docker Socket Mount      │ CRITICAL │ §7.1         │ Sandbox container must not mount docker.sock (equals host root)  │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼──────────────────────────────────────────────────────────────────┤
  │ SB-002  │ Network Mode             │ CRITICAL │ §7.2         │ Must not use "host" network mode                                 │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼──────────────────────────────────────────────────────────────────┤
  │ SB-003  │ Outbound Network Restrict│ HIGH     │ §8.1         │ Container network marked internal, limit outbound traffic        │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼──────────────────────────────────────────────────────────────────┤
  │ SB-004  │ Dangerous Linux Caps     │ CRITICAL │ §7.2         │ No ALL/SYS_ADMIN/NET_ADMIN capabilities                          │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼──────────────────────────────────────────────────────────────────┤
  │ SB-005  │ seccomp Configuration    │ HIGH     │ §7.2         │ Not "unconfined" (allows all syscalls)                           │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼──────────────────────────────────────────────────────────────────┤
  │ SB-006  │ Dangerous Path Mounts    │ CRITICAL │ §7.2         │ Must not mount /etc, /proc, /sys, /dev, /root                    │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼──────────────────────────────────────────────────────────────────┤
  │ SB-007  │ no-new-privileges        │ HIGH     │ §1.4         │ Set no-new-privileges to prevent setuid escalation               │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼──────────────────────────────────────────────────────────────────┤
  │ SB-008  │ Sandbox Image Compilers  │ INFO     │ §7.3         │ Whether image contains go/gcc/rustc/node/python3                 │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼──────────────────────────────────────────────────────────────────┤
  │ SB-009  │ compose Comprehensive Chk│ HIGH     │ §1.4         │ Compose file: no docker.sock + cap_drop ALL + loopback bind      │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼──────────────────────────────────────────────────────────────────┤
  │ SB-010  │ cap_drop ALL             │ MEDIUM   │ §1.4         │ Container drops all capabilities then adds back as needed        │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼──────────────────────────────────────────────────────────────────┤
  │ SB-011  │ Docker Image SLSA Prov   │ INFO     │ §9.6         │ Whether image has SLSA provenance tag (supply chain verify)      │
  └─────────┴──────────────────────────┴──────────┴──────────────┴──────────────────────────────────────────────────────────────────┘

  Module 08: Session & Memory (SM-001 ~ SM-005) — Attack Surfaces AS-3, AS-7

  ┌─────────┬──────────────────────────┬──────────┬──────────────┬──────────────────────────────────────────────────────────────┐
  │ Check ID│         Name             │ Severity │ Handbook Ref │                       Check Description                      │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼──────────────────────────────────────────────────────────────┤
  │ SM-001  │ MEMORY.md Injection Ptrn │ HIGH     │ §5.7         │ Detect "ignore instruction", script tags, eval inject ptrns  │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼──────────────────────────────────────────────────────────────┤
  │ SM-002  │ memory/ Anomalous Files  │ MEDIUM   │ §5.7         │ Memory files modified in last 7 days need manual review      │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼──────────────────────────────────────────────────────────────┤
  │ SM-003  │ Old Session Log Cleanup  │ INFO     │ §6.8         │ .jsonl/.json/.log files in sessions/ older than 30 days      │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼──────────────────────────────────────────────────────────────┤
  │ SM-004  │ Session Log Total Size   │ INFO     │ §6.8         │ sessions/ directory over 100MB needs cleanup                 │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼──────────────────────────────────────────────────────────────┤
  │ SM-005  │ Workspace Isolation      │ INFO     │ §1.3         │ Multi-workspace scenarios should use independent configs     │
  └─────────┴──────────────────────────┴──────────┴──────────────┴──────────────────────────────────────────────────────────────┘

  Module 09: Agent Behavior Config (AB-001 ~ AB-008) — Attack Surfaces AS-4, AS-6, AS-10

  ┌─────────┬──────────────────────────┬─────────────┬──────────────┬──────────────────────────────────────────────────────────────┐
  │ Check ID│         Name             │  Severity   │ Handbook Ref │                       Check Description                      │
  ├─────────┼──────────────────────────┼─────────────┼──────────────┼──────────────────────────────────────────────────────────────┤
  │ AB-001  │ exec.mode Is ask         │ CRITICAL    │ §5.5         │ Agent must confirm with user before executing, not "allow"   │
  ├─────────┼──────────────────────────┼─────────────┼──────────────┼──────────────────────────────────────────────────────────────┤
  │ AB-002  │ sandbox.mode Config      │ HIGH        │ §7.1         │ Sandbox mode should be docker/sandbox/container              │
  ├─────────┼──────────────────────────┼─────────────┼──────────────┼──────────────────────────────────────────────────────────────┤
  │ AB-003  │ Message Send Limit       │ MEDIUM      │ §10.4        │ Configure message rate limit, prevent infinite messaging     │
  ├─────────┼──────────────────────────┼─────────────┼──────────────┼──────────────────────────────────────────────────────────────┤
  │ AB-004  │ API Spend Limit Alert    │ INFO        │ §10.3        │ Detect OpenAI/Anthropic API Keys, remind monthly cap setup   │
  ├─────────┼──────────────────────────┼─────────────┼──────────────┼──────────────────────────────────────────────────────────────┤
  │ AB-005  │ MCP Server Audit         │ HIGH/MEDIUM │ §5.3         │ List configured MCP server count, each is an exec surface    │
  ├─────────┼──────────────────────────┼─────────────┼──────────────┼──────────────────────────────────────────────────────────────┤
  │ AB-006  │ Document Processing Cfg  │ HIGH        │ §3.12        │ Whether format stripping enabled (anti white-text/OCR inj)   │
  ├─────────┼──────────────────────────┼─────────────┼──────────────┼──────────────────────────────────────────────────────────────┤
  │ AB-007  │ Outbound URL Whitelist   │ HIGH        │ §8.2         │ web_fetch has URL whitelist configured (anti data exfil)     │
  ├─────────┼──────────────────────────┼─────────────┼──────────────┼──────────────────────────────────────────────────────────────┤
  │ AB-008  │ Financial API Key Alert  │ CRITICAL    │ §10.1        │ Detect Stripe/PayPal/Crypto Keys, require dual-sign approve  │
  └─────────┴──────────────────────────┴─────────────┴──────────────┴──────────────────────────────────────────────────────────────┘

  Module 10: System Persistence (SP-001 ~ SP-004) — Attack Surface AS-5

  ┌─────────┬──────────────────────────┬──────────┬──────────────┬────────────────────────────────────────────────────────┐
  │ Check ID│         Name             │ Severity │ Handbook Ref │                   Check Description                    │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼────────────────────────────────────────────────────────┤
  │ SP-001  │ Crontab Entries          │ HIGH     │ §11.4        │ Check crontab for openclaw-related scheduled tasks     │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼────────────────────────────────────────────────────────┤
  │ SP-002  │ macOS launchd Services   │ HIGH     │ §11.4        │ Suspicious services in LaunchAgents/LaunchDaemons      │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼────────────────────────────────────────────────────────┤
  │ SP-003  │ Linux systemd Services   │ HIGH     │ §11.4        │ Suspicious openclaw services in systemd user/system    │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼────────────────────────────────────────────────────────┤
  │ SP-004  │ Shell Startup Files      │ MEDIUM   │ §11.4        │ openclaw-related entries in .bashrc/.zshrc etc         │
  └─────────┴──────────────────────────┴──────────┴──────────────┴────────────────────────────────────────────────────────┘

  Module 11: Windows-Specific (WIN-001 ~ WIN-002) — Attack Surface AS-12

  ┌─────────┬──────────────────────────┬──────────┬──────────────┬────────────────────────────────────────────────────────────┐
  │ Check ID│         Name             │ Severity │ Handbook Ref │                      Check Description                     │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼────────────────────────────────────────────────────────────┤
  │ WIN-001 │ Node.js Version          │ CRITICAL │ §9.4         │ >= 20.11.1 (fixes CVE-2024-27980 command injection)        │
  ├─────────┼──────────────────────────┼──────────┼──────────────┼────────────────────────────────────────────────────────────┤
  │ WIN-002 │ Suspicious .bat/.cmd     │ MEDIUM   │ §9.4         │ .bat/.cmd files in non-system PATH dirs (CVE-2024-27980)   │
  └─────────┴──────────────────────────┴──────────┴──────────────┴────────────────────────────────────────────────────────────┘


  27 Threat ID Mappings

  ┌───────────────┬────────────────────────────────────────┬────────────────────────────────────────┐
  │   Threat ID   │                 Name                   │            Associated Checks           │
  ├───────────────┼────────────────────────────────────────┼────────────────────────────────────────┤
  │ T-RECON-001   │ Public API Reconnaissance              │ NE-005, GW-005, GW-006                 │
  ├───────────────┼────────────────────────────────────────┼────────────────────────────────────────┤
  │ T-RECON-002   │ Channel Enumeration                    │ CH-006, CH-007                         │
  ├───────────────┼────────────────────────────────────────┼────────────────────────────────────────┤
  │ T-RECON-003   │ Message Metadata Analysis              │ CH-005                                 │
  ├───────────────┼────────────────────────────────────────┼────────────────────────────────────────┤
  │ T-ACCESS-001  │ Gateway Auth Bypass (none mode)        │ GW-001, GW-002                         │
  ├───────────────┼────────────────────────────────────────┼────────────────────────────────────────┤
  │ T-ACCESS-002  │ Config Exposure Token Theft             │ GW-003, GW-004, CL-006                │
  ├───────────────┼────────────────────────────────────────┼────────────────────────────────────────┤
  │ T-ACCESS-003  │ trusted-proxy Bypass                   │ GW-007                                 │
  ├───────────────┼────────────────────────────────────────┼────────────────────────────────────────┤
  │ T-ACCESS-004  │ Malicious Skill Installation           │ SK-002, SK-003, SK-004, SK-010         │
  ├───────────────┼────────────────────────────────────────┼────────────────────────────────────────┤
  │ T-ACCESS-005  │ Skill Auto-Update Hijack               │ SK-009                                 │
  ├───────────────┼────────────────────────────────────────┼────────────────────────────────────────┤
  │ T-ACCESS-006  │ DM Policy Bypass                       │ CH-003                                 │
  ├───────────────┼────────────────────────────────────────┼────────────────────────────────────────┤
  │ T-EXEC-001    │ Channel Message Prompt Injection       │ CH-001, CH-002, AB-001                 │
  ├───────────────┼────────────────────────────────────────┼────────────────────────────────────────┤
  │ T-EXEC-002    │ Cross-Channel Info Leak Exploitation   │ CH-005                                 │
  ├───────────────┼────────────────────────────────────────┼────────────────────────────────────────┤
  │ T-EXEC-003    │ Docker Socket Sandbox Escape           │ SB-001, SB-006                         │
  ├───────────────┼────────────────────────────────────────┼────────────────────────────────────────┤
  │ T-EXEC-004    │ Linux Capabilities Sandbox Escape      │ SB-004, SB-005                         │
  ├───────────────┼────────────────────────────────────────┼────────────────────────────────────────┤
  │ T-EXEC-005    │ Skill Code Execution (eval/exec/spawn) │ SK-002, SK-003                         │
  ├───────────────┼────────────────────────────────────────┼────────────────────────────────────────┤
  │ T-EXEC-006    │ Agent Unrestricted Command Execution   │ AB-001, AB-002                         │
  ├───────────────┼────────────────────────────────────────┼────────────────────────────────────────┤
  │ T-EVADE-001   │ Obfuscated Skill Code                  │ SK-006                                 │
  ├───────────────┼────────────────────────────────────────┼────────────────────────────────────────┤
  │ T-EVADE-002   │ Config Hot-Reload Tampering            │ FP-004, FP-007                         │
  ├───────────────┼────────────────────────────────────────┼────────────────────────────────────────┤
  │ T-EVADE-003   │ Telemetry/Debug Info Leakage           │ GW-009, GW-010                         │
  ├───────────────┼────────────────────────────────────────┼────────────────────────────────────────┤
  │ T-EVADE-004   │ Staged Payload Delivery                │ SK-008                                 │
  ├───────────────┼────────────────────────────────────────┼────────────────────────────────────────┤
  │ T-PERSIST-001 │ cron/launchd/systemd/shell Persistence │ SP-001, SP-002, SP-003, SP-004         │
  ├───────────────┼────────────────────────────────────────┼────────────────────────────────────────┤
  │ T-DISC-001    │ Permission-Based Dir Traversal         │ FP-001, FP-002, FP-003, FP-005         │
  ├───────────────┼────────────────────────────────────────┼────────────────────────────────────────┤
  │ T-DISC-002    │ Cloud Sync Credential Leak             │ FP-008                                 │
  ├───────────────┼────────────────────────────────────────┼────────────────────────────────────────┤
  │ T-DISC-003    │ Git Repo Credential Leak               │ FP-009                                 │
  ├───────────────┼────────────────────────────────────────┼────────────────────────────────────────┤
  │ T-DISC-004    │ Shell History Credential Leak           │ CL-008                                │
  ├───────────────┼────────────────────────────────────────┼────────────────────────────────────────┤
  │ T-EXFIL-001   │ web_fetch Outbound Data Exfiltration   │ AB-007, SB-003                         │
  ├───────────────┼────────────────────────────────────────┼────────────────────────────────────────┤
  │ T-EXFIL-002   │ Session Log Data Exposure              │ CL-001, CL-002, CL-003, SM-003, SM-004 │
  ├───────────────┼────────────────────────────────────────┼────────────────────────────────────────┤
  │ T-EXFIL-003   │ Skill Credential Theft                 │ SK-003, SK-005                         │
  ├───────────────┼────────────────────────────────────────┼────────────────────────────────────────┤
  │ T-IMPACT-001  │ Financial API Unauthorized Access       │ AB-008                                │
  ├───────────────┼────────────────────────────────────────┼────────────────────────────────────────┤
  │ T-IMPACT-002  │ Agent Message Spam/Abuse               │ AB-003                                 │
  ├───────────────┼────────────────────────────────────────┼────────────────────────────────────────┤
  │ T-IMPACT-003  │ API Over-Consumption                   │ AB-004                                 │
  ├───────────────┼────────────────────────────────────────┼────────────────────────────────────────┤
  │ T-IMPACT-004  │ Memory Poisoning Persistence           │ SM-001, SM-002                         │
  ├───────────────┼────────────────────────────────────────┼────────────────────────────────────────┤
  │ T-IMPACT-005  │ MCP Server Abuse                       │ AB-005                                 │
  └───────────────┴────────────────────────────────────────┴────────────────────────────────────────┘


  Severity Distribution Statistics

  ┌──────────┬───────┬───────┐
  │  Level   │ Count │  %    │
  ├──────────┼───────┼───────┤
  │ CRITICAL │ 20    │ 25%   │
  ├──────────┼───────┼───────┤
  │ HIGH     │ 34    │ 42.5% │
  ├──────────┼───────┼───────┤
  │ MEDIUM   │ 16    │ 20%   │
  ├──────────┼───────┼───────┤
  │ INFO     │ 10    │ 12.5% │
  ├──────────┼───────┼───────┤
  │ Total    │ 80    │ 100%  │
  └──────────┴───────┴───────┘

```

---

# USAGE
---

## Complete Parameter Reference

| Parameter | Description | Default |
|-----------|-------------|---------|
| (no parameters) | Audit the local default instance at `~/.openclaw/`, run all modules | — |
| `--openclaw-dir PATH` | Custom OpenClaw directory path | `~/.openclaw/` |
| `--remote HOST[:PORT]` | Additionally check remote instance port exposure (can be specified multiple times) | — |
| `--docker-name NAME` | Specify Docker container name | `openclaw-sandbox` |
| `--compose-file PATH` | Specify docker-compose.yml path | Auto-search |
| `--modules 01,03,07` | Only run specified modules (comma-separated) | All modules |
| `--skip 07,11` | Skip specified modules (comma-separated) | — |
| `--severity critical` | Minimum display level: `critical` \| `high` \| `medium` \| `info` | `info` |
| `--format terminal\|md\|both` | Output format | `both` |
| `--fix` | Include fix command suggestions in the report | Off |
| `--checklist` | Output §9.3 periodic checklist table | Off |
| `--json` | Additionally output JSON format (CI/CD integration) | Off |
| `--output-dir PATH` | Report output directory | `./openclaw-audit-report/` |
| `--whitelist SKILL1,SKILL2` | Skill whitelist, excluded from supply chain scan | `openclaw-security-audit` |

---

## Local Instance Audit Method

```bash
Simply run  /openclaw-security-audit

  No parameters needed, audits ~/.openclaw/ directory by default, runs all 11 modules:

  ┌────────┬──────────────────────────────────────────┐
  │ Module │              Check Content               │
  ├────────┼──────────────────────────────────────────┤
  │ 01     │ File System Permissions                  │
  ├────────┼──────────────────────────────────────────┤
  │ 02     │ Gateway Configuration                    │
  ├────────┼──────────────────────────────────────────┤
  │ 03     │ Network Port Exposure (local bind check) │
  ├────────┼──────────────────────────────────────────┤
  │ 04     │ Channel Configuration                    │
  ├────────┼──────────────────────────────────────────┤
  │ 05     │ Credential Leak Detection                │
  ├────────┼──────────────────────────────────────────┤
  │ 06     │ Skill Supply Chain Audit                 │
  ├────────┼──────────────────────────────────────────┤
  │ 07     │ Sandbox & Docker Security                │
  ├────────┼──────────────────────────────────────────┤
  │ 08     │ Session & Memory                         │
  ├────────┼──────────────────────────────────────────┤
  │ 09     │ Agent Behavior Configuration             │
  ├────────┼──────────────────────────────────────────┤
  │ 10     │ System Persistence Check                 │
  ├────────┼──────────────────────────────────────────┤
  │ 11     │ Windows-Specific (auto-skipped on macOS) │
  └────────┴──────────────────────────────────────────┘

  Common Combinations

  # Full audit + fix suggestions
  /openclaw-security-audit --fix

  # Only show critical issues
  /openclaw-security-audit --fix --severity critical

  # Specify OpenClaw directory (when not using default path)
  /openclaw-security-audit --openclaw-dir /path/to/openclaw --fix

  # Include Docker container checks
  /openclaw-security-audit --fix --docker-name my-openclaw-container

  # Only run specific modules (e.g., permissions + network + credentials)
  /openclaw-security-audit --modules 01,03,05 --fix

  # Skip Docker and Windows modules
  /openclaw-security-audit --skip 07,11 --fix

  # Terminal summary only (no Markdown report)
  /openclaw-security-audit --fix --format terminal

  # Specify report output directory
  /openclaw-security-audit --fix --output-dir /tmp/my-audit-report

  # Full audit + JSON output + periodic checklist
  /openclaw-security-audit --fix --json --checklist
```


---

## Docker Audit Method

```bash
Docker checks use --docker-name to specify the container name:

  /openclaw-security-audit --docker-name openclaw-sandbox --fix

  The default container name is openclaw-sandbox. If your container name differs, you must specify it explicitly.

  Common Combinations

  # Basic Docker audit
  /openclaw-security-audit --docker-name my-openclaw --fix

  # Also specify docker-compose file (check port binding config)
  /openclaw-security-audit --docker-name my-openclaw --compose-file ./docker-compose.yml --fix

  # Only run Docker-related modules (Sandbox + Network + compose config)
  /openclaw-security-audit --docker-name my-openclaw --modules 03,07 --fix

  # Full audit: Docker + Remote port + JSON
  /openclaw-security-audit --docker-name my-openclaw --remote 10.0.0.5:18789 --fix --json

  Docker-Related Check Items

  Primarily involves two modules:

  Module 03 (Network Exposure) — NE-006:
  - Scans docker-compose.yml for port bindings
  - Detects 0.0.0.0:PORT:PORT exposure (should be 127.0.0.1:PORT:PORT)
  - Detects bare port mappings like 18789:18789 (Docker defaults to 0.0.0.0)
  - Detects LAN-related network_mode configuration

  Module 07 (Sandbox & Docker) — Checks:
  - Container isolation configuration
  - Sandbox security policies
  - Container runtime permissions

  Compose File Search Paths

  If --compose-file is not specified, the script searches in order:
  1. ~/.openclaw/docker-compose.yml
  2. ~/.openclaw/docker-compose.yaml
  3. ~/docker-compose.yml
  4. ./docker-compose.yml
```

---

## Remote Audit Method

```bash
  Use /openclaw-security-audit to check remote OpenClaw security

  Basic Usage

  /openclaw-security-audit --remote HOST:PORT

  Example:
  /openclaw-security-audit --remote 192.168.1.100:18789

  What Remote Checks Can Do

  The --remote parameter triggers the NE-005 external reachability test, which:
  1. Sends a curl request to http://HOST:PORT/health (3-second timeout)
  2. If a valid HTTP status code is returned → CRITICAL FAIL (port exposed on network)
  3. If connection fails → PASS (port unreachable, as expected)

  Check multiple remote hosts simultaneously

  /openclaw-security-audit --remote 10.0.0.5:18789 --remote 10.0.0.5:9222 --remote 10.0.0.5:5900

  Full command example (with all common options)

  /openclaw-security-audit --remote 192.168.1.100:18789 --fix --json --severity critical

  --fix — Include fix command suggestions
  --json — Additionally output JSON (for CI/CD)
  --severity critical — Only show CRITICAL level

  Important Notes

  1. Remote check scope is limited — --remote only performs port reachability tests (HTTP probe), it does not SSH into the remote machine for local checks
  2. Local checks still run — In addition to remote probing, the script also checks the local ~/.openclaw/ directory, port bindings, Docker config, and all 11 modules
  3. To run only remote checks, use --modules 03 to run only the network exposure module:
  /openclaw-security-audit --remote 192.168.1.100:18789 --modules 03 --fix
  4. Checked ports include: 18789 (Gateway), 9222 (CDP), 5900 (VNC), 18790/6080 (extension ports), 3000/3001/8080/8443 (ACP ports)

  Report Output

  After audit completion, reports are generated in ./openclaw-audit-report/ (customizable with --output-dir):
  - Terminal colored summary
  - Markdown report (when --format is md or both)
  - JSON report (when --json is used)
```


---
