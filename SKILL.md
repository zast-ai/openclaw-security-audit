---
name: openclaw-security-audit
description: |
  Comprehensive security audit tool for OpenClaw instances. Based on the ZAST.AI Security Handbook,
  covering 12 attack surfaces, 80 deterministic checks, and 27 official threat ID mappings.
  Executed using CLI commands and Python standard library scripts, zero LLM dependency,
  100% reproducible results.

  Supports: Local instance + Docker container + Remote port checks
  Output: Terminal colored summary + Markdown report + JSON (CI/CD integration)

  Use when: openclaw audit, openclaw security, openclaw security check, openclaw security audit,
  openclaw hardening, /openclaw-audit, openclaw security check
---

# OpenClaw Security Audit v1.0.0

You are now entering OpenClaw security audit mode.

## Audit Target

$ARGUMENTS

## Execution Method

**Core Principle**: All checks are performed via Python scripts + CLI commands, no LLM judgment is used.

### Step 1: Run the Main Audit Script

**Path Rule**: Do not hardcode the skill installation path. You already know the full path of this
SKILL.md when loading it — the directory containing it is SKILL_DIR. The script is located at
`SKILL_DIR/scripts/openclaw_audit.py`.

For example: if this file's path is `/x/y/openclaw-security-audit/SKILL.md`, then run:

```bash
python3 /x/y/openclaw-security-audit/scripts/openclaw_audit.py \
  --format both \
  --fix \
  $ARGUMENTS
```

### Step 2: Display Terminal Summary

After the script finishes, directly display the audit summary from the terminal output.

### Step 3: Highlight Key Findings

If there are CRITICAL or HIGH severity findings:
- List them one by one with fix commands
- Remind the user to prioritize CRITICAL items

### Step 4: Report Path

Inform the user of the full report file path.

## Available Parameters

- No parameters: Audit the local default instance at ~/.openclaw/
- `--openclaw-dir PATH`: Custom OpenClaw directory path (default: ~/.openclaw/)
- `--remote HOST:PORT`: Additionally check remote instance port exposure (can be specified multiple times)
- `--docker-name NAME`: Specify Docker container name (default: openclaw-sandbox)
- `--compose-file PATH`: Specify docker-compose.yml path
- `--modules 01,03,07`: Only run specified modules
- `--skip 07,11`: Skip specified modules
- `--severity critical`: Minimum display level: critical|high|medium|info (default: info)
- `--format terminal|md|both`: Output format (default: both)
- `--fix`: Include fix command suggestions in the report
- `--checklist`: Output §9.3 periodic checklist table
- `--json`: Additionally output JSON format (CI/CD integration)
- `--output-dir PATH`: Report output directory (default: ./openclaw-audit-report/)
- `--whitelist SKILL1,SKILL2`: Skill whitelist, excluded from supply chain scan (default: openclaw-security-audit)
