#!/usr/bin/env python3
"""OpenClaw Security Audit - Report Generator

Generates terminal colored summary, Markdown report, JSON output, and fix script.
"""

import json
import os
import sys
from datetime import datetime

from .utils import (
    CRITICAL, HIGH, MEDIUM, INFO,
    PASS, FAIL, WARN, SKIP, ERROR,
    COLORS, TOOL_VERSION,
    CONFIDENCE_HIGH, CONFIDENCE_MEDIUM, CONFIDENCE_LOW,
    get_os_name, format_size,
)

# Severity ordering for display
SEVERITY_ORDER = [CRITICAL, HIGH, MEDIUM, INFO]
STATUS_ORDER = [FAIL, WARN, PASS, SKIP, ERROR]


def _severity_icon(severity):
    icons = {CRITICAL: "🔴", HIGH: "🟠", MEDIUM: "🟡", INFO: "🔵"}
    return icons.get(severity, "⚪")


def _status_icon(status):
    icons = {PASS: "✅", FAIL: "❌", WARN: "⚠️", SKIP: "⏭️", ERROR: "💥"}
    return icons.get(status, "❓")


def _color(text, color_name):
    c = COLORS.get(color_name, "")
    r = COLORS.get("reset", "")
    return f"{c}{text}{r}"


def count_by_status(results):
    """Count results by status."""
    counts = {PASS: 0, FAIL: 0, WARN: 0, SKIP: 0, ERROR: 0}
    for r in results:
        s = r.get("status", "")
        if s in counts:
            counts[s] += 1
    return counts


def count_by_severity(results):
    """Count FAIL/WARN results by severity."""
    counts = {CRITICAL: 0, HIGH: 0, MEDIUM: 0, INFO: 0}
    for r in results:
        if r.get("status") in (FAIL, WARN):
            sev = r.get("severity", "")
            if sev in counts:
                counts[sev] += 1
    return counts


def filter_results(results, min_severity=None, status_filter=None):
    """Filter results by minimum severity and/or status."""
    sev_rank = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, INFO: 3}
    filtered = results
    if min_severity and min_severity in sev_rank:
        min_rank = sev_rank[min_severity]
        filtered = [r for r in filtered if sev_rank.get(r.get("severity"), 3) <= min_rank]
    if status_filter:
        filtered = [r for r in filtered if r.get("status") in status_filter]
    return filtered


def group_by_severity(results):
    """Group results by severity, only FAIL/WARN."""
    groups = {CRITICAL: [], HIGH: [], MEDIUM: [], INFO: []}
    for r in results:
        if r.get("status") in (FAIL, WARN):
            sev = r.get("severity", INFO)
            if sev in groups:
                groups[sev].append(r)
    return groups


# ============================================================
# Terminal Report
# ============================================================

def generate_terminal_report(results, meta, show_fix=False, min_severity=None):
    """Generate colored terminal output."""
    lines = []
    bold = COLORS.get("bold", "")
    dim = COLORS.get("dim", "")
    reset = COLORS.get("reset", "")

    # Header
    lines.append("")
    lines.append(f"{bold}{'═' * 75}{reset}")
    lines.append(f"{bold}  OpenClaw Security Audit Report{reset}")
    lines.append(f"  Target: {meta.get('target_dir', '~/.openclaw/')} | "
                 f"OS: {meta.get('os', 'unknown')} | "
                 f"Date: {meta.get('audit_time', '')}")
    oc_ver = meta.get("openclaw_version", "unknown")
    lines.append(f"  OpenClaw: {oc_ver} | Audit Tool: v{TOOL_VERSION}")
    lines.append(f"{bold}{'═' * 75}{reset}")

    # Summary counts
    status_counts = count_by_status(results)
    sev_counts = count_by_severity(results)

    summary_parts = []
    for sev in SEVERITY_ORDER:
        c = sev_counts[sev]
        if c > 0:
            color = sev if sev != INFO else "info"
            summary_parts.append(f"{_color(f'{sev.upper()}: {c}', color)}")
    summary_parts.append(f"{_color(f'PASS: {status_counts[PASS]}', 'pass')}")
    if status_counts[SKIP] > 0:
        summary_parts.append(f"{_color(f'SKIP: {status_counts[SKIP]}', 'skip')}")
    if status_counts[ERROR] > 0:
        summary_parts.append(f"{_color(f'ERROR: {status_counts[ERROR]}', 'error')}")

    lines.append("")
    lines.append(f"  {' | '.join(summary_parts)}")
    lines.append("")

    # Filtered results
    filtered = results if min_severity is None else filter_results(results, min_severity=min_severity)
    groups = group_by_severity(filtered)

    for sev in SEVERITY_ORDER:
        items = groups.get(sev, [])
        if not items:
            continue

        color = sev if sev != INFO else "info"
        lines.append(f"{_color(f'══ {sev.upper()} ', color)}{'═' * (70 - len(sev))}")

        for r in items:
            status = r.get("status", "")
            status_tag = f"[{status}]"
            conf = r.get("confidence", "")
            conf_tag = f" [{conf}]" if conf else ""
            lines.append(f"  {_color(status_tag, color)} {r['id']}: {r['name']} ({r.get('handbook_ref', '')}){dim}{conf_tag}{reset}")

            if r.get("detail"):
                lines.append(f"    {dim}{r['detail']}{reset}")

            if r.get("evidence"):
                lines.append(f"    {dim}Evidence: {r['evidence'][:150]}{reset}")

            if show_fix and r.get("fix_cmd"):
                lines.append(f"    {_color('Fix:', 'pass')} {r['fix_cmd']}")

            lines.append("")

    # Fix commands summary
    if show_fix:
        fix_results = [r for r in results if r.get("fix_cmd") and r.get("status") in (FAIL, WARN)]
        if fix_results:
            lines.append(f"{bold}══ Fix Commands Summary {'═' * 52}{reset}")
            for r in fix_results:
                lines.append(f"  # {r['id']}: {r['name']}")
                lines.append(f"  {r['fix_cmd']}")
                lines.append("")

    lines.append(f"{bold}{'═' * 75}{reset}")
    return "\n".join(lines)


# ============================================================
# Markdown Report
# ============================================================

def generate_markdown_report(results, meta, show_fix=False, checklist=False):
    """Generate full Markdown report."""
    lines = []

    # Header
    lines.append("# OpenClaw 安全审计报告")
    lines.append("")
    lines.append(f"> 审计时间: {meta.get('audit_time', '')}")
    lines.append(f"> 目标: {meta.get('target_dir', '~/.openclaw/')}")
    lines.append(f"> 操作系统: {meta.get('os', 'unknown')} {meta.get('os_version', '')}")
    oc_ver = meta.get("openclaw_version", "unknown")
    lines.append(f"> OpenClaw 版本: {oc_ver}")
    lines.append(f"> 审计工具版本: v{TOOL_VERSION}")
    lines.append("")

    # Summary table
    status_counts = count_by_status(results)
    sev_counts = count_by_severity(results)
    total = len(results)

    lines.append("## 风险统计")
    lines.append("")
    lines.append("| 级别 | 数量 | 占比 |")
    lines.append("|------|------|------|")
    for sev in SEVERITY_ORDER:
        c = sev_counts[sev]
        pct = f"{c / total * 100:.1f}%" if total > 0 else "0%"
        icon = _severity_icon(sev)
        lines.append(f"| {icon} {sev.upper()} | {c} | {pct} |")
    pass_pct = f"{status_counts[PASS] / total * 100:.1f}%" if total > 0 else "0%"
    lines.append(f"| {_status_icon(PASS)} PASS | {status_counts[PASS]} | {pass_pct} |")
    if status_counts[SKIP] > 0:
        skip_pct = f"{status_counts[SKIP] / total * 100:.1f}%" if total > 0 else "0%"
        lines.append(f"| {_status_icon(SKIP)} SKIP | {status_counts[SKIP]} | {skip_pct} |")
    if status_counts[ERROR] > 0:
        err_pct = f"{status_counts[ERROR] / total * 100:.1f}%" if total > 0 else "0%"
        lines.append(f"| {_status_icon(ERROR)} ERROR | {status_counts[ERROR]} | {err_pct} |")
    lines.append("")

    # Detailed findings by severity
    groups = group_by_severity(results)

    for sev in SEVERITY_ORDER:
        items = groups.get(sev, [])
        if not items:
            continue

        icon = _severity_icon(sev)
        lines.append(f"## {icon} {sev.upper()} 发现")
        lines.append("")

        for r in items:
            lines.append(f"### {r['id']}: {r['name']}")
            lines.append(f"- **严重度**: {sev.upper()}")
            lines.append(f"- **状态**: {r.get('status', '')}")
            if r.get("threat_ids"):
                lines.append(f"- **攻击面**: {', '.join(r['threat_ids'])}")
            if r.get("threat_refs"):
                lines.append(f"- **威胁编号**: {', '.join(r['threat_refs'])}")
            if r.get("handbook_ref"):
                lines.append(f"- **文档引用**: {r['handbook_ref']}")
            if r.get("confidence"):
                lines.append(f"- **置信度**: {r['confidence']}")
            if r.get("detail"):
                lines.append(f"- **详情**: {r['detail']}")
            if r.get("evidence"):
                lines.append(f"- **证据**: `{r['evidence'][:300]}`")
            if show_fix and r.get("fix_cmd"):
                lines.append(f"- **修复命令**: `{r['fix_cmd']}`")
            lines.append("")

    # Fix commands summary
    if show_fix:
        fix_results = [r for r in results if r.get("fix_cmd") and r.get("status") in (FAIL, WARN)]
        if fix_results:
            lines.append("## 修复命令汇总")
            lines.append("")
            lines.append("```bash")
            lines.append("#!/bin/bash")
            lines.append(f"# OpenClaw 安全加固脚本 — 自动生成于 {meta.get('audit_time', '')}")
            lines.append("# 请审查后执行")
            lines.append("")
            for r in fix_results:
                lines.append(f"# {r['id']}: {r['name']}")
                lines.append(r["fix_cmd"])
                lines.append("")
            lines.append("```")
            lines.append("")

    # Security advice appendix (items that cannot be auto-detected)
    lines.append("## 无法自动检测的安全建议（用户教育）")
    lines.append("")
    lines.append("以下场景无法通过 CLI 确定性检查，需要用户手动关注：")
    lines.append("")
    lines.append("| 场景 | 风险 | 文档引用 | 建议 |")
    lines.append("|------|------|---------|------|")
    lines.append("| QR 码钓鱼 | 攻击者伪造配对页面 | §3.6 | 只扫描自己生成的 QR 码 |")
    lines.append("| 提示注入运行时检测 | 语义攻击无法被传统工具检测 | §5.4 | 仔细审读每个 exec approval |")
    lines.append("| 业务文档隐藏注入 | 白色文字/注释/OCR | §3.12 | Agent 对文档\"只读不执行\" |")
    lines.append("| 云模型数据留存 | 对话可能被提供商保留 | §6.3 | 敏感内容使用本地模型 |")
    lines.append("| Agent 高速失败模式 | 几秒内批量错误操作 | §5.4 | exec.mode = \"ask\" + 监督 |")
    lines.append("| 社工攻击 | 通过 Agent 共享进行社工 | §3.8 | 不分享 Agent/令牌/配对码 |")
    lines.append("| 消息元数据泄露 | 通信模式暴露工作习惯 | §3.9 | 定期清理日志 + 本地模型 |")
    lines.append("| IPv4 八进制 SSRF 绕过 | 0177.0.0.1 绕过内网检测 | §9.6 | 保持 OpenClaw 版本最新 |")
    lines.append("")

    # §9.3 Checklist
    if checklist:
        lines.append("## 附录: §9.3 定期检查清单对照表")
        lines.append("")
        lines.append(_generate_checklist(results))

    return "\n".join(lines)


def _generate_checklist(results):
    """Generate §9.3 periodic checklist cross-referenced to audit IDs."""
    # Map check IDs to results for quick lookup
    result_map = {r["id"]: r for r in results}

    checklist_items = [
        ("1", "网关令牌定期轮换", "GW-013"),
        ("2", "所有通道 allowFrom 白名单", "CH-001"),
        ("3", "allowFrom 使用数字 ID", "CH-002"),
        ("4", "dmPolicy 为 pairing", "CH-003"),
        ("5", "exec.mode 为 ask", "AB-001"),
        ("6", "网关绑定 loopback", "GW-005"),
        ("7", "Docker Socket 未挂载", "SB-001"),
        ("8", "会话日志清理", "SM-003"),
        ("9", "凭证文件权限 600/700", "FP-001"),
        ("10", "Skill 审查（新安装）", "SK-001"),
        ("11", "npm audit 无 CVE", "SK-011"),
        ("12", "端口仅监听 loopback", "NE-001"),
        ("13", ".env 无明文密钥", "CL-004"),
        ("14", "遥测已禁用", "GW-010"),
        ("15", "debug 模式关闭", "GW-009"),
        ("16", "OAuth 令牌轮换", "CL-005"),
        ("17", "配置文件不可变标记", "FP-007"),
        ("18", "不在云同步目录", "FP-008"),
        ("19", "不在 git 仓库中", "FP-009"),
        ("20", "出站 URL 白名单", "AB-007"),
        ("21", "MEMORY.md 无注入", "SM-001"),
        ("22", "Windows Node.js 版本", "WIN-001"),
    ]

    lines = []
    lines.append("| # | 检查项 | 对应审计 ID | 本次结果 |")
    lines.append("|---|--------|-----------|---------|")

    for num, desc, check_id in checklist_items:
        r = result_map.get(check_id)
        if r:
            status = r.get("status", "?")
            icon = _status_icon(status)
            lines.append(f"| {num} | {desc} | {check_id} | {icon} {status} |")
        else:
            lines.append(f"| {num} | {desc} | {check_id} | ❓ N/A |")

    return "\n".join(lines)


# ============================================================
# JSON Report
# ============================================================

def generate_json_report(results, meta):
    """Generate JSON report for CI/CD integration."""
    status_counts = count_by_status(results)
    sev_counts = count_by_severity(results)

    report = {
        "meta": {
            "tool_version": TOOL_VERSION,
            "audit_time": meta.get("audit_time", ""),
            "target_dir": meta.get("target_dir", ""),
            "os": meta.get("os", ""),
            "os_version": meta.get("os_version", ""),
            "openclaw_version": meta.get("openclaw_version", "unknown"),
        },
        "summary": {
            "critical": sev_counts[CRITICAL],
            "high": sev_counts[HIGH],
            "medium": sev_counts[MEDIUM],
            "info": sev_counts[INFO],
            "pass": status_counts[PASS],
            "fail": status_counts[FAIL],
            "warn": status_counts[WARN],
            "skip": status_counts[SKIP],
            "error": status_counts[ERROR],
            "total": len(results),
        },
        "results": results,
    }
    return json.dumps(report, indent=2, ensure_ascii=False)


# ============================================================
# Fix Script
# ============================================================

def generate_fix_script(results, meta):
    """Generate bash fix script from FAIL/WARN results that have fix_cmd."""
    fix_results = [r for r in results
                   if r.get("fix_cmd") and r.get("status") in (FAIL, WARN)]

    if not fix_results:
        return None

    lines = []
    lines.append("#!/bin/bash")
    lines.append(f"# OpenClaw Security Hardening Script")
    lines.append(f"# Auto-generated: {meta.get('audit_time', '')}")
    lines.append(f"# Audit Tool: v{TOOL_VERSION}")
    lines.append("#")
    lines.append("# REVIEW BEFORE EXECUTING!")
    lines.append("# Some commands may require sudo or manual adjustment.")
    lines.append("")
    lines.append("set -e")
    lines.append("")

    # Group by severity
    for sev in SEVERITY_ORDER:
        sev_items = [r for r in fix_results if r.get("severity") == sev]
        if not sev_items:
            continue

        lines.append(f"# === {sev.upper()} ===")
        for r in sev_items:
            lines.append(f"# {r['id']}: {r['name']}")
            lines.append(f"# Status: {r.get('status')} | Ref: {r.get('handbook_ref', '')}")
            cmd = r["fix_cmd"]
            # Only add executable commands (skip advisory ones)
            if cmd.startswith(("chmod", "chflags", "chattr", "export", "find ", "rm ",
                               "docker", "git", "npm", "sudo")):
                lines.append(cmd)
            else:
                lines.append(f"echo \"[MANUAL] {r['id']}: {cmd}\"")
            lines.append("")

    return "\n".join(lines)


# ============================================================
# Write Reports
# ============================================================

def write_reports(results, meta, output_dir, fmt="both", show_fix=False,
                  write_json=False, checklist=False, min_severity=None):
    """Write all report files and return paths."""
    os.makedirs(output_dir, exist_ok=True)

    timestamp = meta.get("audit_time", datetime.now().strftime("%Y-%m-%d_%H%M%S"))
    date_str = timestamp.replace(" ", "_").replace(":", "")[:19]

    paths = {}

    # Terminal output (always printed)
    terminal = generate_terminal_report(results, meta, show_fix=show_fix,
                                        min_severity=min_severity)
    print(terminal)

    # Markdown report
    if fmt in ("md", "both"):
        md_content = generate_markdown_report(results, meta, show_fix=show_fix, checklist=checklist)
        md_path = os.path.join(output_dir, f"audit_{date_str}.md")
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md_content)
        paths["markdown"] = md_path

    # JSON report
    if write_json:
        json_content = generate_json_report(results, meta)
        json_path = os.path.join(output_dir, f"audit_{date_str}.json")
        with open(json_path, "w", encoding="utf-8") as f:
            f.write(json_content)
        paths["json"] = json_path

    # Fix script
    if show_fix:
        fix_content = generate_fix_script(results, meta)
        if fix_content:
            fix_path = os.path.join(output_dir, "fix_commands.sh")
            with open(fix_path, "w", encoding="utf-8") as f:
                f.write(fix_content)
            os.chmod(fix_path, 0o700)
            paths["fix_script"] = fix_path

    return paths
