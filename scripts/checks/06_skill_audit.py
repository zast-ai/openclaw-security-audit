#!/usr/bin/env python3
"""Module 06: Skill Supply Chain Audit (SK-001 ~ SK-012)

Attack Surface: AS-5 (Skills & supply chain)
Threats: T-ACCESS-004/005, T-EXEC-005, T-PERSIST-001, T-EXFIL-003, T-EVADE-004
Handbook: §4.1-§4.7, §9.1, §9.5
"""

import json
import math
import os
import re
import time
from collections import Counter

from ..utils import (
    CRITICAL, HIGH, MEDIUM, INFO,
    PASS, FAIL, WARN, SKIP, ERROR,
    make_result, run_cmd, grep_files, grep_files_with_context,
    read_file_safe, get_file_mtime_days_ago, parse_grep_hit,
)

MODULE_NAME = "06_skill_audit"

# Default whitelist — these skills are excluded from supply chain scanning
# but their hits are still reported as "self-references" for transparency.
_DEFAULT_WHITELIST = ["openclaw-security-audit"]

# Directories and extensions to always skip during scanning
_SKIP_DIRS = {"__pycache__", ".git", ".cache", "node_modules"}
_SKIP_EXTENSIONS = {".pyc", ".pyo", ".class", ".o", ".so", ".dylib"}

# Unicode homoglyph ranges (Cyrillic characters that resemble Latin)
_HOMOGLYPH_RANGES = [
    (0x0400, 0x04FF),  # Cyrillic
    (0x0500, 0x052F),  # Cyrillic Supplement
    (0x2DE0, 0x2DFF),  # Cyrillic Extended-A
    (0xA640, 0xA69F),  # Cyrillic Extended-B
    (0x200B, 0x200F),  # Zero-width characters
    (0x202A, 0x202E),  # Bidi override characters
    (0x2066, 0x2069),  # Bidi isolate characters
    (0xFEFF, 0xFEFF),  # BOM / zero-width no-break space
]

# Specific Cyrillic letters commonly used as Latin homoglyphs
_HOMOGLYPH_CHARS = set("\u0410\u0412\u0421\u0415\u041d\u0406\u041a\u041c\u041e\u0420\u0422\u0425\u0430\u0435\u043e\u0440\u0441\u0443\u0445\u0456")

# Keywords in skill descriptions that indicate legitimate network usage
_LEGITIMATE_NETWORK_KEYWORDS = [
    "browser", "cdp", "chrome devtools", "web", "api", "http client",
    "audit", "security", "scanner", "scraping", "crawl", "fetch",
    "webhook", "notification", "monitor", "health check", "ping",
    "download", "upload", "sync", "cloud", "remote",
]


def _shannon_entropy(data):
    """Calculate Shannon entropy of a byte string or text string."""
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in counter.values()
    )


def _is_homoglyph(char):
    """Check if a character is a known Unicode homoglyph."""
    if char in _HOMOGLYPH_CHARS:
        return True
    cp = ord(char)
    for start, end in _HOMOGLYPH_RANGES:
        if start <= cp <= end:
            return True
    return False


def _find_homoglyphs_in_file(filepath):
    """Return list of (line_number, char, codepoint) for homoglyphs found."""
    content = read_file_safe(filepath)
    if not content:
        return []
    findings = []
    for line_no, line in enumerate(content.splitlines(), 1):
        # Skip lines that are homoglyph detector definitions themselves
        if '_HOMOGLYPH' in line or 'homoglyph' in line.lower():
            continue
        for char in line:
            if _is_homoglyph(char):
                findings.append((line_no, char, f"U+{ord(char):04X}"))
    return findings


def _get_skills_dir(openclaw_dir):
    """Return the skills directory path."""
    return os.path.join(openclaw_dir, "skills")


def _walk_skill_files(skills_dir, extensions=None):
    """Yield (filepath, relative_path) for all files in skills_dir.

    Automatically skips __pycache__, .git, compiled files, etc.
    If extensions is provided, only yield files matching those extensions.
    """
    if not os.path.isdir(skills_dir):
        return
    for root, dirs, files in os.walk(skills_dir):
        # Prune directories we never want to scan
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for fname in files:
            # Skip compiled/binary artifacts
            _, ext = os.path.splitext(fname)
            if ext in _SKIP_EXTENSIONS:
                continue
            if extensions:
                if not any(fname.endswith(e) for e in extensions):
                    continue
            fpath = os.path.join(root, fname)
            rel = os.path.relpath(fpath, skills_dir)
            yield fpath, rel


def _get_exclude_args(whitelist):
    """Return grep --exclude-dir arguments for whitelisted skills and build artifacts."""
    args = [f"--exclude-dir={d}" for d in _SKIP_DIRS]
    for skill_name in whitelist:
        args.append(f"--exclude-dir={skill_name}")
    return args


def _grep_with_whitelist(pattern, skills_dir, whitelist, extra_args=None):
    """Run grep excluding whitelisted skills, and separately collect whitelisted hits.

    Returns (real_hits, self_ref_hits) where both are lists of strings.
    """
    # 1. Real scan: exclude whitelisted skills
    #    Always use -E (extended regex) for patterns with \b, \s, etc.
    exclude_args = _get_exclude_args(whitelist)
    all_extra = ["-E"] + (extra_args or []) + exclude_args
    real_hits = grep_files(pattern, skills_dir, recursive=True, extra_args=all_extra)

    # 2. Self-reference scan: only scan whitelisted skill directories
    self_ref_hits = []
    base_extra = ["-E"] + (extra_args or []) + [f"--exclude-dir={d}" for d in _SKIP_DIRS]
    for skill_name in whitelist:
        skill_path = os.path.join(skills_dir, skill_name)
        if os.path.isdir(skill_path):
            hits = grep_files(pattern, skill_path, recursive=True, extra_args=base_extra)
            self_ref_hits.extend(hits)

    return real_hits, self_ref_hits


def _is_noise_line(line):
    """Check if a matched line is noise (comment, pattern definition, markdown table, etc.)."""
    stripped = line.strip()
    # Comments
    if stripped.startswith('#') or stripped.startswith('//') or stripped.startswith('*'):
        return True
    # Symbol-only definitions that should not be treated like dangerous execution.
    if re.match(r'^\s*def\s+eval\s*\(', line):
        return True
    if re.match(r'^\s*(async\s+)?function\s+eval\s*\(', line):
        return True
    if re.match(r'^\s*class\s+\w+', line) and 'eval' in line:
        return True
    # Pattern definition contexts — these indicate the line is defining detection
    # rules rather than executing suspicious code
    pattern_indicators = [
        'patterns = [', 'patterns=[', '_PATTERN', '_patterns',
        'grep_files', 'pattern_str', 'injection_patterns',
        'patterns.append', 're.search(r', 're.compile(',
        'regex', 'PATTERN_',
        # Database execute() is not a dangerous exec — it's SQL execution
        '.execute(', 'cursor.execute', 'conn.execute',
        'session.execute', 'db.execute',
    ]
    for indicator in pattern_indicators:
        if indicator in line:
            return True
    return False


def _is_markdown_file(filepath):
    """Check if a file is a markdown document."""
    return filepath.lower().endswith(('.md', '.markdown', '.rst', '.txt'))


def _get_skill_root_from_path(filepath, skills_dir):
    """Extract the skill root directory from a file path under skills_dir."""
    try:
        rel = os.path.relpath(filepath, skills_dir)
        parts = rel.split(os.sep)
        if parts:
            return os.path.join(skills_dir, parts[0])
    except ValueError:
        pass
    return None


def _skill_has_legitimate_network_purpose(skill_dir):
    """Check if a skill's description indicates legitimate network usage."""
    for desc_file in ["SKILL.md", "README.md", "package.json"]:
        content = read_file_safe(os.path.join(skill_dir, desc_file), max_size=64 * 1024)
        if content:
            content_lower = content.lower()
            for keyword in _LEGITIMATE_NETWORK_KEYWORDS:
                if keyword in content_lower:
                    return True
    return False


def _format_self_ref_section(self_ref_hits):
    """Format whitelisted self-reference hits into an evidence appendix."""
    if not self_ref_hits:
        return ""
    lines = ["\n--- Whitelisted self-references (excluded from scoring) ---"]
    for hit in self_ref_hits[:10]:
        lines.append(hit)
    if len(self_ref_hits) > 10:
        lines.append(f"... and {len(self_ref_hits) - 10} more")
    return "\n".join(lines)


def run_checks(openclaw_dir, **kwargs):
    """Run all 12 skill supply chain checks. Returns list of result dicts."""
    skills_dir = _get_skills_dir(openclaw_dir)
    whitelist = kwargs.get("whitelist", _DEFAULT_WHITELIST)

    if not os.path.isdir(skills_dir):
        return [make_result(
            "SK-000", "Skills directory existence",
            INFO, SKIP,
            f"Skills directory does not exist: {skills_dir}",
            threat_ids=["AS-5"], handbook_ref="§4.1",
        )]

    results = []
    results.append(_sk001(skills_dir))
    results.append(_sk002(skills_dir, whitelist))
    results.append(_sk003(skills_dir, whitelist))
    results.append(_sk004(skills_dir, whitelist))
    results.append(_sk005(skills_dir, whitelist))
    results.append(_sk006(skills_dir, whitelist))
    results.append(_sk007(skills_dir, whitelist))
    results.append(_sk008(skills_dir, whitelist))
    results.append(_sk009(openclaw_dir))
    results.append(_sk010())
    results.append(_sk011(skills_dir))
    results.append(_sk012(skills_dir))
    return results


# SK-001: Installed skill list with timestamps
def _sk001(skills_dir):
    check_id = "SK-001"
    name = "Installed skill inventory with timestamps"

    try:
        entries = []
        for item in os.listdir(skills_dir):
            item_path = os.path.join(skills_dir, item)
            if os.path.isdir(item_path):
                try:
                    mtime = os.path.getmtime(item_path)
                    days_ago = int((time.time() - mtime) / 86400)
                    entries.append((item, mtime, days_ago))
                except OSError:
                    entries.append((item, 0, -1))

        if not entries:
            return make_result(check_id, name, INFO, PASS,
                               "No skills installed",
                               threat_ids=["AS-5"], handbook_ref="§4.1")

        # Sort by modification time, newest first
        entries.sort(key=lambda x: x[1], reverse=True)

        recent = [e for e in entries if 0 <= e[2] <= 7]
        skill_list = []
        for skill_name, _mtime, days in entries:
            marker = " [NEW - installed within 7 days]" if 0 <= days <= 7 else ""
            skill_list.append(f"  {skill_name} ({days}d ago){marker}")

        detail = f"[Advisory] Found {len(entries)} installed skill(s)"
        if recent:
            detail += f" — {len(recent)} installed in the last 7 days; review if unexpected"

        evidence = "\n".join(skill_list[:30])
        if len(skill_list) > 30:
            evidence += f"\n  ... and {len(skill_list) - 30} more"

        status = WARN if recent else PASS
        return make_result(check_id, name, INFO, status, detail,
                           threat_ids=["AS-5"], handbook_ref="§4.1",
                           evidence=evidence)
    except Exception as e:
        return make_result(check_id, name, INFO, ERROR,
                           f"Failed to enumerate skills: {e}",
                           threat_ids=["AS-5"], handbook_ref="§4.1")


# SK-002: Dangerous function patterns (exec, spawn, child_process, eval, new Function)
def _sk002(skills_dir, whitelist):
    check_id = "SK-002"
    name = "Dangerous function patterns (exec/eval/spawn)"

    patterns = [
        (r'\bexec\s*\(', "exec("),
        (r'\bspawn\s*\(', "spawn("),
        (r'child_process', "child_process"),
        (r'\beval\s*\(', "eval("),
        (r'new\s+Function\s*\(', "new Function("),
    ]

    source_includes = ["--include=*.js", "--include=*.ts",
                       "--include=*.py", "--include=*.sh",
                       "--include=*.mjs", "--include=*.cjs"]

    all_real_hits = []
    all_self_refs = []
    noise_count = 0
    for pattern_str, label in patterns:
        real, self_ref = _grep_with_whitelist(
            pattern_str, skills_dir, whitelist,
            extra_args=["-n"] + source_includes)
        for hit in real:
            parsed = parse_grep_hit(hit)
            if parsed is None:
                continue
            fpath, _, content = parsed
            # Exclude markdown/doc files
            if _is_markdown_file(fpath):
                noise_count += 1
                continue
            # Exclude comments and pattern definitions
            if _is_noise_line(content):
                noise_count += 1
                continue
            all_real_hits.append(f"[{label}] {hit}")
        for hit in self_ref:
            all_self_refs.append(f"[{label}] {hit}")

    # Deduplicate at file level
    unique_files = set()
    deduped = []
    for hit in all_real_hits:
        inner = hit.split("] ", 1)[-1] if "] " in hit else hit
        fname = inner.split(":", 1)[0] if ":" in inner else inner
        if fname not in unique_files:
            unique_files.add(fname)
            deduped.append(hit)

    if not deduped:
        evidence = ""
        if noise_count > 0:
            evidence = f"({noise_count} noise hit(s) excluded: comments, pattern defs, docs)"
        if all_self_refs:
            evidence += _format_self_ref_section(all_self_refs)
        return make_result(check_id, name, HIGH, PASS,
                           "No dangerous function patterns found in skills",
                           threat_ids=["AS-5"],
                           threat_refs=["T-EXEC-005"],
                           handbook_ref="§4.2",
                           evidence=evidence)

    evidence = "\n".join(deduped[:20])
    if len(deduped) > 20:
        evidence += f"\n... and {len(deduped) - 20} more matches"
    if noise_count > 0:
        evidence += f"\n({noise_count} noise hit(s) excluded: comments, pattern defs, docs)"
    evidence += _format_self_ref_section(all_self_refs)

    return make_result(check_id, name, HIGH, WARN,
                       f"Found {len(deduped)} file(s) with dangerous function patterns — "
                       f"manual review recommended",
                       threat_ids=["AS-5"],
                       threat_refs=["T-EXEC-005"],
                       handbook_ref="§4.2",
                       evidence=evidence)


# SK-003: Credential theft patterns (read env + send over network)
def _sk003(skills_dir, whitelist):
    check_id = "SK-003"
    name = "Credential theft patterns (env read + network send)"

    patterns = [
        (r'process\.env.*fetch', "process.env + fetch"),
        (r'readFile.*fetch', "readFile + fetch"),
        (r'process\.env.*http', "process.env + http"),
        (r'os\.environ.*request', "os.environ + request"),
        (r'os\.environ.*urlopen', "os.environ + urlopen"),
        (r'os\.environ.*http', "os.environ + http"),
        (r'getenv.*curl', "getenv + curl"),
        (r'getenv.*fetch', "getenv + fetch"),
    ]

    all_real_hits = []
    all_self_refs = []
    for pattern_str, label in patterns:
        real, self_ref = _grep_with_whitelist(pattern_str, skills_dir, whitelist)
        # Filter noise from real hits (comments, pattern definitions, markdown)
        for hit in real:
            parsed = parse_grep_hit(hit)
            if parsed is not None:
                fpath, _, content = parsed
                if _is_markdown_file(fpath) or _is_noise_line(content):
                    continue
            all_real_hits.append(f"[{label}] {hit}")
        for hit in self_ref:
            all_self_refs.append(f"[{label}] {hit}")

    if not all_real_hits:
        evidence = ""
        if all_self_refs:
            evidence = _format_self_ref_section(all_self_refs)
        return make_result(check_id, name, CRITICAL, PASS,
                           "No credential theft patterns detected in skills",
                           threat_ids=["AS-5"],
                           threat_refs=["T-EXFIL-003"],
                           handbook_ref="§4.2",
                           evidence=evidence)

    evidence = "\n".join(all_real_hits[:15])
    if len(all_real_hits) > 15:
        evidence += f"\n... and {len(all_real_hits) - 15} more matches"
    evidence += _format_self_ref_section(all_self_refs)

    return make_result(check_id, name, CRITICAL, FAIL,
                       f"CRITICAL: Found {len(all_real_hits)} credential theft pattern(s) — "
                       f"env/credential read combined with network send",
                       threat_ids=["AS-5"],
                       threat_refs=["T-EXFIL-003"],
                       handbook_ref="§4.2",
                       evidence=evidence)


# SK-004: Mining signatures
def _sk004(skills_dir, whitelist):
    check_id = "SK-004"
    name = "Cryptocurrency mining signatures"

    patterns = [
        (r'xmrig', "xmrig"),
        (r'coinhive', "coinhive"),
        (r'cryptonight', "cryptonight"),
        (r'stratum\+tcp', "stratum+tcp"),
        (r'minergate', "minergate"),
        (r'hashrate', "hashrate"),
        (r'coin-hive', "coin-hive"),
    ]

    all_real_hits = []
    all_self_refs = []
    for pattern_str, label in patterns:
        real, self_ref = _grep_with_whitelist(
            pattern_str, skills_dir, whitelist,
            extra_args=["-i", "-l"])
        # Filter markdown/doc hits from real results
        for hit in real:
            if _is_markdown_file(hit):
                continue
            all_real_hits.append(f"[{label}] {hit}")
        for hit in self_ref:
            all_self_refs.append(f"[{label}] {hit}")

    if not all_real_hits:
        evidence = ""
        if all_self_refs:
            evidence = _format_self_ref_section(all_self_refs)
        return make_result(check_id, name, CRITICAL, PASS,
                           "No mining signatures detected in skills",
                           threat_ids=["AS-5"],
                           threat_refs=["T-EXEC-005"],
                           handbook_ref="§4.2",
                           evidence=evidence)

    evidence = "\n".join(all_real_hits[:15])
    evidence += _format_self_ref_section(all_self_refs)

    return make_result(check_id, name, CRITICAL, FAIL,
                       f"CRITICAL: Found {len(all_real_hits)} mining signature(s) in skills",
                       threat_ids=["AS-5"],
                       threat_refs=["T-EXEC-005"],
                       handbook_ref="§4.2",
                       evidence=evidence)


# SK-005: Covert communication channels (WebSocket, ws://, wss://)
def _sk005(skills_dir, whitelist):
    check_id = "SK-005"
    name = "Covert communication channels (WebSocket/C2)"

    patterns = [
        (r'WebSocket', "WebSocket"),
        (r'wss://', "wss://"),
        (r'ws://', "ws://"),
        (r'\.connect\s*\(.*wss?:', "WebSocket connect"),
    ]

    source_includes = ["--include=*.js", "--include=*.ts",
                       "--include=*.py", "--include=*.sh",
                       "--include=*.mjs", "--include=*.cjs"]

    # Phase 1: grep with line content for semantic analysis
    all_raw_hits = []
    all_self_refs = []
    for pattern_str, label in patterns:
        real, self_ref = _grep_with_whitelist(
            pattern_str, skills_dir, whitelist,
            extra_args=["-n"] + source_includes)
        for hit in real:
            all_raw_hits.append((label, hit))
        for hit in self_ref:
            all_self_refs.append(f"[{label}] {hit}")

    # Phase 2: semantic classification
    suspicious_hits = []
    legitimate_hits = []
    noise_count = 0

    _skill_legit_cache = {}

    for label, hit in all_raw_hits:
        parsed = parse_grep_hit(hit)
        if parsed is None:
            suspicious_hits.append(f"[{label}] {hit}")
            continue
        fpath, _line_no, content = parsed

        # Rule 1: markdown/doc files → noise
        if _is_markdown_file(fpath):
            noise_count += 1
            continue

        # Rule 2: comments or pattern definitions → noise
        if _is_noise_line(content):
            noise_count += 1
            continue

        # Rule 3: localhost WebSocket → legitimate
        if 'localhost' in content or '127.0.0.1' in content:
            legitimate_hits.append(f"[{label}] {hit}")
            continue

        # Rule 4: skill declares legitimate network purpose → legitimate
        skill_root = _get_skill_root_from_path(fpath, skills_dir)
        if skill_root:
            if skill_root not in _skill_legit_cache:
                _skill_legit_cache[skill_root] = _skill_has_legitimate_network_purpose(skill_root)
            if _skill_legit_cache[skill_root]:
                skill_name = os.path.basename(skill_root)
                legitimate_hits.append(
                    f"[{label}] {hit} (skill '{skill_name}' declares network usage)")
                continue

        # Default: suspicious
        suspicious_hits.append(f"[{label}] {hit}")

    # Deduplicate at file level
    def _dedup_file_level(hits):
        seen = set()
        result = []
        for hit in hits:
            inner = hit.split("] ", 1)[-1] if "] " in hit else hit
            fname = inner.split(":", 1)[0] if ":" in inner else inner
            if fname not in seen:
                seen.add(fname)
                result.append(hit)
        return result

    deduped_suspicious = _dedup_file_level(suspicious_hits)
    deduped_legitimate = _dedup_file_level(legitimate_hits)

    # Build evidence
    evidence_parts = []

    if deduped_suspicious:
        evidence_parts.append(f"=== Suspicious WebSocket/C2 ({len(deduped_suspicious)} file(s)) ===")
        evidence_parts.extend(deduped_suspicious[:15])
        if len(deduped_suspicious) > 15:
            evidence_parts.append(f"... and {len(deduped_suspicious) - 15} more")

    if deduped_legitimate:
        evidence_parts.append(f"\n=== Legitimate WebSocket usage ({len(deduped_legitimate)} file(s), INFO only) ===")
        evidence_parts.extend(deduped_legitimate[:10])
        if len(deduped_legitimate) > 10:
            evidence_parts.append(f"... and {len(deduped_legitimate) - 10} more")

    if noise_count > 0:
        evidence_parts.append(f"\n({noise_count} noise hit(s) excluded: comments, pattern defs, docs)")

    if all_self_refs:
        evidence_parts.append(_format_self_ref_section(all_self_refs))

    evidence = "\n".join(evidence_parts)

    if not deduped_suspicious:
        detail = "No suspicious WebSocket/C2 channel patterns found in skills"
        if deduped_legitimate:
            detail += f" ({len(deduped_legitimate)} legitimate usage(s) detected, see evidence)"
        return make_result(check_id, name, INFO, PASS, detail,
                           threat_ids=["AS-5"],
                           threat_refs=["T-ACCESS-004"],
                           handbook_ref="§4.2",
                           evidence=evidence)

    return make_result(check_id, name, MEDIUM, WARN,
                       f"Found {len(deduped_suspicious)} file(s) with suspicious WebSocket/C2 patterns — "
                       f"manual review recommended",
                       threat_ids=["AS-5"],
                       threat_refs=["T-ACCESS-004"],
                       handbook_ref="§4.2",
                       evidence=evidence)


# SK-006: Code obfuscation detection (Shannon entropy + Unicode homoglyphs)
def _sk006(skills_dir, whitelist):
    check_id = "SK-006"
    name = "Code obfuscation detection (entropy + homoglyphs)"

    code_extensions = (
        ".js", ".ts", ".py", ".sh", ".mjs", ".cjs",
        ".jsx", ".tsx", ".rb", ".pl", ".php",
    )

    high_entropy_files = []
    homoglyph_files = []
    self_ref_files = []

    for fpath, rel in _walk_skill_files(skills_dir, extensions=code_extensions):
        # Check if file belongs to a whitelisted skill
        is_whitelisted = any(
            rel.startswith(wl + os.sep) or rel.startswith(wl + "/")
            for wl in whitelist
        )

        content = read_file_safe(fpath, max_size=2 * 1024 * 1024)
        if not content:
            continue

        # Shannon entropy check
        entropy = _shannon_entropy(content)
        if entropy > 5.5:
            if is_whitelisted:
                self_ref_files.append(f"[HIGH ENTROPY {round(entropy, 2)}] {rel} (whitelisted)")
            else:
                high_entropy_files.append((rel, round(entropy, 2)))

        # Homoglyph detection (already excludes definition lines via _find_homoglyphs_in_file)
        glyphs = _find_homoglyphs_in_file(fpath)
        if glyphs:
            sample = glyphs[:5]
            glyph_desc = ", ".join(
                f"L{ln}:{cp}" for ln, _ch, cp in sample
            )
            if len(glyphs) > 5:
                glyph_desc += f" (+{len(glyphs) - 5} more)"
            if is_whitelisted:
                self_ref_files.append(f"[HOMOGLYPH] {rel}: {glyph_desc} (whitelisted)")
            else:
                homoglyph_files.append((rel, glyph_desc))

    issues = []
    evidence_parts = []

    if high_entropy_files:
        issues.append(f"{len(high_entropy_files)} file(s) with high entropy (>5.5)")
        for fname, ent in high_entropy_files[:10]:
            evidence_parts.append(f"[HIGH ENTROPY {ent}] {fname}")
        if len(high_entropy_files) > 10:
            evidence_parts.append(
                f"... and {len(high_entropy_files) - 10} more high-entropy files"
            )

    if homoglyph_files:
        issues.append(f"{len(homoglyph_files)} file(s) with Unicode homoglyphs")
        for fname, desc in homoglyph_files[:10]:
            evidence_parts.append(f"[HOMOGLYPH] {fname}: {desc}")
        if len(homoglyph_files) > 10:
            evidence_parts.append(
                f"... and {len(homoglyph_files) - 10} more files with homoglyphs"
            )

    if self_ref_files:
        evidence_parts.append("")
        evidence_parts.append("--- Whitelisted self-references (excluded from scoring) ---")
        evidence_parts.extend(self_ref_files[:10])
        if len(self_ref_files) > 10:
            evidence_parts.append(f"... and {len(self_ref_files) - 10} more")

    if not issues:
        return make_result(check_id, name, HIGH, PASS,
                           "No obfuscation indicators found in skill code",
                           threat_ids=["AS-5"],
                           threat_refs=["T-EVADE-004"],
                           handbook_ref="§4.2",
                           evidence="\n".join(evidence_parts) if evidence_parts else "")

    # Homoglyphs are a strong malicious signal → FAIL
    # High entropy alone (minified JS, base64 assets) → WARN
    if homoglyph_files:
        return make_result(check_id, name, HIGH, FAIL,
                           f"Obfuscation indicators (includes homoglyphs): {'; '.join(issues)}",
                           threat_ids=["AS-5"],
                           threat_refs=["T-EVADE-004"],
                           handbook_ref="§4.2",
                           evidence="\n".join(evidence_parts))

    return make_result(check_id, name, HIGH, WARN,
                       f"High entropy files detected: {'; '.join(issues)} — "
                       f"could be minified code or obfuscation; manual review recommended",
                       threat_ids=["AS-5"],
                       threat_refs=["T-EVADE-004"],
                       handbook_ref="§4.2",
                       evidence="\n".join(evidence_parts))


# SK-007: Auto-start events
def _sk007(skills_dir, whitelist):
    check_id = "SK-007"
    name = "Suspicious auto-start event registration"

    patterns = [
        (r'onStartupFinished', "onStartupFinished"),
        (r'activationEvents', "activationEvents"),
        (r'onStartup', "onStartup"),
        (r'autostart', "autostart"),
        (r'"activate"', "activate event"),
    ]

    all_real_hits = []
    all_self_refs = []
    for pattern_str, label in patterns:
        real, self_ref = _grep_with_whitelist(
            pattern_str, skills_dir, whitelist,
            extra_args=["--include=*.json", "--include=*.js",
                        "--include=*.ts", "--include=*.yaml",
                        "--include=*.yml", "--include=*.toml"])
        for hit in real:
            all_real_hits.append(f"[{label}] {hit}")
        for hit in self_ref:
            all_self_refs.append(f"[{label}] {hit}")

    if not all_real_hits:
        evidence = ""
        if all_self_refs:
            evidence = _format_self_ref_section(all_self_refs)
        return make_result(check_id, name, MEDIUM, PASS,
                           "No auto-start event registrations found",
                           threat_ids=["AS-5"],
                           threat_refs=["T-PERSIST-001"],
                           handbook_ref="§4.3",
                           evidence=evidence)

    evidence = "\n".join(all_real_hits[:15])
    if len(all_real_hits) > 15:
        evidence += f"\n... and {len(all_real_hits) - 15} more matches"
    evidence += _format_self_ref_section(all_self_refs)

    return make_result(check_id, name, MEDIUM, WARN,
                       f"Found {len(all_real_hits)} auto-start event pattern(s) — "
                       f"verify these are expected for legitimate skills (e.g. VS Code activationEvents)",
                       threat_ids=["AS-5"],
                       threat_refs=["T-PERSIST-001"],
                       handbook_ref="§4.3",
                       evidence=evidence)


# SK-008: Network requests (staged payload download) — with semantic analysis
def _sk008(skills_dir, whitelist):
    check_id = "SK-008"
    name = "Network request patterns (staged payload risk)"

    patterns = [
        (r'fetch\s*\(', "fetch("),
        (r'\baxios\b', "axios"),
        (r'http\.get\s*\(', "http.get("),
        (r'https\.get\s*\(', "https.get("),
        (r'request\s*\(', "request("),
        (r'\burllib\b', "urllib"),
        (r'requests\.get', "requests.get"),
        (r'requests\.post', "requests.post"),
        (r'httpx', "httpx"),
        (r'aiohttp', "aiohttp"),
        (r'wget', "wget"),
        (r'\bcurl\b', "curl"),
    ]

    source_includes = ["--include=*.js", "--include=*.ts",
                       "--include=*.py", "--include=*.sh",
                       "--include=*.mjs", "--include=*.cjs"]

    # Phase 1: grep for candidate files (excluding whitelist)
    all_real_hits = []
    all_self_refs = []
    for pattern_str, label in patterns:
        real, self_ref = _grep_with_whitelist(
            pattern_str, skills_dir, whitelist,
            extra_args=["-n"] + source_includes)
        for hit in real:
            all_real_hits.append((label, hit))
        for hit in self_ref:
            all_self_refs.append(f"[{label}] {hit}")

    # Phase 2: semantic classification of real hits
    suspicious_hits = []   # HIGH FAIL
    legitimate_hits = []   # INFO (reported but not scored)
    noise_count = 0

    # Cache skill legitimacy lookups
    _skill_legit_cache = {}

    for label, hit in all_real_hits:
        parsed = parse_grep_hit(hit)
        if parsed is None:
            suspicious_hits.append(f"[{label}] {hit}")
            continue
        fpath, _line_no, content = parsed

        # Rule 1: markdown/doc files → noise
        if _is_markdown_file(fpath):
            noise_count += 1
            continue

        # Rule 2: comments or pattern definitions → noise
        if _is_noise_line(content):
            noise_count += 1
            continue

        # Rule 3: localhost targets → legitimate
        if 'localhost' in content or '127.0.0.1' in content:
            legitimate_hits.append(f"[{label}] {hit}")
            continue

        # Rule 4: skill has legitimate network purpose → legitimate
        skill_root = _get_skill_root_from_path(fpath, skills_dir)
        if skill_root:
            if skill_root not in _skill_legit_cache:
                _skill_legit_cache[skill_root] = _skill_has_legitimate_network_purpose(skill_root)
            if _skill_legit_cache[skill_root]:
                skill_name = os.path.basename(skill_root)
                legitimate_hits.append(f"[{label}] {hit} (skill '{skill_name}' declares network usage)")
                continue

        # Default: suspicious
        suspicious_hits.append(f"[{label}] {hit}")

    # Deduplicate suspicious at file level
    unique_files = set()
    deduped_suspicious = []
    for hit in suspicious_hits:
        # Extract file path from "[label] path:line:content"
        inner = hit.split("] ", 1)[-1] if "] " in hit else hit
        fname = inner.split(":", 1)[0] if ":" in inner else inner
        if fname not in unique_files:
            unique_files.add(fname)
            deduped_suspicious.append(hit)

    # Build evidence
    evidence_parts = []

    if deduped_suspicious:
        evidence_parts.append(f"=== Suspicious network requests ({len(deduped_suspicious)} file(s)) ===")
        evidence_parts.extend(deduped_suspicious[:15])
        if len(deduped_suspicious) > 15:
            evidence_parts.append(f"... and {len(deduped_suspicious) - 15} more")

    if legitimate_hits:
        # Deduplicate legitimate at file level
        legit_unique = set()
        deduped_legit = []
        for hit in legitimate_hits:
            inner = hit.split("] ", 1)[-1] if "] " in hit else hit
            fname = inner.split(":", 1)[0] if ":" in inner else inner
            if fname not in legit_unique:
                legit_unique.add(fname)
                deduped_legit.append(hit)
        evidence_parts.append(f"\n=== Legitimate network usage ({len(deduped_legit)} file(s), INFO only) ===")
        evidence_parts.extend(deduped_legit[:10])
        if len(deduped_legit) > 10:
            evidence_parts.append(f"... and {len(deduped_legit) - 10} more")

    if noise_count > 0:
        evidence_parts.append(f"\n({noise_count} noise hit(s) excluded: comments, pattern defs, docs)")

    if all_self_refs:
        evidence_parts.append(_format_self_ref_section(all_self_refs))

    evidence = "\n".join(evidence_parts)

    # Determine status based on suspicious hits only
    if not deduped_suspicious:
        detail = "No suspicious network request patterns found in skills"
        if legitimate_hits:
            detail += f" ({len(legitimate_hits)} legitimate usage(s) detected, see evidence)"
        return make_result(check_id, name, INFO, PASS, detail,
                           threat_ids=["AS-5"],
                           threat_refs=["T-EVADE-004"],
                           handbook_ref="§4.4",
                           evidence=evidence)

    return make_result(check_id, name, HIGH, FAIL,
                       f"Found {len(deduped_suspicious)} file(s) with suspicious network requests — "
                       f"possible staged payload download",
                       threat_ids=["AS-5"],
                       threat_refs=["T-EVADE-004"],
                       handbook_ref="§4.4",
                       evidence=evidence)


# SK-009: Skill version lock / auto-update settings
def _sk009(openclaw_dir):
    check_id = "SK-009"
    name = "Skill version pinning and auto-update settings"

    config_candidates = [
        os.path.join(openclaw_dir, "openclaw.json"),
        os.path.join(openclaw_dir, "config.json"),
        os.path.join(openclaw_dir, "settings.json"),
    ]

    config_content = None
    config_path = None
    for candidate in config_candidates:
        content = read_file_safe(candidate)
        if content:
            config_content = content
            config_path = candidate
            break

    if config_content is None:
        return make_result(check_id, name, MEDIUM, SKIP,
                           "No configuration file found to check auto-update settings",
                           threat_ids=["AS-5"],
                           threat_refs=["T-ACCESS-005"],
                           handbook_ref="§4.5")

    auto_update_patterns = [
        "auto-update", "autoUpdate", "auto_update",
        "autoupdate", "update.mode", "skill.autoUpdate",
    ]

    version_lock_patterns = [
        "version-lock", "versionLock", "version_lock",
        "pinned", "lockfile", "skill-lock",
    ]

    has_auto_update = any(p in config_content for p in auto_update_patterns)
    has_version_lock = any(p in config_content for p in version_lock_patterns)

    lock_files = [
        os.path.join(openclaw_dir, "skill-lock.json"),
        os.path.join(openclaw_dir, "skills.lock"),
        os.path.join(openclaw_dir, ".skill-versions"),
    ]
    has_lock_file = any(os.path.exists(lf) for lf in lock_files)

    issues = []
    if not has_version_lock and not has_lock_file:
        issues.append("No skill version pinning detected")
    if has_auto_update:
        issues.append("Auto-update may be enabled — skills could change without review")

    if not issues:
        return make_result(check_id, name, MEDIUM, PASS,
                           "Skill version management appears configured",
                           threat_ids=["AS-5"],
                           threat_refs=["T-ACCESS-005"],
                           handbook_ref="§4.5",
                           evidence=f"config: {config_path}")

    return make_result(check_id, name, MEDIUM, WARN,
                       "; ".join(issues) + " — recommend locking skill versions",
                       threat_ids=["AS-5"],
                       threat_refs=["T-ACCESS-005"],
                       handbook_ref="§4.5",
                       fix_cmd="Pin skill versions in configuration and disable auto-update",
                       evidence=f"config: {config_path}")


# SK-010: curl|bash in shell history (unsafe installation)
def _sk010():
    check_id = "SK-010"
    name = "Unsafe curl|bash installation in shell history"

    home = os.path.expanduser("~")
    history_files = [
        os.path.join(home, ".zsh_history"),
        os.path.join(home, ".bash_history"),
    ]

    all_hits = []
    for hist_file in history_files:
        if not os.path.exists(hist_file):
            continue
        for pattern in [
            r'curl.*\|.*bash',
            r'curl.*\|.*sh',
            r'wget.*\|.*bash',
            r'wget.*\|.*sh',
            r'curl.*\|.*zsh',
            r'wget.*\|.*zsh',
        ]:
            hits = grep_files(pattern, hist_file, recursive=False,
                              extra_args=["-E", "-i"])
            for hit in hits:
                all_hits.append(hit)

    if not all_hits:
        return make_result(check_id, name, HIGH, PASS,
                           "No unsafe curl|bash patterns found in shell history",
                           threat_ids=["AS-5"],
                           threat_refs=["T-EXEC-005"],
                           handbook_ref="§9.5")

    unique_hits = list(dict.fromkeys(all_hits))

    evidence = "\n".join(unique_hits[:10])
    if len(unique_hits) > 10:
        evidence += f"\n... and {len(unique_hits) - 10} more"

    return make_result(check_id, name, HIGH, WARN,
                       f"Found {len(unique_hits)} unsafe curl|bash installation(s) in "
                       f"shell history — skills may have been installed without verification",
                       threat_ids=["AS-5"],
                       threat_refs=["T-EXEC-005"],
                       handbook_ref="§9.5",
                       fix_cmd="Always download scripts first, review, then execute. "
                               "Never pipe curl directly to bash.",
                       evidence=evidence)


# SK-011: npm audit for known CVEs
def _sk011(skills_dir):
    check_id = "SK-011"
    name = "npm audit for known CVEs in skill dependencies"

    package_dirs = []
    for root, _dirs, files in os.walk(skills_dir):
        if "package.json" in files and "node_modules" not in root:
            package_dirs.append(root)

    if not package_dirs:
        return make_result(check_id, name, HIGH, SKIP,
                           "No package.json found in skills directory — "
                           "no npm dependencies to audit",
                           threat_ids=["AS-5"],
                           threat_refs=["T-ACCESS-005"],
                           handbook_ref="§9.1")

    all_vulns = []
    audit_errors = []
    watched_cves = {"CVE-2026-25253", "CVE-2026-25593"}
    watched_found = []

    for pkg_dir in package_dirs:
        rc, stdout, stderr = run_cmd(
            ["npm", "audit", "--json"],
            timeout=60,
            shell=False,
            cwd=pkg_dir,
        )

        if stdout:
            try:
                audit_data = json.loads(stdout)
                vulnerabilities = audit_data.get("vulnerabilities", {})
                if isinstance(vulnerabilities, dict):
                    for pkg_name, vuln_info in vulnerabilities.items():
                        severity = vuln_info.get("severity", "unknown")
                        via = vuln_info.get("via", [])
                        for v in via:
                            if isinstance(v, dict):
                                cve = v.get("cve", "")
                                title = v.get("title", "")
                                if cve in watched_cves:
                                    watched_found.append(
                                        f"{cve}: {title} (in {pkg_name})"
                                    )
                                all_vulns.append(
                                    f"[{severity.upper()}] {pkg_name}: "
                                    f"{title or 'unknown'} ({cve or 'no CVE'})"
                                )

                advisories = audit_data.get("advisories", {})
                if isinstance(advisories, dict):
                    for _adv_id, adv_info in advisories.items():
                        severity = adv_info.get("severity", "unknown")
                        title = adv_info.get("title", "")
                        module_name = adv_info.get("module_name", "unknown")
                        cves = adv_info.get("cves", [])
                        for cve in cves:
                            if cve in watched_cves:
                                watched_found.append(
                                    f"{cve}: {title} (in {module_name})"
                                )
                        all_vulns.append(
                            f"[{severity.upper()}] {module_name}: "
                            f"{title} ({', '.join(cves) if cves else 'no CVE'})"
                        )

            except (json.JSONDecodeError, KeyError, TypeError):
                audit_errors.append(f"Failed to parse npm audit output for {pkg_dir}")
        elif rc == -1:
            audit_errors.append(f"npm audit failed for {pkg_dir}: {stderr}")

    if audit_errors and not all_vulns:
        return make_result(check_id, name, HIGH, ERROR,
                           f"npm audit encountered errors: {'; '.join(audit_errors)}",
                           threat_ids=["AS-5"],
                           threat_refs=["T-ACCESS-005"],
                           handbook_ref="§9.1")

    if not all_vulns:
        detail = "npm audit found no known vulnerabilities"
        if audit_errors:
            detail += f" (with {len(audit_errors)} audit error(s))"
        return make_result(check_id, name, HIGH, PASS,
                           detail,
                           threat_ids=["AS-5"],
                           threat_refs=["T-ACCESS-005"],
                           handbook_ref="§9.1")

    evidence_parts = []
    if watched_found:
        evidence_parts.append("=== WATCHED CVEs ===")
        evidence_parts.extend(watched_found)
        evidence_parts.append("")

    evidence_parts.append(f"=== All vulnerabilities ({len(all_vulns)}) ===")
    evidence_parts.extend(all_vulns[:20])
    if len(all_vulns) > 20:
        evidence_parts.append(f"... and {len(all_vulns) - 20} more")

    severity = CRITICAL if watched_found else HIGH
    detail = f"Found {len(all_vulns)} known vulnerability(ies) in skill npm dependencies"
    if watched_found:
        detail += f" — INCLUDING {len(watched_found)} watched CVE(s): " + \
                  ", ".join(c.split(":")[0] for c in watched_found)

    return make_result(check_id, name, severity, FAIL,
                       detail,
                       threat_ids=["AS-5"],
                       threat_refs=["T-ACCESS-005"],
                       handbook_ref="§9.1",
                       fix_cmd="cd <skill_dir> && npm audit fix",
                       evidence="\n".join(evidence_parts))


# SK-012: Unused installed skills (access time >90 days)
def _sk012(skills_dir):
    check_id = "SK-012"
    name = "Unused installed skills (>90 days inactive)"

    try:
        stale_skills = []
        active_skills = []

        for item in os.listdir(skills_dir):
            item_path = os.path.join(skills_dir, item)
            if not os.path.isdir(item_path):
                continue

            most_recent_access = 0
            try:
                for root, _dirs, files in os.walk(item_path):
                    for fname in files:
                        fpath = os.path.join(root, fname)
                        try:
                            atime = os.path.getatime(fpath)
                            if atime > most_recent_access:
                                most_recent_access = atime
                        except OSError:
                            pass
            except OSError:
                pass

            if most_recent_access == 0:
                stale_skills.append((item, "unknown"))
            else:
                days_since_access = int((time.time() - most_recent_access) / 86400)
                if days_since_access > 90:
                    stale_skills.append((item, f"{days_since_access}d"))
                else:
                    active_skills.append((item, f"{days_since_access}d"))

        if not stale_skills:
            return make_result(check_id, name, INFO, PASS,
                               f"All {len(active_skills)} installed skill(s) have been "
                               f"accessed within the last 90 days",
                               threat_ids=["AS-5"],
                               handbook_ref="§9.3")

        evidence_lines = [f"  {s[0]} (last access: {s[1]} ago)" for s in stale_skills[:20]]
        if len(stale_skills) > 20:
            evidence_lines.append(f"  ... and {len(stale_skills) - 20} more")

        return make_result(check_id, name, INFO, WARN,
                           f"{len(stale_skills)} skill(s) not accessed in >90 days — "
                           f"consider uninstalling to reduce attack surface",
                           threat_ids=["AS-5"],
                           handbook_ref="§9.3",
                           fix_cmd="Review and uninstall unused skills",
                           evidence="\n".join(evidence_lines))

    except Exception as e:
        return make_result(check_id, name, INFO, ERROR,
                           f"Failed to check skill access times: {e}",
                           threat_ids=["AS-5"],
                           handbook_ref="§9.3")
