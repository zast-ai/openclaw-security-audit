#!/usr/bin/env python3
"""Module 03: Network Exposure Checks (NE-001 ~ NE-009)

Attack Surface: AS-1 (Gateway ports), AS-8 (Sandbox ports), AS-9 (SSRF/network/proxy)
Handbook: §2.2-§2.3, §7.4, §8.2, §8.4, §9.6
"""

import os
import re

from ..utils import (
    CRITICAL, HIGH, MEDIUM, INFO,
    PASS, FAIL, WARN, SKIP, ERROR,
    make_result, run_cmd, is_macos, is_linux, is_windows, read_file_safe, get_env_var,
)

MODULE_NAME = "03_network_exposure"


def run_checks(openclaw_dir, **kwargs):
    """Run all 9 network exposure checks. Returns list of result dicts."""
    remote_hosts = kwargs.get("remote_hosts", [])
    compose_file = kwargs.get("compose_file")

    # Take a full TCP listening port snapshot once, shared by all port checks
    port_snapshot, proc_map = _get_listening_ports()

    results = []
    results.append(_ne001(port_snapshot))
    results.append(_ne002(port_snapshot))
    results.append(_ne003(port_snapshot))
    results.append(_ne004(port_snapshot))
    results.append(_ne005(remote_hosts))
    results.append(_ne006(openclaw_dir, compose_file))
    results.append(_ne007())
    results.append(_ne008(port_snapshot, proc_map))
    results.append(_ne009())
    return results


def _get_listening_ports():
    """Get a snapshot of all TCP listening ports on the system.

    Runs a single OS-specific command to capture all listening TCP sockets.
    Returns (ports, proc_map) where:
      - ports: {port_number: bind_address} ('127.0.0.1', '0.0.0.0', '::1', etc.)
      - proc_map: {port_number: process_name} (best-effort; may be empty)
    If a port is not in ports dict, it is not listening.
    """
    ports = {}
    proc_map = {}

    if is_macos():
        rc, out, _ = run_cmd(
            ["lsof", "-iTCP", "-sTCP:LISTEN", "-n", "-P"],
            timeout=15,
        )
        if rc != 0 or not out:
            return ports, proc_map
        # Parse lsof output. Example:
        # COMMAND   PID USER   FD TYPE DEVICE SIZE/OFF NODE NAME
        # node    12345 user   22u IPv4 ...          TCP 127.0.0.1:18789 (LISTEN)
        # node    12345 user   23u IPv6 ...          TCP *:18789 (LISTEN)
        for line in out.splitlines()[1:]:  # skip header
            parts = line.split()
            if not parts:
                continue
            proc_name = parts[0]  # COMMAND column
            for part in reversed(parts):
                if "(LISTEN)" in part:
                    continue
                if ":" in part:
                    # part is like "127.0.0.1:18789" or "*:9222" or "[::1]:3000"
                    addr_port = part.rsplit(":", 1)
                    if len(addr_port) == 2:
                        addr, port_str = addr_port
                        try:
                            port_num = int(port_str)
                        except ValueError:
                            break
                        if addr in ("*", "0.0.0.0", "[::]", ""):
                            addr = "0.0.0.0"
                        # If the same port has both loopback and wildcard,
                        # wildcard takes precedence (worst case)
                        existing = ports.get(port_num)
                        if existing == "0.0.0.0":
                            pass  # already worst case
                        else:
                            ports[port_num] = addr
                        # Record process name (first seen wins for the port)
                        if port_num not in proc_map:
                            proc_map[port_num] = proc_name
                    break

    elif is_linux():
        rc, out, _ = run_cmd(["ss", "-tulnp"], timeout=15)
        if rc != 0 or not out:
            # Fallback to netstat
            rc, out, _ = run_cmd(["netstat", "-tulnp"], timeout=15)
            if rc != 0 or not out:
                return ports, proc_map
            # Parse netstat output
            # Example: tcp  0  0 0.0.0.0:22  0.0.0.0:*  LISTEN  1234/sshd
            for line in out.splitlines():
                if "LISTEN" not in line:
                    continue
                fields = line.split()
                if len(fields) < 4:
                    continue
                local = fields[3]  # Local Address like 0.0.0.0:22 or :::22
                addr, _, port_str = local.rpartition(":")
                try:
                    port_num = int(port_str)
                except ValueError:
                    continue
                if addr in ("*", "0.0.0.0", "::", "[::]", ""):
                    addr = "0.0.0.0"
                existing = ports.get(port_num)
                if existing != "0.0.0.0":
                    ports[port_num] = addr
                # Extract process name from "PID/name" column (last field)
                if len(fields) >= 7 and "/" in fields[6]:
                    pname = fields[6].split("/", 1)[-1]
                    if port_num not in proc_map:
                        proc_map[port_num] = pname
            return ports, proc_map

        # Parse ss output. Example:
        # State  Recv-Q Send-Q  Local Address:Port  Peer Address:Port  Process
        # LISTEN 0      128     127.0.0.1:18789     0.0.0.0:*          users:(("node",pid=1234,fd=22))
        for line in out.splitlines():
            if not line.strip().startswith("LISTEN"):
                continue
            fields = line.split()
            if len(fields) < 4:
                continue
            local = fields[3]  # Local Address:Port
            addr, _, port_str = local.rpartition(":")
            try:
                port_num = int(port_str)
            except ValueError:
                continue
            if addr in ("*", "0.0.0.0", "::", "[::]", ""):
                addr = "0.0.0.0"
            existing = ports.get(port_num)
            if existing != "0.0.0.0":
                ports[port_num] = addr
            # Extract process name from users:(("name",...)) in the last field
            proc_match = re.search(r'\("([^"]+)"', line)
            if proc_match and port_num not in proc_map:
                proc_map[port_num] = proc_match.group(1)

    elif is_windows():
        # Try PowerShell first, then netstat
        rc, out, _ = run_cmd(
            ["powershell", "-Command",
             "Get-NetTCPConnection -State Listen | "
             "Select-Object LocalAddress,LocalPort,OwningProcess | "
             "Format-Table -HideTableHeaders"],
            timeout=15,
        )
        if rc == 0 and out:
            for line in out.strip().splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    addr = parts[0]
                    try:
                        port_num = int(parts[1])
                    except ValueError:
                        continue
                    if addr in ("0.0.0.0", "::", "[::]"):
                        addr = "0.0.0.0"
                    existing = ports.get(port_num)
                    if existing != "0.0.0.0":
                        ports[port_num] = addr
                    # Try to resolve PID to process name
                    if len(parts) >= 3 and port_num not in proc_map:
                        try:
                            pid = parts[2]
                            prc, pout, _ = run_cmd(
                                ["powershell", "-Command",
                                 f"(Get-Process -Id {pid}).ProcessName"],
                                timeout=5,
                            )
                            if prc == 0 and pout.strip():
                                proc_map[port_num] = pout.strip()
                        except Exception:
                            pass
        else:
            # Fallback to netstat -anob (requires admin for -b, fall back to -ano)
            rc, out, _ = run_cmd(["netstat", "-ano"], timeout=15)
            if rc == 0 and out:
                for line in out.splitlines():
                    if "LISTENING" not in line:
                        continue
                    fields = line.split()
                    if len(fields) < 2:
                        continue
                    local = fields[1]
                    addr, _, port_str = local.rpartition(":")
                    try:
                        port_num = int(port_str)
                    except ValueError:
                        continue
                    if addr in ("0.0.0.0", "::", "[::]", ""):
                        addr = "0.0.0.0"
                    existing = ports.get(port_num)
                    if existing != "0.0.0.0":
                        ports[port_num] = addr

    return ports, proc_map


def _check_port_from_snapshot(port, snapshot):
    """Look up a port in the snapshot.

    Returns (is_listening: bool, bind_address: str or None).
    """
    if port in snapshot:
        return True, snapshot[port]
    return False, None


def _port_check_result(check_id, name, port, severity, threat_ids, handbook_ref,
                       port_snapshot=None):
    """Run a standard port binding check and return a result dict."""
    if port_snapshot is not None:
        is_listening, bind_addr = _check_port_from_snapshot(port, port_snapshot)
    else:
        is_listening, bind_addr = False, None

    if not is_listening:
        return make_result(
            check_id, name, severity, PASS,
            f"Port {port} is not listening",
            threat_ids=threat_ids, handbook_ref=handbook_ref,
            evidence=f"port={port}, not listening",
        )

    if bind_addr in ("127.0.0.1", "::1", "[::1]"):
        return make_result(
            check_id, name, severity, PASS,
            f"Port {port} is bound to loopback ({bind_addr})",
            threat_ids=threat_ids, handbook_ref=handbook_ref,
            evidence=f"port={port}, bind={bind_addr}",
        )

    # Bound to 0.0.0.0, *, or unexpected address
    fix = f"Reconfigure service to bind to 127.0.0.1:{port} instead of {bind_addr}:{port}"
    return make_result(
        check_id, name, severity, FAIL,
        f"Port {port} is bound to {bind_addr} — accessible from network",
        threat_ids=threat_ids, handbook_ref=handbook_ref,
        fix_cmd=fix,
        evidence=f"port={port}, bind={bind_addr}",
    )


# ---------- Individual Checks ----------


# NE-001: Gateway port 18789 listen address
def _ne001(port_snapshot):
    return _port_check_result(
        "NE-001", "Gateway port 18789 listen address",
        18789, CRITICAL,
        threat_ids=["AS-1"], handbook_ref="§2.2",
        port_snapshot=port_snapshot,
    )


# NE-002: CDP port 9222 listen address (Chrome DevTools Protocol)
def _ne002(port_snapshot):
    return _port_check_result(
        "NE-002", "CDP port 9222 listen address",
        9222, CRITICAL,
        threat_ids=["AS-8"], handbook_ref="§7.4",
        port_snapshot=port_snapshot,
    )


# NE-003: VNC port 5900 listen address
def _ne003(port_snapshot):
    return _port_check_result(
        "NE-003", "VNC port 5900 listen address",
        5900, HIGH,
        threat_ids=["AS-8"], handbook_ref="§7.4",
        port_snapshot=port_snapshot,
    )


# NE-004: Extra ports 18790 and 6080
def _ne004(port_snapshot):
    check_id = "NE-004"
    name = "Extra ports 18790/6080 listen address"

    issues = []
    evidence_parts = []

    for port in (18790, 6080):
        is_listening, bind_addr = _check_port_from_snapshot(port, port_snapshot)
        if not is_listening:
            evidence_parts.append(f"{port}=not_listening")
            continue
        if bind_addr in ("127.0.0.1", "::1", "[::1]"):
            evidence_parts.append(f"{port}=loopback")
            continue
        issues.append(f"Port {port} bound to {bind_addr}")
        evidence_parts.append(f"{port}=bind:{bind_addr}")

    evidence = ", ".join(evidence_parts)

    if issues:
        return make_result(
            check_id, name, MEDIUM, FAIL,
            f"Extra port(s) exposed to network: {'; '.join(issues)}",
            threat_ids=["AS-1", "AS-8"], handbook_ref="§2.2",
            fix_cmd="Reconfigure extra ports to bind to 127.0.0.1",
            evidence=evidence,
        )

    return make_result(
        check_id, name, MEDIUM, PASS,
        "Extra ports 18790/6080 are loopback-only or not listening",
        threat_ids=["AS-1", "AS-8"], handbook_ref="§2.2",
        evidence=evidence,
    )


# NE-005: External reachability test (only if --remote provided)
def _ne005(remote_hosts):
    check_id = "NE-005"
    name = "External reachability test"

    if not remote_hosts:
        return make_result(
            check_id, name, CRITICAL, SKIP,
            "No --remote hosts provided; skipping external reachability test",
            threat_ids=["AS-1"], handbook_ref="§2.3",
        )

    reachable = []
    unreachable = []

    for host_port in remote_hosts:
        # host_port format: "HOST:PORT"
        url = f"http://{host_port}/health"
        rc, out, err = run_cmd(
            ["curl", "-s", "--connect-timeout", "3", "-o", "/dev/null",
             "-w", "%{http_code}", url],
            timeout=10,
        )
        if rc == 0 and out and out != "000":
            reachable.append(f"{host_port} (HTTP {out})")
        else:
            unreachable.append(host_port)

    if reachable:
        return make_result(
            check_id, name, CRITICAL, FAIL,
            f"OpenClaw port(s) reachable externally: {', '.join(reachable)}",
            threat_ids=["AS-1"], handbook_ref="§2.3",
            fix_cmd="Bind services to 127.0.0.1 and block ports in firewall",
            evidence=f"reachable={reachable}, unreachable={unreachable}",
        )

    return make_result(
        check_id, name, CRITICAL, PASS,
        f"All {len(unreachable)} remote endpoint(s) are unreachable (expected)",
        threat_ids=["AS-1"], handbook_ref="§2.3",
        evidence=f"tested={unreachable}",
    )


# NE-006: docker-compose.yml bind check
# See also SB-009 for docker-compose.yml comprehensive security check
def _ne006(openclaw_dir, compose_file):
    check_id = "NE-006"
    name = "docker-compose.yml bind address check"

    # Resolve compose file path
    candidate_paths = []
    if compose_file:
        candidate_paths.append(compose_file)
    candidate_paths.extend([
        os.path.join(openclaw_dir, "docker-compose.yml"),
        os.path.join(openclaw_dir, "docker-compose.yaml"),
        os.path.expanduser("~/docker-compose.yml"),
        os.path.expanduser("~/docker-compose.yaml"),
        "./docker-compose.yml",
        "./docker-compose.yaml",
    ])

    content = None
    used_path = None
    for p in candidate_paths:
        c = read_file_safe(p)
        if c is not None:
            content = c
            used_path = p
            break

    if content is None:
        return make_result(
            check_id, name, CRITICAL, SKIP,
            "No docker-compose.yml found",
            threat_ids=["AS-1"], handbook_ref="§1.4",
            evidence=f"searched: {candidate_paths[:4]}",
        )

    # Check for 0.0.0.0 binds or "lan" references in port mappings
    issues = []

    # Match port bindings like "0.0.0.0:18789:18789" or "- 0.0.0.0:..."
    wildcard_binds = re.findall(r'["\']?\s*0\.0\.0\.0:\d+', content)
    if wildcard_binds:
        cleaned = [s.strip().strip('"').strip("'") for s in wildcard_binds[:5]]
        issues.append(f"0.0.0.0 bind found: {', '.join(cleaned)}")

    # Match lines with "lan" (case insensitive) in port/network context
    # e.g. network_mode: "lan", or binding to LAN IP
    lan_refs = re.findall(r'(?i)(?:network_mode|ports).*?lan', content)
    if lan_refs:
        issues.append(f"LAN reference found in compose config")

    # Also check for bare port mappings without explicit 127.0.0.1 (e.g. "18789:18789")
    # These default to 0.0.0.0 in Docker
    bare_ports = re.findall(r'["\']?\s*(\d{4,5}:\d{4,5})\s*["\']?', content)
    bare_without_ip = []
    for bp in bare_ports:
        # Check if this port mapping has an IP prefix (already caught above or safe)
        line_pattern = re.compile(rf'[\d.]+:{re.escape(bp)}')
        if not line_pattern.search(content):
            bare_without_ip.append(bp)
    if bare_without_ip:
        issues.append(f"Bare port binding (defaults to 0.0.0.0): {', '.join(bare_without_ip[:5])}")

    if issues:
        return make_result(
            check_id, name, CRITICAL, FAIL,
            f"docker-compose.yml has network exposure: {'; '.join(issues)}",
            threat_ids=["AS-1"], handbook_ref="§1.4",
            fix_cmd="Change all port bindings to '127.0.0.1:PORT:PORT' in docker-compose.yml",
            evidence=f"file={used_path}, issues={len(issues)}",
        )

    return make_result(
        check_id, name, CRITICAL, PASS,
        "docker-compose.yml port bindings are properly scoped",
        threat_ids=["AS-1"], handbook_ref="§1.4",
        evidence=f"file={used_path}",
    )


# NE-007: SSH tunnel / Tailscale check
def _ne007():
    check_id = "NE-007"
    name = "SSH tunnel / Tailscale exposure check"

    findings = []
    evidence_parts = []

    # Check for SSH tunnels forwarding port 18789
    rc, out, _ = run_cmd(["pgrep", "-a", "ssh"])
    if rc == 0 and out:
        for line in out.splitlines():
            if "18789" in line:
                findings.append(f"SSH tunnel on 18789: {line.strip()[:120]}")
                evidence_parts.append("ssh_tunnel_18789")

    # Check Tailscale status
    rc, out, _ = run_cmd(["tailscale", "status"], timeout=5)
    if rc == 0 and out:
        evidence_parts.append("tailscale_active")
        # Tailscale is running; not inherently bad but worth noting
        findings.append("Tailscale is active — ensure OpenClaw ports are not exposed via Tailscale ACLs")

    if not findings:
        return make_result(
            check_id, name, INFO, PASS,
            "No SSH tunnels on 18789 or Tailscale detected",
            threat_ids=["AS-1"], handbook_ref="§2.3",
            evidence="no_tunnels_found",
        )

    return make_result(
        check_id, name, INFO, WARN,
        f"Secure tunnel/VPN detected: {'; '.join(findings)}",
        threat_ids=["AS-1"], handbook_ref="§2.3",
        fix_cmd="Verify that tunnel/VPN access is intentional and secured with authentication",
        evidence=", ".join(evidence_parts),
    )


# NE-008: ACP port binding address
def _ne008(port_snapshot, proc_map=None):
    check_id = "NE-008"
    name = "ACP port binding address"

    if proc_map is None:
        proc_map = {}

    # ACP (Agent Communication Protocol) commonly uses ports in the 3000-3999 or 8000-8999 range.
    # We check a set of known ACP-related ports.
    acp_ports = [3000, 3001, 8080, 8443]
    openclaw_issues = []   # confirmed or unknown-process issues
    unrelated_ports = []   # confirmed non-openclaw processes (informational)
    evidence_parts = []

    for port in acp_ports:
        is_listening, bind_addr = _check_port_from_snapshot(port, port_snapshot)
        if not is_listening:
            continue

        proc_name = proc_map.get(port, "")
        proc_label = f" ({proc_name})" if proc_name else ""
        evidence_parts.append(f"{port}={bind_addr}{proc_label}")

        # If process name is known and clearly not openclaw-related, skip it
        if proc_name and not re.search(r'\bopenclaw\b|\bclaw\b', proc_name, re.IGNORECASE):
            unrelated_ports.append(f"port {port} used by '{proc_name}' (not OpenClaw)")
            continue

        if bind_addr not in ("127.0.0.1", "::1", "[::1]", None):
            openclaw_issues.append(f"ACP port {port} bound to {bind_addr}{proc_label}")

    if not evidence_parts:
        return make_result(
            check_id, name, HIGH, PASS,
            "No ACP-related ports detected listening",
            threat_ids=["AS-9"], handbook_ref="§9.6",
            evidence="acp_ports_not_listening",
        )

    # Add unrelated port info to evidence for transparency
    if unrelated_ports:
        evidence_parts.append(
            f"--- Non-OpenClaw (excluded): {'; '.join(unrelated_ports)}")

    if openclaw_issues:
        return make_result(
            check_id, name, HIGH, FAIL,
            f"ACP port(s) exposed to network: {'; '.join(openclaw_issues)}",
            threat_ids=["AS-9"], handbook_ref="§9.6",
            fix_cmd="Reconfigure ACP services to bind to 127.0.0.1",
            evidence=", ".join(evidence_parts),
        )

    return make_result(
        check_id, name, HIGH, PASS,
        "ACP ports are loopback-only or used by non-OpenClaw processes",
        threat_ids=["AS-9"], handbook_ref="§9.6",
        evidence=", ".join(evidence_parts),
    )


# NE-009: HTTP proxy environment variables
def _ne009():
    check_id = "NE-009"
    name = "HTTP proxy environment variables"

    proxy_vars = ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy",
                  "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy"]

    found = {}
    for var in proxy_vars:
        val = os.environ.get(var)
        if val:
            found[var] = val

    if not found:
        return make_result(
            check_id, name, MEDIUM, PASS,
            "No HTTP proxy environment variables set",
            threat_ids=["AS-9"], handbook_ref="§8.4",
            evidence="no_proxy_vars",
        )

    # Proxies are set -- warn that they may forward to subprocesses
    sanitized = {k: (v[:40] + "..." if len(v) > 40 else v) for k, v in found.items()}
    var_list = ", ".join(f"{k}={v}" for k, v in sanitized.items())

    return make_result(
        check_id, name, MEDIUM, WARN,
        f"Proxy environment variable(s) set: {var_list} — "
        f"these are inherited by all child processes including sandbox browsers",
        threat_ids=["AS-9"], handbook_ref="§8.4",
        fix_cmd="Unset proxy vars for OpenClaw process or add NO_PROXY=localhost,127.0.0.1",
        evidence=f"vars={list(found.keys())}",
    )
