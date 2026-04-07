#!/usr/bin/env python3
"""Module 07: Sandbox & Docker Checks (SB-001 ~ SB-011)

Attack Surface: AS-8 (Sandbox escape)
Threats: Docker Socket privilege escalation, sandbox escape, container network escape
Handbook: §7.1-§7.4, §8.1, §9.6
"""

import json
import os
import re

from ..utils import (
    CRITICAL, HIGH, MEDIUM, INFO,
    PASS, FAIL, WARN, SKIP, ERROR,
    make_result, run_cmd, read_file_safe, check_command_exists,
)

MODULE_NAME = "07_sandbox_docker"


def _get_container_inspect(docker_name):
    """Run docker inspect and return parsed JSON for the container.

    Returns None if container does not exist or command fails.
    """
    rc, out, err = run_cmd(["docker", "inspect", docker_name], timeout=15)
    if rc != 0:
        return None
    try:
        data = json.loads(out)
        return data[0] if data else None
    except (json.JSONDecodeError, IndexError, TypeError):
        return None


def _get_binds_and_mounts(inspect_data):
    """Extract all bind/mount source paths from inspect data."""
    sources = []
    # HostConfig.Binds: list of "host:container[:opts]"
    binds = (inspect_data.get("HostConfig") or {}).get("Binds") or []
    for b in binds:
        parts = b.split(":")
        if parts:
            sources.append(parts[0])
    # Mounts array
    mounts = inspect_data.get("Mounts") or []
    for m in mounts:
        src = m.get("Source", "")
        if src:
            sources.append(src)
    return sources


def run_checks(openclaw_dir, **kwargs):
    """Run all 11 sandbox & Docker checks. Returns list of result dicts."""
    docker_name = kwargs.get("docker_name", "openclaw-sandbox")
    compose_file = kwargs.get("compose_file", os.path.join(openclaw_dir, "docker-compose.yml"))

    results = []

    # Pre-flight: check if docker command exists
    if not check_command_exists("docker"):
        for cid, name in [
            ("SB-001", "Docker Socket mounted to sandbox"),
            ("SB-002", "Sandbox network mode"),
            ("SB-003", "Egress network restricted"),
            ("SB-004", "Dangerous Linux capabilities"),
            ("SB-005", "seccomp configuration"),
            ("SB-006", "Dangerous path mounts"),
            ("SB-007", "no-new-privileges flag"),
            ("SB-008", "Sandbox image compiler check"),
            ("SB-009", "docker-compose.yml comprehensive check"),
            ("SB-010", "cap_drop ALL check"),
            ("SB-011", "Docker image SLSA provenance"),
        ]:
            results.append(make_result(
                cid, name, INFO, SKIP,
                "Docker command not found on this system",
                threat_ids=["AS-8"], handbook_ref="§7.1"))
        return results

    # Try to get container inspect data
    inspect_data = _get_container_inspect(docker_name)

    results.append(_sb001(inspect_data, docker_name))
    results.append(_sb002(inspect_data, docker_name))
    results.append(_sb003(inspect_data, docker_name))
    results.append(_sb004(inspect_data, docker_name))
    results.append(_sb005(inspect_data, docker_name))
    results.append(_sb006(inspect_data, docker_name))
    results.append(_sb007(inspect_data, docker_name))
    results.append(_sb008(inspect_data, docker_name))
    results.append(_sb009(compose_file))
    results.append(_sb010(inspect_data, docker_name))
    results.append(_sb011(inspect_data, docker_name))

    return results


# ---------------------------------------------------------------------------
# SB-001: Docker Socket mounted to sandbox
# ---------------------------------------------------------------------------
def _sb001(inspect_data, docker_name):
    check_id = "SB-001"
    name = "Docker Socket mounted to sandbox"
    if inspect_data is None:
        return make_result(check_id, name, CRITICAL, SKIP,
                           f"Container '{docker_name}' not found or not inspectable",
                           threat_ids=["AS-8"], handbook_ref="§7.1")

    sources = _get_binds_and_mounts(inspect_data)
    socket_mounts = [s for s in sources if "docker.sock" in s]

    if socket_mounts:
        return make_result(check_id, name, CRITICAL, FAIL,
                           "Docker socket is mounted into the sandbox container "
                           "-- this grants host-root-equivalent access",
                           threat_ids=["AS-8"], handbook_ref="§7.1",
                           fix_cmd=f"Remove docker.sock volume mount from {docker_name} configuration",
                           evidence=f"mounts containing docker.sock: {socket_mounts}")
    return make_result(check_id, name, CRITICAL, PASS,
                       "Docker socket is not mounted into the sandbox container",
                       threat_ids=["AS-8"], handbook_ref="§7.1")


# ---------------------------------------------------------------------------
# SB-002: Sandbox network mode
# ---------------------------------------------------------------------------
def _sb002(inspect_data, docker_name):
    check_id = "SB-002"
    name = "Sandbox network mode"
    if inspect_data is None:
        return make_result(check_id, name, CRITICAL, SKIP,
                           f"Container '{docker_name}' not found or not inspectable",
                           threat_ids=["AS-8"], handbook_ref="§7.2")

    network_mode = (inspect_data.get("HostConfig") or {}).get("NetworkMode", "")

    if network_mode == "host":
        return make_result(check_id, name, CRITICAL, FAIL,
                           "Sandbox container uses 'host' network mode -- "
                           "container shares the host network namespace, defeating network isolation",
                           threat_ids=["AS-8"], handbook_ref="§7.2",
                           fix_cmd="Change network mode to 'bridge' or a custom isolated network",
                           evidence=f"NetworkMode={network_mode}")
    return make_result(check_id, name, CRITICAL, PASS,
                       f"Sandbox network mode is '{network_mode}' (not 'host')",
                       threat_ids=["AS-8"], handbook_ref="§7.2",
                       evidence=f"NetworkMode={network_mode}")


# ---------------------------------------------------------------------------
# SB-003: Egress network restricted
# ---------------------------------------------------------------------------
def _sb003(inspect_data, docker_name):
    check_id = "SB-003"
    name = "Egress network restricted"
    if inspect_data is None:
        return make_result(check_id, name, HIGH, SKIP,
                           f"Container '{docker_name}' not found or not inspectable",
                           threat_ids=["AS-8"], handbook_ref="§8.1")

    # Determine the network(s) the container is connected to
    networks = (inspect_data.get("NetworkSettings") or {}).get("Networks") or {}
    if not networks:
        return make_result(check_id, name, HIGH, WARN,
                           "No networks found for the container; cannot verify egress restriction",
                           threat_ids=["AS-8"], handbook_ref="§8.1")

    non_internal = []
    for net_name in networks:
        rc, out, _ = run_cmd(["docker", "network", "inspect", net_name])
        if rc != 0:
            non_internal.append(f"{net_name} (inspect failed)")
            continue
        try:
            net_data = json.loads(out)
            net_info = net_data[0] if net_data else {}
        except (json.JSONDecodeError, IndexError):
            non_internal.append(f"{net_name} (parse failed)")
            continue
        internal = net_info.get("Internal", False)
        if not internal:
            non_internal.append(net_name)

    if non_internal:
        return make_result(check_id, name, HIGH, WARN,
                           f"Sandbox is connected to non-internal network(s): {', '.join(non_internal)} -- "
                           "recommend using --internal network to restrict egress",
                           threat_ids=["AS-8"], handbook_ref="§8.1",
                           fix_cmd="docker network create --internal openclaw-sandbox-net",
                           evidence=f"non_internal_networks={non_internal}")
    return make_result(check_id, name, HIGH, PASS,
                       "All sandbox networks are marked as internal (egress restricted)",
                       threat_ids=["AS-8"], handbook_ref="§8.1")


# ---------------------------------------------------------------------------
# SB-004: Dangerous Linux capabilities
# ---------------------------------------------------------------------------
def _sb004(inspect_data, docker_name):
    check_id = "SB-004"
    name = "Dangerous Linux capabilities"
    if inspect_data is None:
        return make_result(check_id, name, CRITICAL, SKIP,
                           f"Container '{docker_name}' not found or not inspectable",
                           threat_ids=["AS-8"], handbook_ref="§7.2")

    cap_add = (inspect_data.get("HostConfig") or {}).get("CapAdd") or []
    dangerous = {"ALL", "SYS_ADMIN", "NET_ADMIN"}
    found = [c for c in cap_add if c.upper() in dangerous]

    if found:
        return make_result(check_id, name, CRITICAL, FAIL,
                           f"Dangerous capabilities added to sandbox: {', '.join(found)}",
                           threat_ids=["AS-8"], handbook_ref="§7.2",
                           fix_cmd="Remove dangerous capabilities and use cap_drop: ALL with minimal cap_add",
                           evidence=f"CapAdd={cap_add}")
    return make_result(check_id, name, CRITICAL, PASS,
                       "No dangerous capabilities (ALL/SYS_ADMIN/NET_ADMIN) added",
                       threat_ids=["AS-8"], handbook_ref="§7.2",
                       evidence=f"CapAdd={cap_add}")


# ---------------------------------------------------------------------------
# SB-005: seccomp configuration
# ---------------------------------------------------------------------------
def _sb005(inspect_data, docker_name):
    check_id = "SB-005"
    name = "seccomp configuration"
    if inspect_data is None:
        return make_result(check_id, name, HIGH, SKIP,
                           f"Container '{docker_name}' not found or not inspectable",
                           threat_ids=["AS-8"], handbook_ref="§7.2")

    security_opt = (inspect_data.get("HostConfig") or {}).get("SecurityOpt") or []
    unconfined = any("seccomp:unconfined" in s or "seccomp=unconfined" in s
                     for s in security_opt)

    if unconfined:
        return make_result(check_id, name, HIGH, FAIL,
                           "seccomp is set to 'unconfined' -- all syscalls are allowed",
                           threat_ids=["AS-8"], handbook_ref="§7.2",
                           fix_cmd="Remove 'seccomp:unconfined' from security options; "
                                   "use the default seccomp profile or a custom restrictive one",
                           evidence=f"SecurityOpt={security_opt}")
    return make_result(check_id, name, HIGH, PASS,
                       "seccomp is not disabled (unconfined)",
                       threat_ids=["AS-8"], handbook_ref="§7.2",
                       evidence=f"SecurityOpt={security_opt}")


# ---------------------------------------------------------------------------
# SB-006: Dangerous path mounts
# ---------------------------------------------------------------------------
def _sb006(inspect_data, docker_name):
    check_id = "SB-006"
    name = "Dangerous path mounts"
    if inspect_data is None:
        return make_result(check_id, name, CRITICAL, SKIP,
                           f"Container '{docker_name}' not found or not inspectable",
                           threat_ids=["AS-8"], handbook_ref="§7.2")

    dangerous_paths = {"/etc", "/proc", "/sys", "/dev", "/root"}
    sources = _get_binds_and_mounts(inspect_data)

    found_dangerous = []
    for src in sources:
        normalized = src.rstrip("/")
        for dp in dangerous_paths:
            if normalized == dp or normalized.startswith(dp + "/"):
                found_dangerous.append(src)
                break

    if found_dangerous:
        return make_result(check_id, name, CRITICAL, FAIL,
                           f"Dangerous host paths mounted into sandbox: {', '.join(found_dangerous)}",
                           threat_ids=["AS-8"], handbook_ref="§7.2",
                           fix_cmd="Remove mounts of /etc, /proc, /sys, /dev, /root from container configuration",
                           evidence=f"dangerous_mounts={found_dangerous}")
    return make_result(check_id, name, CRITICAL, PASS,
                       "No dangerous host paths (/etc, /proc, /sys, /dev, /root) are mounted",
                       threat_ids=["AS-8"], handbook_ref="§7.2",
                       evidence=f"all_mounts={sources}")


# ---------------------------------------------------------------------------
# SB-007: no-new-privileges
# ---------------------------------------------------------------------------
def _sb007(inspect_data, docker_name):
    check_id = "SB-007"
    name = "no-new-privileges flag"
    if inspect_data is None:
        return make_result(check_id, name, HIGH, SKIP,
                           f"Container '{docker_name}' not found or not inspectable",
                           threat_ids=["AS-8"], handbook_ref="§1.4")

    security_opt = (inspect_data.get("HostConfig") or {}).get("SecurityOpt") or []
    has_no_new_priv = any("no-new-privileges" in s for s in security_opt)

    if has_no_new_priv:
        return make_result(check_id, name, HIGH, PASS,
                           "no-new-privileges is enabled",
                           threat_ids=["AS-8"], handbook_ref="§1.4",
                           evidence=f"SecurityOpt={security_opt}")
    return make_result(check_id, name, HIGH, WARN,
                       "no-new-privileges is not set -- processes inside the container "
                       "could escalate privileges via setuid binaries",
                       threat_ids=["AS-8"], handbook_ref="§1.4",
                       fix_cmd="Add --security-opt=no-new-privileges:true to docker run, "
                               "or security_opt: [no-new-privileges:true] in compose",
                       evidence=f"SecurityOpt={security_opt}")


# ---------------------------------------------------------------------------
# SB-008: Sandbox image compiler check
# ---------------------------------------------------------------------------
def _sb008(inspect_data, docker_name):
    check_id = "SB-008"
    name = "Sandbox image compiler check"
    if inspect_data is None:
        return make_result(check_id, name, INFO, SKIP,
                           f"Container '{docker_name}' not found or not inspectable",
                           threat_ids=["AS-8"], handbook_ref="§7.3")

    # Check if container is running
    state = (inspect_data.get("State") or {}).get("Running", False)
    if not state:
        return make_result(check_id, name, INFO, SKIP,
                           f"Container '{docker_name}' is not running; cannot exec into it",
                           threat_ids=["AS-8"], handbook_ref="§7.3")

    compilers = ["go", "gcc", "rustc", "node", "python3"]
    found = []
    for compiler in compilers:
        rc, out, _ = run_cmd(["docker", "exec", docker_name, "which", compiler], timeout=10)
        if rc == 0 and out.strip():
            found.append(compiler)

    if found:
        return make_result(check_id, name, INFO, WARN,
                           f"Compilers/interpreters found in sandbox image: {', '.join(found)} -- "
                           "if compilers are present, ensure network egress is restricted to prevent "
                           "compilation and exfiltration of data",
                           threat_ids=["AS-8"], handbook_ref="§7.3",
                           evidence=f"found_compilers={found}")
    return make_result(check_id, name, INFO, PASS,
                       "No common compilers/interpreters (go, gcc, rustc, node, python3) found in sandbox",
                       threat_ids=["AS-8"], handbook_ref="§7.3")


# ---------------------------------------------------------------------------
# SB-009: docker-compose.yml comprehensive check
# See also NE-006 for docker-compose.yml bind address check
# ---------------------------------------------------------------------------
def _sb009(compose_file):
    check_id = "SB-009"
    name = "docker-compose.yml comprehensive check"

    content = read_file_safe(compose_file)
    if content is None:
        return make_result(check_id, name, HIGH, SKIP,
                           f"Compose file not found or unreadable: {compose_file}",
                           threat_ids=["AS-8"], handbook_ref="§1.4")

    issues = []

    # Check for docker.sock mount
    if "docker.sock" in content:
        issues.append("docker.sock is mounted in compose file (host-root-equivalent access)")

    # Check for cap_drop: ALL
    content_lower = content.lower()
    if "cap_drop" not in content_lower or "all" not in content_lower:
        issues.append("cap_drop: ALL not found -- recommend dropping all capabilities")

    # Check OPENCLAW_GATEWAY_BIND
    if "OPENCLAW_GATEWAY_BIND" in content:
        # Look for binding to 0.0.0.0 or non-loopback
        bind_match = re.search(r'OPENCLAW_GATEWAY_BIND\s*[=:]\s*["\']?([^"\'}\s]+)', content)
        if bind_match:
            bind_val = bind_match.group(1).strip()
            if bind_val not in ("127.0.0.1", "localhost", "::1"):
                issues.append(f"OPENCLAW_GATEWAY_BIND is '{bind_val}' -- should be 127.0.0.1 (loopback only)")
    else:
        issues.append("OPENCLAW_GATEWAY_BIND not set in compose -- should bind to 127.0.0.1")

    if issues:
        detail = f"Found {len(issues)} issue(s) in compose file: " + "; ".join(issues)
        return make_result(check_id, name, HIGH, FAIL, detail,
                           threat_ids=["AS-8"], handbook_ref="§1.4",
                           fix_cmd="Edit docker-compose.yml: remove docker.sock mount, "
                                   "add cap_drop: [ALL], set OPENCLAW_GATEWAY_BIND=127.0.0.1",
                           evidence=f"compose_file={compose_file}")
    return make_result(check_id, name, HIGH, PASS,
                       "docker-compose.yml passes all checks (no docker.sock, cap_drop ALL, loopback bind)",
                       threat_ids=["AS-8"], handbook_ref="§1.4",
                       evidence=f"compose_file={compose_file}")


# ---------------------------------------------------------------------------
# SB-010: cap_drop ALL check
# ---------------------------------------------------------------------------
def _sb010(inspect_data, docker_name):
    check_id = "SB-010"
    name = "cap_drop ALL check"
    if inspect_data is None:
        return make_result(check_id, name, MEDIUM, SKIP,
                           f"Container '{docker_name}' not found or not inspectable",
                           threat_ids=["AS-8"], handbook_ref="§1.4")

    cap_drop = (inspect_data.get("HostConfig") or {}).get("CapDrop") or []
    has_drop_all = "ALL" in [c.upper() for c in cap_drop]

    if has_drop_all:
        return make_result(check_id, name, MEDIUM, PASS,
                           "cap_drop includes ALL -- all capabilities are dropped by default",
                           threat_ids=["AS-8"], handbook_ref="§1.4",
                           evidence=f"CapDrop={cap_drop}")
    return make_result(check_id, name, MEDIUM, WARN,
                       "cap_drop does not include ALL -- recommend dropping all capabilities "
                       "and only adding back the minimum required",
                       threat_ids=["AS-8"], handbook_ref="§1.4",
                       fix_cmd="Add cap_drop: [ALL] to container configuration and "
                               "selectively add back only required capabilities with cap_add",
                       evidence=f"CapDrop={cap_drop}")


# ---------------------------------------------------------------------------
# SB-011: Docker image SLSA provenance
# ---------------------------------------------------------------------------
def _sb011(inspect_data, docker_name):
    check_id = "SB-011"
    name = "Docker image SLSA provenance"
    if inspect_data is None:
        return make_result(check_id, name, INFO, SKIP,
                           f"Container '{docker_name}' not found or not inspectable",
                           threat_ids=["AS-8"], handbook_ref="§9.6")

    # Check image config labels for SLSA / provenance attestation
    config = inspect_data.get("Config") or {}
    labels = config.get("Labels") or {}

    provenance_keys = [
        "org.opencontainers.image.source",
        "org.opencontainers.image.revision",
        "slsa.dev/provenance",
        "io.github.actions.provenance",
        "vcs-ref",
    ]

    found_labels = {k: v for k, v in labels.items()
                    if any(pk in k.lower() for pk in
                           ["provenance", "slsa", "vcs-ref", "source", "revision"])}

    if found_labels:
        return make_result(check_id, name, INFO, PASS,
                           f"Image has provenance-related labels: {list(found_labels.keys())}",
                           threat_ids=["AS-8"], handbook_ref="§9.6",
                           evidence=f"provenance_labels={found_labels}")
    return make_result(check_id, name, INFO, WARN,
                       "OpenClaw sandbox image lacks SLSA provenance labels -- "
                       "image supply chain cannot be verified. Consider building with "
                       "SLSA-compliant CI/CD pipelines that attach provenance attestations",
                       threat_ids=["AS-8"], handbook_ref="§9.6",
                       evidence=f"image_labels={labels}")
