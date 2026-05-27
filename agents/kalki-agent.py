#!/usr/bin/env python3
"""
KALKI Remote Agent — deploy on any Linux host to report:
  - Heartbeats & system info
  - File integrity (FIM) hashes
  - Installed packages (Vuln inventory)
  - Auth log parsing (HIDS)
  - Security config posture (SCA)

Usage:
  python3 kalki-agent.py --server http://waf-server:8000 [--agent-id AGT_ID]
"""

import argparse
import hashlib
import json
import os
import platform
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

SERVER: str = ""
AGENT_ID: str = ""
INTERVAL: int = 30
FIM_PATHS: list[str] = [
    "/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/ssh/sshd_config",
    "/etc/sudoers", "/etc/fstab", "/etc/hostname",
]
LOG_PATHS: list[str] = ["/var/log/auth.log", "/var/log/syslog"]


def log(msg: str):
    print(f"[kalki-agent {time.strftime('%H:%M:%S')}] {msg}")


def api_post(path: str, params: dict | None = None, body: str | None = None) -> dict:
    url = f"{SERVER}{path}"
    if params:
        qs = "&".join(f"{k}={urllib.parse.quote(str(v))}" for k, v in params.items())
        url += f"?{qs}"
    data = body.encode() if body else None
    try:
        req = urllib.request.Request(url, data=data, method="POST")
        if body:
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}: {e.read().decode()[:200]}"}
    except Exception as e:
        return {"error": str(e)}


def api_get(path: str, params: dict | None = None) -> dict:
    url = f"{SERVER}{path}"
    if params:
        qs = "&".join(f"{k}={urllib.parse.quote(str(v))}" for k, v in params.items())
        url += f"?{qs}"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}: {e.read().decode()[:200]}"}
    except Exception as e:
        return {"error": str(e)}


def register() -> str:
    hostname = socket.gethostname()
    os_info = f"{platform.system()} {platform.release()} {platform.version()}"
    ip = socket.gethostbyname(hostname) if hostname else "0.0.0.0"
    log(f"Registering as '{hostname}' ({os_info})...")
    result = api_post("/api/v1/agents/register", {
        "hostname": hostname,
        "os_info": os_info,
        "ip_address": ip,
        "agent_version": "1.0.0",
        "tags": json.dumps(["linux", "endpoint"]),
    })
    if "error" in result:
        log(f"Registration failed: {result['error']}")
        sys.exit(1)
    aid = result.get("agent_id", "")
    log(f"Registered as agent: {aid}")
    return aid


def heartbeat():
    cpu = _get_cpu()
    mem = _get_mem()
    extra = json.dumps({"cpu_percent": cpu, "memory_percent": mem, "load": os.getloadavg() if hasattr(os, "getloadavg") else []})
    api_post(f"/api/v1/agents/{AGENT_ID}/heartbeat", {"extra": extra})


def run_fim() -> dict:
    results = []
    for path in FIM_PATHS:
        if not os.path.exists(path):
            continue
        try:
            with open(path, "rb") as f:
                h = hashlib.sha256(f.read()).hexdigest()
            st = os.stat(path)
            results.append({
                "file": path,
                "hash": h,
                "size": st.st_size,
                "mode": oct(st.st_mode & 0o777),
                "mtime": st.st_mtime,
            })
        except PermissionError:
            results.append({"file": path, "error": "permission denied"})
        except Exception as e:
            results.append({"file": path, "error": str(e)})
    return {"summary": f"Checked {len(results)} files", "type": "fim", "files": results}


def run_vuln_inventory() -> dict:
    pkgs = []
    try:
        if os.path.exists("/usr/bin/dpkg"):
            out = subprocess.run(["dpkg-query", "-W"], capture_output=True, text=True, timeout=15)
            for line in out.stdout.strip().split("\n"):
                parts = line.split(maxsplit=1)
                if len(parts) == 2:
                    pkgs.append({"name": parts[0], "version": parts[1], "type": "dpkg"})
        elif os.path.exists("/usr/bin/rpm"):
            out = subprocess.run(["rpm", "-qa", "--queryformat", "%{NAME} %{VERSION}\n"], capture_output=True, text=True, timeout=15)
            for line in out.stdout.strip().split("\n"):
                parts = line.split(maxsplit=1)
                if len(parts) == 2:
                    pkgs.append({"name": parts[0], "version": parts[1], "type": "rpm"})
    except Exception as e:
        return {"summary": f"Package scan failed: {e}", "type": "vuln_inventory", "packages": []}
    return {"summary": f"Found {len(pkgs)} packages", "type": "vuln_inventory", "packages": pkgs}


def run_sca_cis() -> dict:
    checks = []
    try:
        checks.append({"id": "cis-1.1", "title": "selinux_enabled", "passed": subprocess.run(["getenforce"], capture_output=True, text=True, timeout=5).stdout.strip() != "Disabled"})
    except Exception:
        checks.append({"id": "cis-1.1", "title": "selinux_enabled", "passed": False})
    try:
        r = subprocess.run(["stat", "/etc/shadow"], capture_output=True, text=True, timeout=5)
        checks.append({"id": "cis-1.2", "title": "shadow_perms_640", "passed": "0640" in r.stdout or "0600" in r.stdout})
    except Exception:
        checks.append({"id": "cis-1.2", "title": "shadow_perms_640", "passed": False})
    try:
        r = subprocess.run(["systemctl", "is-enabled", "ufw"], capture_output=True, text=True, timeout=5)
        checks.append({"id": "cis-3.1", "title": "ufw_enabled", "passed": "enabled" in r.stdout})
    except Exception:
        checks.append({"id": "cis-3.1", "title": "ufw_enabled", "passed": False})
    passed = sum(1 for c in checks if c["passed"])
    return {"summary": f"{passed}/{len(checks)} checks passed", "type": "sca", "benchmark_id": "cis_linux_agent", "checks": checks, "passed": passed, "total": len(checks)}


def tail_logs() -> dict:
    alerts = []
    patterns = [
        (re.compile(r"Failed password for .* from (\S+)"), "ssh_bruteforce", "high"),
        (re.compile(r"Accepted (publickey|password) for .* from (\S+)"), "ssh_access", "info"),
        (re.compile(r"sudo:.*COMMAND="), "sudo_exec", "info"),
        (re.compile(r"sshd.*Connection closed by authenticating user"), "ssh_closed", "medium"),
    ]
    for log_path in LOG_PATHS:
        if not os.path.exists(log_path):
            continue
        try:
            with open(log_path) as f:
                for line in f:
                    for pat, ltype, sev in patterns:
                        if pat.search(line):
                            alerts.append({"type": ltype, "severity": sev, "line": line.strip()})
                            break
        except PermissionError:
            pass
        except Exception:
            pass
    return {"summary": f"Found {len(alerts)} log matches", "type": "hids", "alerts": alerts}


def process_commands():
    result = api_get(f"/api/v1/agents/{AGENT_ID}/commands")
    cmds = result.get("commands", [])
    for cmd in cmds:
        cid = cmd.get("id")
        cdata = cmd.get("command", {})
        ctype = cdata.get("type") if isinstance(cdata, dict) else ""
        log(f"Executing command #{cid}: {ctype}")
        result_data = {}
        if ctype == "run_fim":
            result_data = run_fim()
        elif ctype == "run_sca":
            result_data = run_sca_cis()
        elif ctype == "run_vuln_inventory":
            result_data = run_vuln_inventory()
        elif ctype == "tail_logs":
            result_data = tail_logs()
        else:
            result_data = {"summary": f"Unknown command: {ctype}", "type": "unknown"}

        api_post(f"/api/v1/agents/{AGENT_ID}/results", {
            "result_type": result_data.get("type", ctype),
            "payload": json.dumps(result_data),
        })
        api_post(f"/api/v1/agents/{AGENT_ID}/commands/{cid}/ack", {"status": "completed"})


def _get_cpu() -> float:
    try:
        with open("/proc/stat") as f:
            line = f.readline()
            parts = line.split()
            idle = int(parts[4])
            total = sum(int(p) for p in parts[1:])
            return round((1 - idle / total) * 100, 1)
    except Exception:
        return 0.0


def _get_mem() -> float:
    try:
        with open("/proc/meminfo") as f:
            data = f.read()
        total = int(re.search(r"MemTotal:\s+(\d+)", data).group(1))
        avail = int(re.search(r"MemAvailable:\s+(\d+)", data).group(1))
        return round((1 - avail / total) * 100, 1)
    except Exception:
        return 0.0


def main():
    global SERVER, AGENT_ID, INTERVAL
    parser = argparse.ArgumentParser(description="KALKI Remote Monitoring Agent")
    parser.add_argument("--server", required=True, help="KALKI WAF server URL (e.g. http://10.0.0.1:8000)")
    parser.add_argument("--agent-id", help="Existing agent ID (omit to register new)")
    parser.add_argument("--interval", type=int, default=30, help="Heartbeat interval in seconds")
    args = parser.parse_args()

    SERVER = args.server.rstrip("/")
    INTERVAL = args.interval

    if args.agent_id:
        AGENT_ID = args.agent_id
        log(f"Using existing agent: {AGENT_ID}")
    else:
        AGENT_ID = register()

    log(f"Agent started. Server: {SERVER} | Interval: {INTERVAL}s")
    log("Commands: run_fim, run_sca, run_vuln_inventory, tail_logs")

    while True:
        try:
            heartbeat()
            process_commands()
        except Exception as e:
            log(f"Error in cycle: {e}")
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
