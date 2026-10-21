#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Writes the JSON parts of the hand-made scenarios in test/fixtures/<scenario>/:
`ip -j addr`, `nft -j list ruleset`, the journal, Docker's API and meta.json.
The text outputs next to them (iptables-save, ss, sshd -T, UFW's files) are
written by hand after the formats of iptables 1.8.10, iproute2 6.x, OpenSSH
9.6 and ufw 0.36. Recorded hosts (capture.sh) can replace them.

Addresses are documentation ranges (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24, 2001:db8::/32) and private networks; no real host is named.

    python3 test/fixtures/make_fixtures.py
"""

import base64
import json
import os
import random
import shutil
import struct
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
NOW = "2026-10-20T12:00:00Z"
T0 = int(datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc).timestamp())


def write(scenario, rel, data):
    path = os.path.join(HERE, scenario, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        if isinstance(data, str):
            f.write(data)
        else:
            json.dump(data, f, indent=1, ensure_ascii=False)
            f.write("\n")


# ---------------------------------------------------------------------------
# ip -j addr

def link(idx, name, addrs, flags=("BROADCAST", "MULTICAST", "UP", "LOWER_UP"), kind="ether"):
    info = []
    for a in addrs:
        fam = "inet6" if ":" in a[0] else "inet"
        d = {"family": fam, "local": a[0], "prefixlen": a[1], "scope": a[2] if len(a) > 2 else "global",
             "label": name, "valid_life_time": 4294967295, "preferred_life_time": 4294967295}
        if fam == "inet6":
            d.pop("label")
        info.append(d)
    return {"ifindex": idx, "ifname": name, "flags": list(flags), "mtu": 1500, "qdisc": "fq_codel",
            "operstate": "UP", "group": "default", "txqlen": 1000, "link_type": kind,
            "address": f"52:54:00:00:00:{idx:02x}", "broadcast": "ff:ff:ff:ff:ff:ff", "addr_info": info}


LO = link(1, "lo", [("127.0.0.1", 8, "host"), ("::1", 128, "host")], ("LOOPBACK", "UP", "LOWER_UP"), "loopback")


def wg(idx, addr):
    return link(idx, "wg0", [(addr, 24)], ("POINTOPOINT", "NOARP", "UP", "LOWER_UP"), "none")


# ---------------------------------------------------------------------------
# Docker's API

def network(name, nid, subnet, bridge=None):
    opts = {"com.docker.network.bridge.name": bridge} if bridge else {}
    return {"Name": name, "Id": nid, "Created": "2026-09-01T10:00:00Z", "Scope": "local", "Driver": "bridge",
            "EnableIPv4": True, "EnableIPv6": False,
            "IPAM": {"Driver": "default", "Options": None, "Config": [{"Subnet": subnet,
                                                                         "Gateway": subnet.replace("0/16", "1")}]},
            "Internal": False, "Attachable": False, "Ingress": False, "Options": opts, "Labels": {}}


def container(cid, name, image, net, nid, ip, ports=None, mounts=(), user="", privileged=False, caps=None,
              network_mode=None, pid_mode="", security_opt=None, apparmor="docker-default"):
    nets = {} if network_mode == "host" else {net: {"NetworkID": nid, "IPAddress": ip, "IPPrefixLen": 16,
                                                    "GlobalIPv6Address": "", "Gateway": ip.rsplit(".", 1)[0] + ".1"}}
    bindings = {}
    for key, binds in (ports or {}).items():
        bindings[key] = [{"HostIp": h, "HostPort": str(p)} for h, p in binds]
    return {
        "Id": cid, "Created": "2026-10-18T08:00:00Z", "Name": "/" + name, "AppArmorProfile": apparmor,
        "Config": {"Hostname": cid[:12], "User": user, "Image": image, "ExposedPorts": {k: {} for k in ports or {}},
                   "Labels": {"com.docker.compose.project": "app", "com.docker.compose.service": name}},
        "HostConfig": {"Privileged": privileged, "PidMode": pid_mode, "CapAdd": caps, "CapDrop": None,
                       "NetworkMode": network_mode or net, "SecurityOpt": security_opt,
                       "PortBindings": {k: [{"HostIp": h, "HostPort": str(p)} for h, p in v] for k, v in
                                        (ports or {}).items()}},
        "Mounts": [{"Type": m[0], "Source": m[1], "Destination": m[2], "Mode": "" if m[3] else "ro", "RW": m[3],
                    "Propagation": "rprivate"} for m in mounts],
        "NetworkSettings": {"Ports": bindings, "Networks": nets},
        "State": {"Status": "running", "Running": True, "Pid": 4000},
    }


def summary(c):
    ports = []
    for key, binds in c["NetworkSettings"]["Ports"].items():
        p, proto = key.split("/")
        for b in binds or []:
            ports.append({"IP": b["HostIp"], "PrivatePort": int(p), "PublicPort": int(b["HostPort"]), "Type": proto})
    return {"Id": c["Id"], "Names": [c["Name"]], "Image": c["Config"]["Image"], "State": "running", "Ports": ports}


def docker(scenario, containers, networks, version="28.5.1", backend="iptables"):
    info = {"ID": "fixture", "Containers": len(containers), "ContainersRunning": len(containers),
            "ServerVersion": version, "OperatingSystem": "Ubuntu 24.04.3 LTS", "KernelVersion": "6.8.0-85-generic",
            "SecurityOptions": ["name=apparmor", "name=seccomp,profile=builtin", "name=cgroupns"],
            "FirewallBackend": {"Driver": backend}}
    write(scenario, "docker/info.json", info)
    write(scenario, "docker/version.json", {"Version": version, "ApiVersion": "1.51", "Os": "linux"})
    write(scenario, "docker/containers.json", [summary(c) for c in containers])
    write(scenario, "docker/networks.json", networks + [
        {"Name": "host", "Id": "f" * 64, "Driver": "host", "IPAM": {"Config": []}, "Options": {}},
        {"Name": "none", "Id": "e" * 64, "Driver": "null", "IPAM": {"Config": []}, "Options": {}}])
    for c in containers:
        write(scenario, f"docker/inspect-{c['Id'][:12]}.json", c)


# ---------------------------------------------------------------------------
# The journal

def jline(minutes_ago, ident, pid, msg):
    return json.dumps({"__REALTIME_TIMESTAMP": str((T0 - minutes_ago * 60) * 1000000), "_PID": str(pid),
                       "SYSLOG_IDENTIFIER": ident, "MESSAGE": msg})


# ---------------------------------------------------------------------------
# A DSA key, which OpenSSH 10 no longer makes

def dsa_pub(comment):
    rnd = random.Random(7)

    def mpint(bits):
        n = rnd.getrandbits(bits) | (1 << (bits - 1))
        b = n.to_bytes((bits + 7) // 8, "big")
        if b[0] & 0x80:
            b = b"\0" + b
        return struct.pack(">I", len(b)) + b

    name = b"ssh-dss"
    blob = struct.pack(">I", len(name)) + name + mpint(1024) + mpint(160) + mpint(1024) + mpint(1024)
    return "ssh-dss " + base64.b64encode(blob).decode() + " " + comment


# ---------------------------------------------------------------------------
# Scenario ufw-docker: UFW on, Docker publishes 8080 past it, WireGuard, IPv4 and IPv6

def ufw_docker(s="ufw-docker"):
    write(s, "commands/ip-addr.json", [
        LO,
        link(2, "eth0", [("203.0.113.10", 32), ("2001:db8:10::1", 64), ("fe80::5054:ff:fe00:2", 64, "link")]),
        link(3, "enp7s0", [("10.0.0.2", 32)]),
        wg(4, "10.8.0.1"),
        link(5, "docker0", [("172.17.0.1", 16)]),
        link(6, "br-1a2b3c4d5e6f", [("172.18.0.1", 16)]),
        link(7, "veth1f2e3d4", [], kind="ether"),
    ])
    app = "1a2b3c4d5e6f" + "7" * 52
    br = "a" * 64
    containers = [
        container("0123456789ab" + "0" * 52, "web", "nginx:1.27-alpine", "bridge", br, "172.17.0.2",
                  {"80/tcp": [("0.0.0.0", 8080), ("::", 8080)]}),
        container("1123456789ab" + "1" * 52, "db", "postgres:17", "app", app, "172.18.0.2",
                  {"5432/tcp": [("127.0.0.1", 5432)]}, mounts=[("volume", "/var/lib/docker/volumes/db/_data",
                                                                "/var/lib/postgresql/data", True)]),
        container("2123456789ab" + "2" * 52, "cache", "redis:7.4", "app", app, "172.18.0.3",
                  {"6379/tcp": [("10.8.0.1", 6379)]}, user="redis", security_opt=["no-new-privileges:true"]),
        container("3123456789ab" + "3" * 52, "runner", "gitea/act_runner:0.2.13", "app", app, "172.18.0.4",
                  mounts=[("bind", "/var/run/docker.sock", "/var/run/docker.sock", True)]),
    ]
    docker(s, containers, [network("bridge", br, "172.17.0.0/16", "docker0"), network("app", app, "172.18.0.0/16")])
    j = [
        jline(5, "sshd-session", 5101, "Accepted publickey for root from 10.8.0.2 port 51022 ssh2: ED25519 "
                                       "SHA256:qDKmFG/9kyw+c70mRjy835t7UXT1U0DlyvkwDDsFSKc"),
        jline(5, "sshd-session", 5101, "pam_unix(sshd:session): session opened for user root(uid=0) by root(uid=0)"),
        jline(300, "sshd-session", 5090, "Accepted publickey for alex from 10.8.0.3 port 40112 ssh2: ED25519 "
                                         "SHA256:2K79bJsAg+NO83qU9qr34b0KCHjClsFCTLWZr+geexE"),
        jline(301, "sshd-session", 5089, "Failed password for alex from 10.8.0.9 port 40100 ssh2"),
        jline(301, "sshd-session", 5089, "Connection closed by authenticating user alex 10.8.0.9 port 40100 [preauth]"),
        jline(1440, "sshd", 1001, "Server listening on 0.0.0.0 port 22."),
        jline(60, "sudo", 6001, "  alex : TTY=pts/0 ; PWD=/home/alex ; USER=root ; COMMAND=/usr/bin/apt update"),
        jline(61, "sudo", 6000, "  alex : 1 incorrect password attempt ; TTY=pts/0 ; PWD=/home/alex ; "
                                "USER=root ; COMMAND=/usr/bin/ls"),
        jline(120, "cockpit-session", 7001, "pam_unix(cockpit:session): session opened for user alex(uid=1000) "
                                            "by alex(uid=0)"),
    ]
    write(s, "commands/journal.jsonl", "\n".join(j) + "\n")
    # The journal begins 9 days and 4 hours back (rotation): the logins cover less than 14 days.
    write(s, "commands/journal-start.jsonl",
          json.dumps({"__REALTIME_TIMESTAMP": str((T0 - 9 * 86400 - 4 * 3600) * 10**6)}) + "\n")
    # Only the tables of iptables-nft: read from iptables-save, left out here.
    write(s, "commands/nft.json", {"nftables": [
        {"metainfo": {"version": "1.0.9", "release_name": "Old Doc Yak #3", "json_schema_version": 1}},
        {"table": {"family": "ip", "name": "filter", "handle": 1}},
        {"chain": {"family": "ip", "table": "filter", "name": "INPUT", "handle": 1, "type": "filter",
                   "hook": "input", "prio": 0, "policy": "drop"}},
        {"rule": {"family": "ip", "table": "filter", "chain": "INPUT", "handle": 9,
                  "expr": [{"xt": {"type": "match", "name": "conntrack"}}, {"counter": {"packets": 0, "bytes": 0}},
                           {"accept": None}]}},
        {"table": {"family": "ip6", "name": "filter", "handle": 2}},
        {"table": {"family": "ip", "name": "nat", "handle": 3}},
        {"table": {"family": "ip6", "name": "nat", "handle": 4}},
    ]})
    write(s, "meta.json", {"now": NOW, "uid": 0, "stat": {
        "/root/.ssh/authorized_keys": {"mode": "600", "uid": 0},
        "/root/.ssh": {"mode": "700", "uid": 0, "type": "dir"},
        "/home/alex/.ssh/authorized_keys": {"mode": "664", "uid": 1000},
        "/home/alex/.ssh": {"mode": "700", "uid": 1000, "type": "dir"}},
        "exists": ["/var/run/docker.sock"]})


# ---------------------------------------------------------------------------
# Scenario hetzner-open: UFW off, Docker publishes to 0.0.0.0, a Hetzner Cloud Firewall in
# front, CrowdSec from Ubuntu's archive, a login from outside the VPN

def hetzner_open():
    s = "hetzner-open"
    write(s, "commands/ip-addr.json", [
        LO,
        link(2, "eth0", [("203.0.113.20", 32), ("2001:db8:20::1", 64), ("fe80::5054:ff:fe00:2", 64, "link")]),
        link(3, "enp7s0", [("10.0.0.3", 32)]),
        link(4, "docker0", [("172.17.0.1", 16)]),
    ])
    br = "b" * 64
    containers = [
        container("4123456789ab" + "4" * 52, "caddy", "caddy:2.10", "bridge", br, "172.17.0.2",
                  {"80/tcp": [("0.0.0.0", 80), ("::", 80)], "443/tcp": [("0.0.0.0", 443), ("::", 443)],
                   "443/udp": [("0.0.0.0", 443), ("::", 443)]}),
        container("5123456789ab" + "5" * 52, "onlyoffice", "onlyoffice/documentserver:9.1", "bridge", br,
                  "172.17.0.3", {"80/tcp": [("0.0.0.0", 8443), ("::", 8443)]}, privileged=True),
        container("6123456789ab" + "6" * 52, "rustdesk", "rustdesk/rustdesk-server:1.1.14", "bridge", br,
                  "172.17.0.4", {"21115/tcp": [("0.0.0.0", 21115)], "21116/tcp": [("0.0.0.0", 21116)],
                                 "21116/udp": [("0.0.0.0", 21116)]},
                  caps=["NET_ADMIN"]),
        container("7123456789ab" + "7" * 52, "postgres", "postgres:16", "bridge", br, "172.17.0.5",
                  {"5432/tcp": [("0.0.0.0", 5432)]}),
    ]
    docker(s, containers, [network("bridge", br, "172.17.0.0/16", "docker0")])
    j = [jline(90, "sshd-session", 5201, "Accepted publickey for root from 198.51.100.20 port 50111 ssh2: ED25519 "
                                         "SHA256:qDKmFG/9kyw+c70mRjy835t7UXT1U0DlyvkwDDsFSKc")]
    for n, pid in enumerate(range(5300, 5306)):
        j.append(jline(200 + n, "sshd-session", pid, "Invalid user admin from 192.0.2.50 port 41000"))
        j.append(jline(200 + n, "sshd-session", pid, "Failed password for invalid user admin from 192.0.2.50 "
                                                     "port 41000 ssh2"))
    j.append(jline(400, "sshd-session", 5310, "Failed password for root from 192.0.2.77 port 41500 ssh2"))
    j.append(jline(30, "cockpit-session", 7101, "pam_unix(cockpit:auth): authentication failure; logname= uid=0 "
                                                "euid=0 tty= ruser= rhost=192.0.2.90  user=admin"))
    write(s, "commands/journal.jsonl", "\n".join(j) + "\n")
    write(s, "commands/nft.json", {"nftables": [
        {"metainfo": {"version": "1.0.9", "release_name": "Old Doc Yak #3", "json_schema_version": 1}},
        {"table": {"family": "ip", "name": "filter", "handle": 1}},
        {"table": {"family": "ip", "name": "nat", "handle": 2}},
        {"table": {"family": "ip6", "name": "filter", "handle": 3}},
        {"table": {"family": "ip", "name": "crowdsec", "handle": 5}},
        {"set": {"family": "ip", "name": "crowdsec-blacklists", "table": "crowdsec", "type": "ipv4_addr",
                 "handle": 2, "flags": ["timeout"],
                 "elem": [{"elem": {"val": "192.0.2.50", "timeout": 14400, "expires": 13000}},
                          {"elem": {"val": "192.0.2.77", "timeout": 14400, "expires": 12000}}]}},
        {"chain": {"family": "ip", "table": "crowdsec", "name": "crowdsec-chain", "handle": 1, "type": "filter",
                   "hook": "input", "prio": 0, "policy": "accept"}},
        {"rule": {"family": "ip", "table": "crowdsec", "chain": "crowdsec-chain", "handle": 3,
                  "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}},
                                      "right": "@crowdsec-blacklists"}},
                           {"counter": {"packets": 12, "bytes": 720}}, {"drop": None}]}},
    ]})
    write(s, "commands/cscli-decisions.json", [
        {"id": 11, "machine_id": "fixture", "scenario": "crowdsecurity/ssh-bf", "message": "Ip 192.0.2.50 performed "
         "'crowdsecurity/ssh-bf' (6 events over 5s)", "events_count": 6, "start_at": "2026-10-20T08:40:00Z",
         "stop_at": "2026-10-20T08:40:05Z", "created_at": "2026-10-20T08:40:06Z", "capacity": 5, "leakspeed": "10s",
         "simulated": False, "source": {"ip": "192.0.2.50", "scope": "Ip", "value": "192.0.2.50", "cn": "XX",
                                        "as_name": "EXAMPLE-AS", "as_number": "64500"},
         "decisions": [{"id": 21, "origin": "crowdsec", "type": "ban", "scope": "Ip", "value": "192.0.2.50",
                        "duration": "3h37m", "scenario": "crowdsecurity/ssh-bf", "simulated": False}]},
        {"id": 12, "machine_id": "fixture", "scenario": "crowdsecurity/ssh-slow-bf", "events_count": 11,
         "source": {"ip": "192.0.2.77", "scope": "Ip", "value": "192.0.2.77", "cn": "XX"},
         "decisions": [{"id": 22, "origin": "crowdsec", "type": "ban", "scope": "Ip", "value": "192.0.2.77",
                        "duration": "3h20m", "scenario": "crowdsecurity/ssh-slow-bf", "simulated": False}]}])
    write(s, "commands/cscli-alerts.json", [
        {"id": 11, "scenario": "crowdsecurity/ssh-bf", "source": {"ip": "192.0.2.50"}, "events_count": 6},
        {"id": 12, "scenario": "crowdsecurity/ssh-slow-bf", "source": {"ip": "192.0.2.77"}, "events_count": 11},
        {"id": 9, "scenario": "crowdsecurity/ssh-bf", "source": {"ip": "192.0.2.51"}, "events_count": 6}])
    write(s, "commands/cscli-bouncers.json", [
        {"id": 1, "name": "cs-firewall-bouncer-1729000000", "ip_address": "127.0.0.1", "revoked": False,
         "type": "crowdsec-firewall-bouncer", "version": "v0.0.25-debian-pragmatic-e2cba8fa", "last_pull":
         "2026-10-20T11:59:50Z", "auth_type": "api-key", "created_at": "2026-09-01T10:00:00Z"}])
    write(s, "hetzner-api/servers.json", {"servers": [
        {"id": 4711, "name": "web-1", "status": "running",
         "public_net": {"ipv4": {"ip": "203.0.113.20", "blocked": False}, "ipv6": {"ip": "2001:db8:20::/64"},
                        "firewalls": [{"id": 38, "status": "applied"}], "floating_ips": []},
         "private_net": [{"network": 100, "ip": "10.0.0.3"}]},
        {"id": 4712, "name": "other", "status": "running",
         "public_net": {"ipv4": {"ip": "203.0.113.21"}, "ipv6": {"ip": "2001:db8:21::/64"}, "firewalls": []}}],
        "meta": {"pagination": {"page": 1, "per_page": 50, "previous_page": None, "next_page": None,
                                "last_page": 1, "total_entries": 2}}})
    write(s, "hetzner-api/firewalls.json", {"firewalls": [
        {"id": 38, "name": "web", "labels": {}, "created": "2026-09-01T10:00:00+00:00",
         "rules": [
             {"direction": "in", "protocol": "tcp", "port": "80", "source_ips": ["0.0.0.0/0", "::/0"],
              "destination_ips": [], "description": "HTTP"},
             {"direction": "in", "protocol": "tcp", "port": "443", "source_ips": ["0.0.0.0/0", "::/0"],
              "destination_ips": [], "description": "HTTPS"},
             {"direction": "in", "protocol": "udp", "port": "443", "source_ips": ["0.0.0.0/0", "::/0"],
              "destination_ips": [], "description": "HTTP/3"},
             {"direction": "in", "protocol": "tcp", "port": "8443", "source_ips": ["198.51.100.0/24"],
              "destination_ips": [], "description": "Office"},
             {"direction": "in", "protocol": "icmp", "port": None, "source_ips": ["0.0.0.0/0", "::/0"],
              "destination_ips": [], "description": None},
             {"direction": "out", "protocol": "tcp", "port": "any", "source_ips": [],
              "destination_ips": ["0.0.0.0/0"], "description": None}],
         "applied_to": [{"type": "server", "server": {"id": 4711}}]},
        {"id": 39, "name": "unused", "rules": [], "applied_to": []}],
        "meta": {"pagination": {"page": 1, "per_page": 50, "next_page": None, "last_page": 1, "total_entries": 2}}})
    write(s, "meta.json", {"now": NOW, "uid": 0, "stat": {"/root/.ssh/authorized_keys": {"mode": "600", "uid": 0},
                                                         "/root/.ssh": {"mode": "700", "uid": 0, "type": "dir"},
                                                         "/etc/cockpit-security-monitor/hetzner.token":
                                                             {"mode": "600", "uid": 0}},
                           "exists": ["/var/run/docker.sock", "/usr/bin/cscli"]})


# ---------------------------------------------------------------------------
# Scenario nft-native: nftables.conf with a verdict map, Docker in iptables mode, sshd -T
# failing for want of /run/sshd, a CI runner with the Docker socket, no public IPv6

def nft_native():
    s = "nft-native"
    write(s, "commands/ip-addr.json", [
        LO,
        link(2, "eth0", [("198.51.100.30", 32), ("fe80::5054:ff:fe00:2", 64, "link")]),
        wg(3, "10.8.0.4"),
        link(4, "docker0", [("172.17.0.1", 16)]),
    ])
    br = "c" * 64
    containers = [
        container("8123456789ab" + "8" * 52, "forgejo", "codeberg.org/forgejo/forgejo:13", "bridge", br,
                  "172.17.0.2", {"3000/tcp": [("0.0.0.0", 3000)], "22/tcp": [("10.8.0.4", 2222)]}, user="git",
                  security_opt=["no-new-privileges"]),
        container("9123456789ab" + "9" * 52, "runner", "data.forgejo.org/forgejo/runner:11", "bridge", br,
                  "172.17.0.3", mounts=[("bind", "/run/docker.sock", "/var/run/docker.sock", False)],
                  privileged=True),
        container("a123456789ab" + "a" * 52, "monitor", "prom/node-exporter:v1.9", "host", None, "",
                  network_mode="host", pid_mode="host", mounts=[("bind", "/", "/host", False)], user="nobody",
                  apparmor="unconfined"),
    ]
    docker(s, containers, [network("bridge", br, "172.17.0.0/16", "docker0")])
    write(s, "commands/journal.jsonl", "\n".join([
        jline(10, "sshd", 900, "Accepted publickey for root from 10.8.0.2 port 51022 ssh2: ED25519 "
                               "SHA256:qDKmFG/9kyw+c70mRjy835t7UXT1U0DlyvkwDDsFSKc")]) + "\n")
    m = lambda left, right, op="==": {"match": {"op": op, "left": left, "right": right}}  # noqa: E731
    meta = lambda k: {"meta": {"key": k}}  # noqa: E731
    pl = lambda p, f: {"payload": {"protocol": p, "field": f}}  # noqa: E731
    cnt = {"counter": {"packets": 0, "bytes": 0}}
    rules = [
        ("input", [{"vmap": {"key": meta("iifname"), "data": {"set": [["lo", {"accept": None}],
                                                                     ["wg0", {"jump": {"target": "vpn_in"}}]]}}}]),
        ("input", [m({"ct": {"key": "state"}}, ["established", "related"], "in"), cnt, {"accept": None}]),
        ("input", [m({"ct": {"key": "state"}}, "invalid", "in"), {"drop": None}]),
        ("input", [m(meta("l4proto"), "ipv6-icmp"), {"accept": None}]),
        ("input", [m(meta("l4proto"), "icmp"), {"accept": None}]),
        ("input", [m(pl("tcp", "dport"), {"set": [80, 443]}), cnt, {"accept": None}]),
        ("input", [m(pl("udp", "dport"), 51820), cnt, {"accept": None}]),
        ("input", [m(pl("tcp", "dport"), {"range": [60000, 60010]}),
                   m(pl("ip", "saddr"), {"prefix": {"addr": "192.0.2.0", "len": 24}}), {"accept": None}]),
        ("input", [{"xt": {"type": "match", "name": "recent"}}, {"drop": None}]),
        ("input", [{"counter": None}, {"log": {"prefix": "nft drop: "}}]),
        ("vpn_in", [m(pl("tcp", "dport"), 9090), {"accept": None}]),
        ("vpn_in", [m(pl("tcp", "dport"), {"set": [22, 9100]}), {"accept": None}]),
        ("vpn_in", [{"return": None}]),
    ]
    items = [
        {"metainfo": {"version": "1.1.3", "release_name": "Commodore Bullmoose #4", "json_schema_version": 1}},
        {"table": {"family": "inet", "name": "filter", "handle": 1}},
        {"chain": {"family": "inet", "table": "filter", "name": "input", "handle": 1, "type": "filter",
                   "hook": "input", "prio": 0, "policy": "drop"}},
        {"chain": {"family": "inet", "table": "filter", "name": "forward", "handle": 2, "type": "filter",
                   "hook": "forward", "prio": 0, "policy": "accept"}},
        {"chain": {"family": "inet", "table": "filter", "name": "output", "handle": 3, "type": "filter",
                   "hook": "output", "prio": 0, "policy": "accept"}},
        {"chain": {"family": "inet", "table": "filter", "name": "vpn_in", "handle": 4}},
        {"table": {"family": "ip", "name": "filter", "handle": 2}},
        {"table": {"family": "ip", "name": "nat", "handle": 3}},
    ]
    for n, (chain, expr) in enumerate(rules, 10):
        items.append({"rule": {"family": "inet", "table": "filter", "chain": chain, "handle": n, "expr": expr}})
    write(s, "commands/nft.json", {"nftables": items})
    write(s, "meta.json", {"now": NOW, "uid": 0, "rc": {"sshd-T": 255},
                           "stderr": {"sshd-T": "Missing privilege separation directory: /run/sshd\n"},
                           "stat": {"/root/.ssh/authorized_keys": {"mode": "600", "uid": 0},
                                    "/root/.ssh": {"mode": "700", "uid": 0, "type": "dir"},
                                    "/home/ci/.ssh/authorized_keys": {"mode": "644", "uid": 1001},
                                    "/home/ci/.ssh": {"mode": "777", "uid": 1001, "type": "dir"}},
                           "exists": ["/var/run/docker.sock"]})
    write(s, "files/home/ci/.ssh/authorized_keys", dsa_pub("old-ci") + "\n")
    # node_exporter runs in the host network: ss sees its process, its cgroup names the container
    write(s, "files/proc/980/cgroup", f"0::/system.slice/docker-{containers[2]['Id']}.scope\n")


def hetzner_answer():
    """What security-hetzner.py writes for hetzner-open, from the recorded API answers."""
    import importlib.util
    import sys
    lib = os.path.join(HERE, "..", "..", "lib")
    sys.path.insert(0, lib)
    spec = importlib.util.spec_from_file_location("security_hetzner", os.path.join(lib, "security-hetzner.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    api = os.path.join(HERE, "hetzner-open", "hetzner-api")

    def get(path, token):
        with open(os.path.join(api, path.split("?")[0].strip("/") + ".json"), encoding="utf-8") as f:
            return json.load(f)
    out = os.path.join(HERE, "hetzner-open", "files", "var", "lib", "cockpit-security-hetzner", "hetzner.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    token = os.path.join(HERE, "hetzner-open", "files", "etc", "cockpit-security-monitor", "hetzner.token")
    mod.main(["--output", out, "--token-file", token], get=get, addrs=["203.0.113.20", "2001:db8:20::1"],
             now=datetime(2026, 10, 20, 11, 59, tzinfo=timezone.utc))


# ---------------------------------------------------------------------------
# Scenario fail2ban: ufw-docker plus fail2ban 1.0.2 (formats of fail2ban-client's beautifier and
# `-d` dump), four jails with one finding of each kind:
#   sshd             journal, iptables-multiport in INPUT, a ban; f2b-sshd also blocks an address
#                    fail2ban does not hold (left from /etc/iptables/rules.v4)
#   recidive         iptables-allports in INPUT (container ports not covered: a note), its log idle
#   web              Ubuntu's default nftables action (hook input) in front of Docker's 8080 and
#                    caddy's 443 (also UDP): both findings
#   nginx-botsearch  reads the error log, never a hit while fail2ban has run for two days

def fail2ban():
    s = "fail2ban"
    base = os.path.join(HERE, "ufw-docker")
    shutil.copytree(os.path.join(base, "files"), os.path.join(HERE, s, "files"), dirs_exist_ok=True)
    for rel in ("commands/ss.txt", "commands/ip6tables-save.txt", "commands/sshd-T.txt"):
        with open(os.path.join(base, rel), encoding="utf-8") as f:
            write(s, rel, f.read())
    ufw_docker(s)
    with open(os.path.join(base, "commands/iptables-save.txt"), encoding="utf-8") as f:
        ipt = f.read()
    ipt = ipt.replace(":DOCKER-USER - [0:0]\n", ":DOCKER-USER - [0:0]\n:f2b-recidive - [0:0]\n:f2b-sshd - [0:0]\n", 1)
    ipt = ipt.replace("-A INPUT -j ufw-before-logging-input\n",
                      "-A INPUT -p tcp -j f2b-recidive\n-A INPUT -p tcp -m multiport --dports 22 -j f2b-sshd\n"
                      "-A INPUT -j ufw-before-logging-input\n", 1)
    rej = " -j REJECT --reject-with icmp-port-unreachable\n"
    chains = ("-A f2b-recidive -s 198.51.100.20/32" + rej + "-A f2b-recidive -j RETURN\n"
              "-A f2b-sshd -s 203.0.113.50/32" + rej + "-A f2b-sshd -s 198.51.100.7/32" + rej +
              "-A f2b-sshd -j RETURN\n")
    i = ipt.index("COMMIT\n")
    write(s, "commands/iptables-save.txt", ipt[:i] + chains + ipt[i:])
    with open(os.path.join(HERE, s, "commands/nft.json"), encoding="utf-8") as f:
        nft = json.load(f)
    nft["nftables"] += [
        {"table": {"family": "inet", "name": "f2b-table", "handle": 5}},
        {"chain": {"family": "inet", "table": "f2b-table", "name": "f2b-chain", "handle": 1, "type": "filter",
                   "hook": "input", "prio": -1, "policy": "accept"}},
        {"set": {"family": "inet", "name": "addr-set-web", "table": "f2b-table", "type": "ipv4_addr", "handle": 2,
                 "elem": ["192.0.2.80"]}},
        {"rule": {"family": "inet", "table": "f2b-table", "chain": "f2b-chain", "handle": 3, "expr": [
            {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                       "right": {"set": [443, 8080]}}},
            {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "@addr-set-web"}},
            {"reject": None}]}},
    ]
    write(s, "commands/nft.json", nft)
    write(s, "commands/systemctl-show-fail2ban.txt",
          "ActiveState=active\nUnitFileState=enabled\nActiveEnterTimestamp=Sun 2026-10-18 08:00:00 UTC\n")
    write(s, "commands/f2b-version.txt", "Fail2Ban v1.0.2\n")
    write(s, "commands/f2b-ping.txt", "Server replied: pong\n")
    write(s, "commands/f2b-status.txt",
          "Status\n|- Number of jail:\t4\n`- Jail list:\tnginx-botsearch, recidive, sshd, web\n")

    def jail_status(name, failed_now, failed_total, source, banned_total, banned):
        return (f"Status for the jail: {name}\n|- Filter\n|  |- Currently failed:\t{failed_now}\n"
                f"|  |- Total failed:\t{failed_total}\n|  `- {source}\n`- Actions\n"
                f"   |- Currently banned:\t{len(banned)}\n   |- Total banned:\t{banned_total}\n"
                f"   `- Banned IP list:\t{' '.join(banned)}\n")

    write(s, "commands/f2b-status-sshd.txt", jail_status(
        "sshd", 1, 41, "Journal matches:\t_SYSTEMD_UNIT=ssh.service + _COMM=sshd", 7, ["203.0.113.50"]))
    write(s, "commands/f2b-status-recidive.txt", jail_status(
        "recidive", 0, 2, "File list:\t/var/log/fail2ban.log", 1, ["198.51.100.20"]))
    write(s, "commands/f2b-status-web.txt", jail_status(
        "web", 0, 12, "File list:\t/var/log/web/access.log", 3, ["192.0.2.80"]))
    write(s, "commands/f2b-status-nginx-botsearch.txt", jail_status(
        "nginx-botsearch", 0, 0, "File list:\t/var/log/nginx/error.log", 0, []))
    start = "<iptables> -N f2b-<name>\n<iptables> -A f2b-<name> -j <returntype>\n" \
            "<iptables> -I <chain> -p <protocol> -m multiport --dports <port> -j f2b-<name>"
    ban = "<iptables> -I f2b-<name> 1 -s <ip> -j <blocktype>"
    dump = [
        ["set", "syslogsocket", "auto"], ["set", "loglevel", "INFO"], ["set", "logtarget", "/var/log/fail2ban.log"],
        ["set", "allowipv6", "auto"], ["set", "dbfile", "/var/lib/fail2ban/fail2ban.sqlite3"],
        ["set", "dbmaxmatches", 10], ["set", "dbpurgeage", "1d"],
        ["add", "nginx-botsearch", "auto"], ["set", "nginx-botsearch", "usedns", "warn"],
        ["set", "nginx-botsearch", "maxretry", 2], ["set", "nginx-botsearch", "findtime", "10m"],
        ["set", "nginx-botsearch", "bantime", "10m"],
        ["multi-set", "nginx-botsearch", "addfailregex", ['^<HOST> \\- \\S+ \\[\\] \\"(GET|POST|HEAD) '
                                                          '\\/<block> \\S+\\" 404 .+$']],
        ["set", "nginx-botsearch", "addlogpath", "/var/log/nginx/error.log", "head"],
        ["set", "nginx-botsearch", "addaction", "iptables-multiport"],
        ["multi-set", "nginx-botsearch", "action", "iptables-multiport",
         [["actionstart", start], ["actionban", ban], ["name", "nginx-botsearch"], ["port", "http,https"],
          ["protocol", "tcp"], ["chain", "<known/chain>"]]],
        ["add", "recidive", "auto"], ["set", "recidive", "maxretry", 5], ["set", "recidive", "findtime", "1d"],
        ["set", "recidive", "bantime", "1w"],
        ["multi-set", "recidive", "addfailregex", ['^(%(__prefix_line)s|,\\d{3} fail2ban.actions:\\s+)WARNING '
                                                   '\\[(?!recidive)\\S+\\] Ban <HOST>']],
        ["set", "recidive", "addlogpath", "/var/log/fail2ban.log", "head"],
        ["set", "recidive", "addaction", "iptables-allports"],
        ["multi-set", "recidive", "action", "iptables-allports",
         [["actionban", ban], ["name", "recidive"], ["protocol", "tcp"], ["chain", "<known/chain>"]]],
        ["add", "sshd", "systemd"], ["set", "sshd", "usedns", "warn"], ["set", "sshd", "maxretry", 5],
        ["set", "sshd", "addignoreip", "127.0.0.1/8", "::1", "10.8.0.0/24"],
        ["set", "sshd", "addjournalmatch", "_SYSTEMD_UNIT=ssh.service", "+", "_COMM=sshd"],
        ["multi-set", "sshd", "addfailregex", ["^Failed \\S+ for .* from <HOST>", "^Invalid user .* from <HOST>"]],
        ["set", "sshd", "findtime", "10m"], ["set", "sshd", "bantime", "1h"],
        ["set", "sshd", "addaction", "iptables-multiport"],
        ["multi-set", "sshd", "action", "iptables-multiport",
         [["actionstart", start], ["actionban", ban], ["name", "sshd"], ["port", "ssh"], ["protocol", "tcp"],
          ["chain", "<known/chain>"]]],
        ["add", "web", "auto"], ["set", "web", "maxretry", 3], ["set", "web", "findtime", "10m"],
        ["set", "web", "bantime", "10m"],
        ["multi-set", "web", "addfailregex", ['^<HOST> .* "POST /login[^"]*" 401 ']],
        ["set", "web", "addlogpath", "/var/log/web/access.log", "head"],
        ["set", "web", "addaction", "nftables"],
        ["multi-set", "web", "action", "nftables",
         [["actionban", "<nftables> add element <table_family> <table> <addr_set> { <ip> }"], ["name", "web"],
          ["port", "8080,443"], ["protocol", "tcp"], ["chain", "<known/chain>"]]],
        ["start", "nginx-botsearch"], ["start", "recidive"], ["start", "sshd"], ["start", "web"],
    ]
    write(s, "commands/f2b-dump.txt", "".join(repr(c) + "\n" for c in dump))
    write(s, "fail2ban-db.json", {
        "bips": [["203.0.113.50", "sshd", T0 - 1800, 3600, 1], ["198.51.100.20", "recidive", T0 - 86400, 604800, 1],
                 ["192.0.2.80", "web", T0 - 300, 600, 2], ["198.51.100.99", "sshd", T0 - 10000, 3600, 1]],
        "history": [["recidive", 1, T0 - 86400], ["sshd", 7, T0 - 1800], ["web", 3, T0 - 300]]})
    write(s, "files/etc/iptables/rules.v4", "*filter\n:INPUT DROP [0:0]\n:f2b-sshd - [0:0]\n"
                                            "-A f2b-sshd -s 198.51.100.7/32" + rej + "COMMIT\n")
    for p, text in (("var/log/fail2ban.log", "2026-10-15 09:00:00,000 fail2ban.actions [900]: NOTICE  [sshd] "
                                             "Ban 198.51.100.20\n"),
                    ("var/log/web/access.log", '192.0.2.80 - - [20/Oct/2026:11:58:00 +0000] "POST /login HTTP/1.1" '
                                               '401 12 "-" "curl/8.5.0"\n'),
                    ("var/log/nginx/error.log", "2026/10/20 10:00:00 [error] 1450#1450: *7 open() "
                                                '"/usr/share/nginx/html/wp-login.php" failed (2: No such file or '
                                                "directory)\n")):
        write(s, "files/" + p, text)
    with open(os.path.join(HERE, s, "meta.json"), encoding="utf-8") as f:
        meta = json.load(f)
    meta["exists"] = meta.get("exists", []) + ["/usr/bin/fail2ban-client"]
    meta["stat"].update({
        "/var/log/fail2ban.log": {"mode": "640", "uid": 0, "size": 12000, "mtime": "2026-10-15T09:00:00Z"},
        "/var/log/web/access.log": {"mode": "640", "uid": 0, "size": 48000, "mtime": "2026-10-20T11:58:00Z"},
        "/var/log/nginx/error.log": {"mode": "640", "uid": 0, "size": 2048, "mtime": "2026-10-20T10:00:00Z"}})
    write(s, "meta.json", meta)


if __name__ == "__main__":
    ufw_docker()
    fail2ban()
    hetzner_open()
    nft_native()
    hetzner_answer()
    print("written")
