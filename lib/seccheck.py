# SPDX-License-Identifier: Apache-2.0
"""Every check of Security Monitor, stage 1: what is reachable from where,
the SSH configuration and keys, the logins of the last 14 days, the
hardening of the containers and, when installed, CrowdSec.

Lives in /usr/lib/cockpit-security-monitor (root-owned). Standard library
only. Reads only: the commands are listings (ip, ss, iptables-save, nft,
sshd -T, journalctl, cscli), Docker is asked with GET only, files are read
without following a link where a user could place one. The format of the
result (state.json) is in docs/INTERNALS.md.

System is the one door to the machine; the tests replace it with recorded
output (test/fakesys.py).
"""

import copy
import ipaddress
import json
import os
import re
import stat
import time
from datetime import datetime, timezone

import secfw
import seclib
import secproc

FORMAT = 1
NET = ipaddress.ip_network
HETZNER_FILE = "/var/lib/cockpit-security-hetzner/hetzner.json"
HETZNER_TOKEN = "/etc/cockpit-security-monitor/hetzner.token"
MARKS_FILE = "/etc/cockpit-security-monitor/exposure.conf"
PROBE_PORT = 64999
CLASSES = ("internet", "vpn", "private", "local")
ORDER = {"none": 0, "ok": 1, "info": 2, "warning": 3, "danger": 4}
STATE_OF_RESULT = {"open": 3, "unknown": 2, "restricted": 1, "closed": 0, "absent": -1}


class System:
    """The real machine."""

    def run(self, argv, limit=60):
        return secproc.run(argv, limit)

    def read(self, path, limit=4 << 20):
        try:
            with open(path, "rb") as f:
                return f.read(limit).decode("utf-8", "replace")
        except OSError:
            return None

    def read_user_file(self, path, limit=1 << 20):
        """A file a user may control: no link followed at the last step,
        regular files only, at most `limit` bytes. (text, stat) or (None, stat|None)."""
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
        except OSError:
            return None, self.lstat(path)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                return None, st
            with os.fdopen(fd, "rb") as f:
                fd = None
                return f.read(limit).decode("utf-8", "replace"), st
        finally:
            if fd is not None:
                os.close(fd)

    def lstat(self, path):
        try:
            return os.lstat(path)
        except OSError:
            return None

    def stat(self, path):
        try:
            return os.stat(path)
        except OSError:
            return None

    def exists(self, path):
        return os.path.exists(path)

    def listdir(self, path):
        try:
            return sorted(os.listdir(path))
        except OSError:
            return None

    def docker(self, path):
        return seclib.docker_get(path)

    def now(self):
        return datetime.now(timezone.utc)

    def uid(self):
        return os.geteuid()


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def iso_ts(ts):
    return iso(datetime.fromtimestamp(ts, timezone.utc)) if ts else None


class Sources:
    """What each source gave: ok, missing (tool not installed), needs-root,
    error, timeout or skipped, with the time it took."""

    def __init__(self):
        self.items = {}

    def note(self, name, state, t0=None, **kw):
        d = {"state": state}
        if t0 is not None:
            d["took_ms"] = int((time.monotonic() - t0) * 1000)
        d.update({k: v for k, v in kw.items() if v is not None})
        self.items[name] = d

    def from_result(self, name, res, t0, root=True):
        if res.missing:
            self.note(name, "missing", t0)
        elif res.timeout:
            self.note(name, "timeout", t0)
        elif res.rc != 0:
            msg = (res.err or res.out or "").strip().splitlines()
            if not root and msg and re.search(r"(?i)permission|denied|not permitted|must be root|root", msg[0]):
                self.note(name, "needs-root", t0)
            else:
                self.note(name, "error", t0, error=seclib.clean(msg[0] if msg else f"exit {res.rc}", 160))
        else:
            self.note(name, "ok", t0)
        return self.items[name]["state"] == "ok"


# ---------------------------------------------------------------------------
# The scan

def scan(system=None):
    system = system or System()
    t_start = time.monotonic()
    now = system.now()
    root = system.uid() == 0
    src = Sources()
    doc = {"format": FORMAT, "generated": iso(now), "root": root}

    ifaces = collect_ip(system, src, root)
    sockets = collect_ss(system, src, root)
    docker = collect_docker(system, src, root)
    rs, fw = collect_rules(system, src, root)
    ufw = collect_ufw(system, src, rs)
    hetzner = collect_hetzner(system, src, now)
    sshd = collect_sshd(system, src, root)
    keys = collect_keys(system, src, root, sshd)
    logins = collect_logins(system, src, root, ifaces)
    crowd = collect_crowdsec(system, src, root)

    net = network(ifaces)
    fw["input_filter"] = {f: input_filter(rs, net, f) if src.items.get("rules", {}).get("state") == "ok" else
                          "unknown" for f in (4, 6)}
    fw["ufw"] = ufw
    fw["docker"] = docker["summary"] if docker else None
    fw["hetzner"] = hetzner
    doc["network"] = {"interfaces": [i for i in ifaces if i["kind"] != "container"] if ifaces else [],
                      "public": {str(f): bool(net[f]["internet"]) for f in (4, 6)}}
    doc["firewall"] = fw
    rules_ok = src.items.get("rules", {}).get("state") == "ok"
    doc["ports"] = assess_ports(rs if rules_ok else None, net, sockets or [], docker, hetzner, fw)
    doc["ssh"] = assess_ssh(sshd, keys)
    doc["logins"] = logins
    doc["containers"] = assess_containers(docker)
    doc["crowdsec"] = assess_crowdsec(crowd, docker, rs if rules_ok else None)
    doc["sources"] = src.items
    doc["took_ms"] = int((time.monotonic() - t_start) * 1000)
    return doc


# ---------------------------------------------------------------------------
# Network

def collect_ip(system, src, root):
    t0 = time.monotonic()
    res = system.run(["ip", "-j", "addr"], 20)
    if not src.from_result("ip", res, t0, root):
        return []
    try:
        return seclib.parse_ip_addr(res.out)
    except ValueError as e:
        src.note("ip", "error", t0, error=seclib.clean(str(e), 120))
        return []


def network(ifaces):
    """Per family: the interfaces of each class with their address, and the
    networks of the VPN, private and local classes."""
    out = {}
    for f in (4, 6):
        cls = {c: [] for c in CLASSES}
        nets = {c: [] for c in CLASSES}
        for i in ifaces:
            for a in i["addrs"]:
                if a["family"] != f or a["class"] not in CLASSES:
                    continue
                c = a["class"]
                if i["name"] not in [x[0] for x in cls[c]]:
                    cls[c].append((i["name"], a["addr"]))
                n = NET(f"{a['addr']}/{a['prefix']}", strict=False)
                if c in ("vpn", "private"):
                    n = seclib.widen(n)
                if n not in nets[c]:
                    nets[c].append(n)
        if not cls["local"]:
            cls["local"] = [("lo", "127.0.0.1" if f == 4 else "::1")]
        nets["local"] = [NET("127.0.0.0/8") if f == 4 else NET("::1/128")]
        out[f] = {"ifaces": cls, "nets": nets, "internet": cls["internet"]}
    return out


def collect_ss(system, src, root):
    t0 = time.monotonic()
    res = system.run(["ss", "-H", "-tulpn"], 20)
    if not src.from_result("ss", res, t0, root):
        return None
    socks = seclib.parse_ss(res.out)
    if not root:
        src.items["ss"]["partial"] = "processes"
    # The container of a process (for host-network containers), from its cgroup.
    for s in socks:
        for p in s["procs"]:
            cg = system.read(f"/proc/{p['pid']}/cgroup", 8192) or ""
            m = re.search(r"(?:docker[-/]|/docker/)([0-9a-f]{64})", cg)
            if m:
                p["container_id"] = m.group(1)
    return socks


# ---------------------------------------------------------------------------
# Docker

def collect_docker(system, src, root):
    t0 = time.monotonic()
    if not system.exists(seclib.DOCKER_SOCKET):
        src.note("docker", "missing", t0)
        return None
    try:
        info = system.docker("/info")
        version = system.docker("/version")
        listing = system.docker("/containers/json")
        networks = system.docker("/networks")
        containers = []
        for c in listing if isinstance(listing, list) else []:
            cid = str(c.get("Id", ""))
            if re.match(r"^[0-9a-f]{12,64}$", cid):
                containers.append(system.docker(f"/containers/{cid}/json"))
    except PermissionError:
        src.note("docker", "needs-root", t0)
        return None
    except (OSError, ValueError) as e:
        src.note("docker", "error", t0, error=seclib.clean(str(e), 160))
        return None
    src.note("docker", "ok", t0)
    bridges = {}
    for n in networks if isinstance(networks, list) else []:
        if n.get("Driver") != "bridge":
            continue
        name = (n.get("Options") or {}).get("com.docker.network.bridge.name") or "br-" + str(n.get("Id", ""))[:12]
        subnets = []
        for cfg in (n.get("IPAM") or {}).get("Config") or []:
            try:
                subnets.append(NET(cfg.get("Subnet"), strict=False))
            except (TypeError, ValueError):
                pass
        bridges[str(n.get("Id"))] = {"name": name, "subnets": subnets, "ipv6": bool(n.get("EnableIPv6"))}
    backend = (info.get("FirewallBackend") or {}).get("Driver") if isinstance(info, dict) else None
    summary = {"version": seclib.clean((version or {}).get("Version"), 40) or None,
               "backend": backend or "iptables", "backend_known": bool(backend),
               "containers": len(containers)}
    return {"summary": summary, "containers": containers, "bridges": bridges}


def docker_mappings(docker):
    """Published ports: [{"container", "image", "id", "proto", "host_ip", "host_port",
    "port", "addr4", "addr6", "bridge"}]."""
    out = []
    if not docker:
        return out
    for c in docker["containers"]:
        name = str(c.get("Name") or "").lstrip("/")
        image = str((c.get("Config") or {}).get("Image") or "")
        ns = c.get("NetworkSettings") or {}
        nets = ns.get("Networks") or {}
        addr4 = addr6 = bridge = None
        for _, n in sorted(nets.items()):
            b = docker["bridges"].get(str(n.get("NetworkID")))
            if b and n.get("IPAddress"):
                addr4, addr6, bridge = n.get("IPAddress"), n.get("GlobalIPv6Address") or None, b["name"]
                break
        for key, binds in sorted((ns.get("Ports") or {}).items()):
            m = re.match(r"^(\d+)/(tcp|udp|sctp)$", key)
            if not m or not binds:
                continue
            for b in binds:
                try:
                    hp = int(b.get("HostPort"))
                except (TypeError, ValueError):
                    continue
                out.append({"container": seclib.clean(name, 128), "image": seclib.clean(image, 200),
                            "id": str(c.get("Id", ""))[:12], "proto": m.group(2), "port": int(m.group(1)),
                            "host_ip": b.get("HostIp") or "0.0.0.0", "host_port": hp, "addr4": addr4,
                            "addr6": addr6, "bridge": bridge})
    return out


# ---------------------------------------------------------------------------
# The packet filter

HEADER_RE = re.compile(r"^# Generated by ip6?tables-save v([\d.]+) \((nf_tables|legacy)\)", re.M)


def collect_rules(system, src, root):
    """The ruleset from iptables-save, ip6tables-save and nft's JSON."""
    t0 = time.monotonic()
    rs = secfw.Ruleset()
    fw = {"iptables": None, "tables": [], "legacy_rules": False}
    skip = []
    states = []
    for fam, tool in ((4, "iptables-save"), (6, "ip6tables-save")):
        res = system.run([tool], 30)
        if res.missing:
            states.append("missing")
            continue
        if not res.ok:
            states.append("needs-root" if not root else "error")
            continue
        m = HEADER_RE.search(res.out)
        variant = m.group(2) if m else None
        fw["iptables"] = fw["iptables"] or {"version": m.group(1) if m else None, "variant": variant}
        secfw.parse_iptables_save(res.out, fam, rs, "iptables")
        states.append("ok")
        if variant in ("nf_tables", None) and res.out.strip():
            skip.append("ip" if fam == 4 else "ip6")
        # Rules of iptables-legacy apply as well when its tables are loaded.
        if variant == "nf_tables":
            names = system.read("/proc/net/" + ("ip_tables_names" if fam == 4 else "ip6_tables_names"), 4096)
            if names and names.strip():
                lres = system.run([tool.replace("-save", "-legacy-save")], 30)
                if lres.ok and "-A " in lres.out:
                    secfw.parse_iptables_save(lres.out, fam, rs, "legacy")
                    fw["legacy_rules"] = True
    res = system.run(["nft", "-j", "list", "ruleset"], 30)
    if res.ok:
        try:
            secfw.parse_nft_json(json.loads(res.out), rs, skip_iptables=skip)
            states.append("ok")
        except ValueError:
            states.append("error")
    elif res.missing:
        states.append("missing")
    else:
        states.append("needs-root" if not root else "error")
    if "ok" in states:
        src.note("rules", "ok", t0, partial=",".join(sorted({s for s in states if s != "ok"})) or None)
    elif all(s == "missing" for s in states):
        src.note("rules", "missing", t0)
    else:
        src.note("rules", "needs-root" if "needs-root" in states else "error", t0)
    tables = {}
    for c in rs.chains.values():
        k = (c.src, c.family, c.table)
        t = tables.setdefault(k, {"src": c.src, "family": c.family, "table": c.table, "chains": 0, "rules": 0,
                                  "owners": set()})
        t["chains"] += 1
        t["rules"] += len(c.rules)
        o = secfw.owner(c.table, c.name)
        if o:
            t["owners"].add(o)
    fw["tables"] = [dict(t, owners=sorted(t["owners"])) for t in sorted(tables.values(), key=lambda t: (
        t["src"], t["family"], t["table"]))]
    fw["docker_user"] = {str(f): len((rs.chains.get(("iptables", "ip" if f == 4 else "ip6", "filter",
                                                      "DOCKER-USER")) or secfw.Chain("", "", "", "")).rules)
                         for f in (4, 6)}
    return rs, fw


def input_filter(rs, net, fam):
    """Whether this host filters new connections from the internet: a probe
    on a port no rule should name (tcp/64999). on, off or unknown."""
    ifaces = net[fam]["ifaces"]["internet"] or net[fam]["ifaces"]["private"]
    if not ifaces:
        return "unknown"
    iface, addr = ifaces[0]
    sample = secfw.Sample(fam, internet=True)
    pkt = secfw.Packet(fam, "tcp", iface, sample, ipaddress.ip_address(addr), PROBE_PORT, "input")
    kind, _ = secfw.Evaluator(rs).hook(pkt, pkt, ("ingress", "prerouting", "input"))
    return {"accept": "off", "drop": "on"}.get(kind, "unknown")


def collect_ufw(system, src, rs):
    t0 = time.monotonic()
    installed = system.exists("/usr/sbin/ufw") or system.exists("/etc/ufw/ufw.conf")
    if not installed:
        src.note("ufw", "missing", t0)
        return {"installed": False}
    conf = seclib.parse_kv(system.read("/etc/ufw/ufw.conf", 65536))
    default = seclib.parse_kv(system.read("/etc/default/ufw", 65536))
    rules4 = system.read("/etc/ufw/user.rules", 1 << 20)
    rules6 = system.read("/etc/ufw/user6.rules", 1 << 20)
    rules = seclib.parse_ufw_rules(rules4, 4) + seclib.parse_ufw_rules(rules6, 6)
    loaded = {"4": rs.has_chain("ufw-user-input", 4), "6": rs.has_chain("ufw6-user-input", 6)}
    src.note("ufw", "ok" if rules4 is not None else "error", t0)
    return {"installed": True, "enabled": conf.get("ENABLED", "no").lower() == "yes", "loaded": loaded,
            "ipv6": default.get("IPV6", "yes").lower() == "yes",
            "default_input": default.get("DEFAULT_INPUT_POLICY", "").lower() or None,
            "default_forward": default.get("DEFAULT_FORWARD_POLICY", "").lower() or None,
            "rules": rules[:200], "rules_total": len(rules)}


# ---------------------------------------------------------------------------
# Hetzner Cloud Firewall (written by security-hetzner.py, a service without root)

def collect_hetzner(system, src, now):
    t0 = time.monotonic()
    token = system.lstat(HETZNER_TOKEN) is not None
    if not token:
        src.note("hetzner", "skipped", t0, reason="no-token")
        return {"configured": False}
    raw = system.read(HETZNER_FILE, 4 << 20)
    if raw is None:
        src.note("hetzner", "error", t0, error="no answer yet")
        return {"configured": True, "state": "pending"}
    try:
        h = json.loads(raw)
    except ValueError:
        src.note("hetzner", "error", t0, error="unreadable")
        return {"configured": True, "state": "unreadable"}
    out = {"configured": True, "ok_at": h.get("ok_at"), "tried_at": h.get("tried_at"),
           "error": seclib.clean(h.get("error"), 160) or None, "server": h.get("server"),
           "firewalls": h.get("firewalls") or []}
    if not h.get("ok_at"):
        out["state"] = "error"
    elif h.get("error"):
        out["state"] = "stale"
    elif not h.get("server"):
        out["state"] = "not-matched"
    else:
        out["state"] = "ok"
    src.note("hetzner", "ok" if out["state"] == "ok" else "error", t0, error=out.get("error"))
    return out


def hetzner_known(h):
    return bool(h and h.get("configured") and h.get("server") and h.get("ok_at"))


def hetzner_reach(h, fam, proto, port):
    """What the Hetzner Cloud Firewall lets through to this server:
    (result, firewall/rule refs, sources); result none (no firewall applied),
    allows, restricted, blocks."""
    fws = [f for f in (h.get("firewalls") or []) if f.get("status", "applied") == "applied"]
    if not fws:
        return "none", [], []
    narrow = []
    refs = []
    for f in fws:
        for r in f.get("rules") or []:
            if r.get("direction") != "in" or r.get("protocol") != proto:
                continue
            if not _hz_port(r.get("port"), port):
                continue
            nets = []
            for s in r.get("source_ips") or []:
                try:
                    n = NET(s, strict=False)
                except ValueError:
                    continue
                if n.version == fam:
                    nets.append(n)
            ref = {"firewall": seclib.clean(f.get("name"), 80), "id": f.get("id"),
                   "rule": seclib.clean(r.get("description"), 80), "port": r.get("port")}
            if any(n.prefixlen == 0 or (fam == 6 and seclib.GLOBAL6.subnet_of(n)) for n in nets):
                return "allows", [ref], []
            pub = [str(n) for n in nets if not any(n.subnet_of(x) for x in seclib.NOT_INTERNET[fam])]
            if pub:
                narrow.extend(pub)
                refs.append(ref)
    if narrow:
        return "restricted", refs, sorted(set(narrow))
    return "blocks", [{"firewall": seclib.clean(f.get("name"), 80), "id": f.get("id")} for f in fws], []


def _hz_port(spec, port):
    if spec in (None, "", "any"):
        return True
    m = re.match(r"^(\d+)(?:-(\d+))?$", str(spec))
    if not m:
        return False
    lo, hi = int(m.group(1)), int(m.group(2) or m.group(1))
    return lo <= port <= hi


# ---------------------------------------------------------------------------
# Ports: reach from each class and the assessment (spec 4.2)

def assess_ports(rs, net, sockets, docker, hetzner, fw):
    maps = docker_mappings(docker)
    keys = sorted({(s["proto"], s["port"]) for s in sockets} | {(m["proto"], m["host_port"]) for m in maps},
                  key=lambda k: (k[1], k[0]))
    vpn_present = any(net[f]["ifaces"]["vpn"] for f in (4, 6))
    names = {str(c.get("Id")): seclib.clean(str(c.get("Name") or "").lstrip("/"), 128)
             for c in (docker or {}).get("containers") or []}
    out = []
    for proto, port in keys:
        socks = [s for s in sockets if s["proto"] == proto and s["port"] == port]
        pm = [m for m in maps if m["proto"] == proto and m["host_port"] == port]
        procs = [p for s in socks for p in s["procs"]]
        kernel = bool(socks) and not procs
        # systemd holds the socket of a socket-activated service: name the service when it runs
        if any(p["name"] != "systemd" for p in procs):
            procs = [p for p in procs if p["name"] != "systemd"]
        name, weight = seclib.known_port(proto, port, kernel=kernel, vpn=vpn_present)
        in_host_net = {names[p["container_id"]] for p in procs if p.get("container_id") in names}
        service = {"kind": "docker" if pm else "kernel" if kernel else "process",
                   "containers": sorted({m["container"] for m in pm} | in_host_net),
                   "images": sorted({m["image"] for m in pm})[:3],
                   "processes": sorted({p["name"] for p in procs})[:4],
                   "container_ports": sorted({m["port"] for m in pm})}
        binds = sorted({_bind_label(s) for s in socks} | {_map_label(m) for m in pm})
        reach = {}
        for fam in (4, 6):
            reach[str(fam)] = port_reach(rs, net, fam, proto, port, socks, pm, hetzner)
        p = {"id": f"{proto}-{port}", "proto": proto, "port": port, "name": name, "weight": weight,
             "service": service, "binds": binds, "reach": reach}
        p["state"], p["why"] = port_state(p, fw, hetzner)
        out.append(p)
    return out


def _bind_label(s):
    a = s["addr"]
    a = "[" + a + "]" if ":" in a else a
    return f"{a}{'%' + s['iface'] if s['iface'] else ''}:{s['port']}"


def _map_label(m):
    a = m["host_ip"]
    a = "[" + a + "]" if ":" in a else a
    return f"{a}:{m['host_port']}"


def _bind_classes(addr, iface, fam, net):
    """The (class, [(iface, iface address)]) a socket bound to addr (and
    perhaps an interface) receives from."""
    out = {}
    for c in CLASSES:
        cand = net[fam]["ifaces"][c]
        if iface:
            cand = [x for x in cand if x[0] == iface]
        if addr in ("*", "0.0.0.0", "::", ""):
            out[c] = cand
            continue
        try:
            a = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if a.version != fam:
            continue
        if c == "local":
            if a.is_loopback:
                out[c] = cand
            else:
                out[c] = [("lo", str(a))]      # the host reaches its own addresses
            continue
        mine = [x for x in cand if x[1] == str(a)]
        if mine:
            out[c] = mine
    return out


def port_reach(rs, net, fam, proto, port, socks, maps, hetzner):
    """Per class: result, path (input or forward) and the decisive steps."""
    entries = []
    fam_maps = [m for m in maps if seclib.family(m["host_ip"]) == fam] if maps else []
    if maps:
        for m in fam_maps:
            dn = secfw.find_dnat(rs, fam, proto, port, m["host_ip"]) if rs else None
            if dn:
                entries.append({"path": "forward", "addr": m["host_ip"], "iface": None, "to": dn, "map": m})
                continue
            proxy = [s for s in socks if fam in s["families"]]
            for s in proxy:
                entries.append({"path": "input", "addr": s["addr"], "iface": s["iface"], "map": m,
                                "proxy": True})
    else:
        for s in socks:
            if fam in s["families"]:
                entries.append({"path": "input", "addr": s["addr"], "iface": s["iface"]})
    out = {}
    if not entries:
        return {c: {"result": "absent"} for c in CLASSES}
    others = {c: [n for k, v in net[fam]["nets"].items() if k != c for n in v] for c in CLASSES}
    for c in CLASSES:
        best = None
        for e in entries:
            classes = _bind_classes(e["addr"], e["iface"], fam, net)
            ifaces = classes.get(c) or []
            if not ifaces:
                continue
            if rs is None:
                r = {"result": "unknown", "steps": [], "sources": [], "reason": "no-rules"}
            elif c == "local" and e["path"] == "forward":
                r = {"result": "open", "steps": [], "sources": [], "reason": "local-published"}
            else:
                samples = [(i, _sample(c, fam, net, others[c])) for i, _ in ifaces]
                addr_of = dict(ifaces)
                r = secfw.reach(rs, _maker(e, fam, proto, port, addr_of), samples, avoid=others[c])
            r["path"] = e["path"]
            if e.get("proxy"):
                r["proxy"] = True
            if e["path"] == "forward":
                r["to"] = {"addr": e["to"][0], "port": e["to"][1], "rule": e["to"][2].ref()}
            if best is None or STATE_OF_RESULT[r["result"]] > STATE_OF_RESULT[best["result"]]:
                best = r
        out[c] = best or {"result": "absent"}
    inet = out["internet"]
    if inet["result"] in ("open", "restricted", "unknown") and hetzner_known(hetzner):
        hz, refs, srcs = hetzner_reach(hetzner, fam, proto, port)
        inet["hetzner"] = {"result": hz, "refs": refs, "sources": srcs}
        if hz == "blocks":
            inet["host_result"] = inet["result"]
            inet["result"] = "closed"
        elif hz == "restricted":
            inet["host_result"] = inet["result"]
            if inet["result"] != "unknown":
                inet["result"] = "restricted"
                inet["sources"] = sorted(set(inet.get("sources") or []) | set(srcs))
    for c in CLASSES:
        out[c].pop("denied_steps", None)
        _trim(out[c])
    return out


def _trim(r):
    """Keeps the steps short: the base chains that decided."""
    steps = r.get("steps") or []
    r["steps"] = [s for s in steps if s["result"] != "accept" or s["rule"] or s.get("policy")][:6]


def _sample(c, fam, net, avoid):
    if c == "internet":
        return secfw.Sample(fam, internet=True, avoid=avoid)
    nets = net[fam]["nets"][c]
    return secfw.Sample(fam, net=nets[0] if nets else NET("127.0.0.0/8" if fam == 4 else "::1/128"), avoid=avoid)


def _maker(e, fam, proto, port, addr_of):
    def make(iface, sample):
        if sample.internet is False and iface == "lo":
            pass
        host = e["addr"] if e["addr"] not in ("*", "0.0.0.0", "::", "") else addr_of.get(iface)
        dst = ipaddress.ip_address(host)
        pre = secfw.Packet(fam, proto, iface, sample, dst, port, "input")
        if e["path"] == "input":
            return pre, pre, ("ingress", "prerouting", "input")
        to_addr, to_port, _ = e["to"]
        bridge = (e.get("map") or {}).get("bridge")
        post = secfw.Packet(fam, proto, iface, sample, ipaddress.ip_address(to_addr), to_port, "forward",
                            oif=bridge, orig_dst=dst, orig_dport=port, dnat=True)
        return pre, post, ("ingress", "prerouting", "forward")
    return make


def port_state(p, fw, hetzner):
    """The state of a port before marks (spec 4.2) and why."""
    results = {f: p["reach"][f]["internet"]["result"] for f in ("4", "6")}
    if "open" in results.values():
        fams = [f for f, r in results.items() if r == "open"]
        if not hetzner_known(hetzner) and all(fw.get("input_filter", {}).get(int(f)) == "off" for f in fams):
            return "warning", "outside-only"
        return p["weight"], "public-" + {"danger": "danger", "info": "expected", "warning": "other"}[p["weight"]]
    if "restricted" in results.values():
        return ("warning" if p["weight"] == "danger" else "info"), "restricted"
    if "unknown" in results.values():
        return "none", "unknown"
    blocked = any(p["reach"][f]["internet"].get("hetzner", {}).get("result") == "blocks" for f in ("4", "6"))
    if blocked:
        return "ok", "hetzner"
    others = [c for c in ("vpn", "private") if any(p["reach"][f][c]["result"] in ("open", "restricted")
                                                   for f in ("4", "6"))]
    return "ok", ("only-" + "-".join(others)) if others else "local"


# ---------------------------------------------------------------------------
# SSH (spec 4.3)

def collect_sshd(system, src, root):
    t0 = time.monotonic()
    if not system.exists("/usr/sbin/sshd"):
        src.note("sshd", "missing", t0)
        return None
    res = system.run(["/usr/sbin/sshd", "-T"], 20)
    files = []
    for path in ["/etc/ssh/sshd_config"] + ["/etc/ssh/sshd_config.d/" + n for n in
                                            (system.listdir("/etc/ssh/sshd_config.d") or []) if n.endswith(".conf")]:
        text = system.read(path, 1 << 20)
        if text is not None:
            files.append((path, text))
    match = [p for p, t in files if seclib.has_match_block(t)]
    if not res.ok:
        if res.missing:
            src.note("sshd", "missing", t0)
            return None
        reason, msg = seclib.sshd_error(res.err or res.out)
        if not root and reason == "error":
            src.note("sshd", "needs-root", t0)
            return {"state": "skipped", "reason": "needs-root", "match": match}
        src.note("sshd", "error", t0, error=msg, reason=reason)
        return {"state": "error", "reason": reason, "error": msg, "match": match}
    src.note("sshd", "ok", t0)
    cfg = seclib.parse_sshd_t(res.out)
    return {"state": "ok", "config": cfg, "match": match}


def collect_keys(system, src, root, sshd):
    t0 = time.monotonic()
    passwd = system.read("/etc/passwd", 4 << 20)
    if passwd is None:
        src.note("keys", "error", t0, error="/etc/passwd not readable")
        return None
    spec = ((sshd or {}).get("config") or {}).get("authorizedkeysfile")
    out = []
    unreadable = 0
    for name, uid, home in seclib.login_accounts(passwd):
        for path in seclib.key_files(spec, name, home):
            text, st = system.read_user_file(path)
            if st is None:
                continue
            if text is None:
                if stat.S_ISLNK(st.st_mode):
                    out.append({"user": seclib.clean(name, 40), "file": path, "problems": ["link"], "keys": []})
                else:
                    unreadable += 1
                continue
            parent = system.stat(os.path.dirname(path))
            problems = seclib.file_problems(st, uid, parent)
            keys = seclib.parse_authorized_keys(text)
            out.append({"user": seclib.clean(name, 40), "file": path, "mode": oct(st.st_mode & 0o777)[2:],
                        "problems": problems, "keys": keys[:100]})
    if not root and unreadable:
        src.note("keys", "partial", t0, missing="other-users")
    else:
        src.note("keys", "ok", t0)
    return out


def assess_ssh(sshd, keys):
    findings = []
    if sshd and sshd.get("state") == "ok":
        findings = seclib.assess_sshd(sshd["config"])
    key_states = []
    for f in keys or []:
        f["state"] = "warning" if f["problems"] else "ok"
        for k in f["keys"]:
            k["state"] = max((x["state"] for x in k["findings"]), key=ORDER.get, default="ok")
            key_states.append(k["state"])
        f["state"] = max([f["state"]] + [k["state"] for k in f["keys"]], key=ORDER.get)
    state_cfg = max((x["state"] for x in findings), key=ORDER.get, default="none")
    state_keys = max([f["state"] for f in keys or []], key=ORDER.get, default="ok" if keys is not None else "none")
    out = {"sshd": {k: v for k, v in (sshd or {"state": "missing"}).items() if k != "config"},
           "findings": findings, "keys": keys if keys is not None else None,
           "counts": {"keys": len(key_states), "files": len(keys or [])}}
    if sshd and sshd.get("config"):
        cfg = sshd["config"]
        out["ports"] = [v for v in cfg.get("port", [])][:8]
        out["listen"] = [v for v in cfg.get("listenaddress", [])][:8]
    out["state"] = max([state_cfg, state_keys], key=ORDER.get) if (findings or keys) else "none"
    return out


# ---------------------------------------------------------------------------
# Logins of the last 14 days

def collect_logins(system, src, root, ifaces):
    t0 = time.monotonic()
    argv = ["journalctl", "-o", "json", "--no-pager", "-q", "--since=-14d", "-n", "100000",
            "--output-fields=MESSAGE,SYSLOG_IDENTIFIER,_PID,__REALTIME_TIMESTAMP",
            "SYSLOG_IDENTIFIER=sshd", "SYSLOG_IDENTIFIER=sshd-session", "SYSLOG_IDENTIFIER=sudo",
            "SYSLOG_IDENTIFIER=cockpit-session"]
    res = system.run(argv, 90)
    if res.missing:
        src.note("journal", "missing", t0)
        return {"state": "skipped", "reason": "tool-missing"}
    if res.timeout:
        src.note("journal", "timeout", t0)
        return {"state": "timeout"}
    if res.rc not in (0, 1):
        src.note("journal", "error", t0, error=seclib.clean(res.err, 160))
        return {"state": "error"}
    data = seclib.parse_journal(res.out, seclib.vpn_networks(ifaces))
    if not root:
        src.note("journal", "partial", t0, missing="other-users")
    else:
        src.note("journal", "ok", t0)
    outside = [s for s in data["success"] if s["class"] not in (None, "vpn", "private", "local", "link")]
    data["outside"] = len(outside)
    data["state"] = "ok"
    data["truncated"] = data["entries"] >= 100000
    for s in data["success"]:
        s["time"] = iso_ts(s.pop("ts"))
    for f in data["failed"]:
        f["last"] = iso_ts(f["last"])
    for s in data["sudo"]:
        s["last"] = iso_ts(s["last"])
    data["assessment"] = "warning" if outside else "ok"
    return data


# ---------------------------------------------------------------------------
# Containers (spec 4.4)

HOST_DIRS = ("/", "/etc", "/root", "/var/run", "/run")
CAPS = {"SYS_ADMIN", "NET_ADMIN", "ALL"}


def container_findings(c):
    hc = c.get("HostConfig") or {}
    cfg = c.get("Config") or {}
    out = []
    for m in c.get("Mounts") or []:
        srcp = str(m.get("Source") or "")
        dst = str(m.get("Destination") or "")
        if srcp.endswith("/docker.sock") or dst.endswith("/docker.sock"):
            out.append({"kind": "docker-socket", "state": "danger",
                        "detail": seclib.clean(srcp + ("" if m.get("RW") else ":ro"), 160)})
        elif m.get("Type") == "bind" and os.path.normpath(srcp or "/") in HOST_DIRS and m.get("RW"):
            out.append({"kind": "host-mount", "state": "warning", "detail": seclib.clean(f"{srcp}:{dst}", 160)})
    if hc.get("Privileged"):
        out.append({"kind": "privileged", "state": "warning"})
    if hc.get("PidMode") == "host":
        out.append({"kind": "pid-host", "state": "warning"})
    caps = sorted({str(x).upper().replace("CAP_", "") for x in hc.get("CapAdd") or []} & CAPS)
    if caps:
        out.append({"kind": "cap-add", "state": "warning", "detail": ", ".join(caps)})
    if hc.get("NetworkMode") == "host":
        out.append({"kind": "network-host", "state": "info"})
    user = str(cfg.get("User") or "")
    if user.split(":")[0] in ("", "root", "0"):
        out.append({"kind": "root-user", "state": "info"})
    sec = [str(x) for x in hc.get("SecurityOpt") or []]
    if not any(re.match(r"^no-new-privileges([:=]true)?$", x) for x in sec):
        out.append({"kind": "no-new-privileges", "state": "info"})
    if c.get("AppArmorProfile") == "unconfined" or any(re.match(r"^apparmor[:=]unconfined$", x) for x in sec):
        out.append({"kind": "apparmor-unconfined", "state": "info"})
    return out


def assess_containers(docker):
    if not docker:
        return {"state": "skipped", "items": []}
    items = []
    for c in docker["containers"]:
        items.append({"name": seclib.clean(str(c.get("Name") or "").lstrip("/"), 128),
                      "image": seclib.clean((c.get("Config") or {}).get("Image"), 200),
                      "findings": container_findings(c)})
    items.sort(key=lambda i: i["name"])
    return {"state": "ok", "items": items}


# ---------------------------------------------------------------------------
# CrowdSec (spec 4.5): only shown

BOUNCER_CONF = "/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml"


def collect_crowdsec(system, src, root):
    t0 = time.monotonic()
    if not system.exists("/usr/bin/cscli"):
        src.note("crowdsec", "missing", t0)
        return None
    out = {"installed": True}
    act = system.run(["systemctl", "is-active", "crowdsec.service"], 10)
    out["active"] = act.out.strip() or None
    ver = system.run(["cscli", "version"], 20)
    out["version"] = ".".join(map(str, seclib.version_tuple(ver.out + ver.err) or ())) or None
    for key, argv in (("decisions", ["cscli", "decisions", "list", "-o", "json"]),
                      ("alerts", ["cscli", "alerts", "list", "-o", "json", "--since", "14d"]),
                      ("bouncers", ["cscli", "bouncers", "list", "-o", "json"])):
        res = system.run(argv, 30)
        out[key] = seclib.parse_json_list(res.out) if res.ok else None
        if not res.ok:
            out[key + "_error"] = seclib.clean((res.err or res.out).strip().splitlines()[-1] if (res.err or res.out)
                                               .strip() else f"exit {res.rc}", 160)
    conf = system.read(BOUNCER_CONF, 1 << 20)
    out["bouncer_conf"] = seclib.yaml_keys(conf, ("mode", "nftables_hooks", "iptables_chains")) if conf else None
    creds = system.read("/etc/crowdsec/online_api_credentials.yaml", 65536)
    cfg = system.read("/etc/crowdsec/config.yaml", 1 << 20) or ""
    shared = bool(creds and re.search(r"(?m)^\s*login:\s*\S", creds))
    if re.search(r"(?m)^\s*sharing:\s*false\b", cfg):
        shared = False
    out["sharing"] = shared
    if not root and any(out.get(k) is None for k in ("decisions", "alerts", "bouncers")):
        src.note("crowdsec", "needs-root", t0)
    else:
        src.note("crowdsec", "ok" if all(out.get(k) is not None for k in ("decisions", "alerts", "bouncers"))
                 else "partial", t0)
    return out


def assess_crowdsec(cs, docker, rs):
    if not cs:
        return {"installed": False}
    findings = []
    v = tuple(int(x) for x in (cs.get("version") or "0.0.0").split(".")) if cs.get("version") else None
    if v and v < (1, 5, 0):
        findings.append({"code": "old-engine", "state": "warning", "value": cs.get("version")})
    if cs.get("active") not in ("active", None):
        findings.append({"code": "not-running", "state": "warning", "value": cs.get("active")})
    published = bool(docker_mappings(docker))
    bouncers = []
    for b in cs.get("bouncers") or []:
        if not isinstance(b, dict):
            continue
        bouncers.append({"name": seclib.clean(b.get("name"), 80), "type": seclib.clean(b.get("type"), 80),
                         "version": seclib.clean(b.get("version"), 40), "last_pull": b.get("last_pull"),
                         "revoked": bool(b.get("revoked"))})
    conf = cs.get("bouncer_conf")
    fw_bouncer = any("firewall" in (b["type"] or "") for b in bouncers) or conf is not None
    if fw_bouncer and conf is not None and published:
        mode = str(conf.get("mode") or "").lower()
        hooks = [str(x).lower() for x in conf.get("nftables_hooks") or []] if isinstance(
            conf.get("nftables_hooks"), list) else []
        chains = [str(x) for x in conf.get("iptables_chains") or []] if isinstance(
            conf.get("iptables_chains"), list) else []
        if mode == "nftables" and "forward" not in hooks:
            findings.append({"code": "bouncer-input-only", "state": "warning", "value": "nftables"})
        elif mode == "iptables" and "DOCKER-USER" not in chains:
            findings.append({"code": "bouncer-no-docker-user", "state": "warning", "value": "iptables"})
    decisions = []
    for a in cs.get("decisions") or []:
        if not isinstance(a, dict):
            continue
        for d in a.get("decisions") or []:
            if isinstance(d, dict):
                decisions.append({"value": seclib.clean(d.get("value"), 60), "scope": seclib.clean(d.get("scope"),
                                                                                                    20),
                                  "type": seclib.clean(d.get("type"), 20), "scenario": seclib.clean(
                                      d.get("scenario"), 80), "origin": seclib.clean(d.get("origin"), 20),
                                  "duration": seclib.clean(d.get("duration"), 30),
                                  "country": seclib.clean((a.get("source") or {}).get("cn"), 4)})
    scenarios = {}
    for a in cs.get("alerts") or []:
        if isinstance(a, dict):
            s = seclib.clean(a.get("scenario"), 80) or "?"
            scenarios[s] = scenarios.get(s, 0) + 1
    out = {"installed": True, "active": cs.get("active"), "version": cs.get("version"), "sharing": cs.get("sharing"),
           "bouncers": bouncers[:20], "bouncer_conf": conf, "decisions": decisions[:50],
           "decisions_total": len(decisions), "alerts_total": sum(scenarios.values()),
           "scenarios": [{"scenario": k, "count": n} for k, n in sorted(scenarios.items(), key=lambda x: -x[1])][:15],
           "findings": findings,
           "errors": {k: cs[k + "_error"] for k in ("decisions", "alerts", "bouncers") if cs.get(k + "_error")}}
    if any(b["revoked"] for b in bouncers):
        pass
    if not bouncers and cs.get("bouncers") is not None:
        findings.append({"code": "no-bouncer", "state": "warning"})
    out["state"] = max((f["state"] for f in findings), key=ORDER.get, default="ok")
    return out


# ---------------------------------------------------------------------------
# Marks: findings marked as expected

def read_marks(system):
    """(marks, problem): the file counts only when it belongs to root and
    nobody else can write it."""
    st = system.lstat(MARKS_FILE)
    empty = {"ports": {}, "containers": {}}
    if st is None:
        return empty, None
    if not seclib.trusted_file(st):
        return empty, "untrusted"
    marks, errors = seclib.parse_marks(system.read(MARKS_FILE, 1 << 20) or "")
    return marks, ("lines " + ",".join(map(str, errors[:10]))) if errors else None


def view(doc, marks):
    """The state with the marks applied: a marked port is info (public,
    expected), a marked container finding no longer counts."""
    v = copy.deepcopy(doc)
    for p in v.get("ports") or []:
        key = f"{p['port']}/{p['proto']}"
        if key in marks["ports"]:
            p["expected"] = marks["ports"][key]
            if ORDER.get(p["state"], 0) >= ORDER["info"] or p["state"] == "none":
                p["base_state"] = p["state"]
                p["state"] = "info"
    for c in (v.get("containers") or {}).get("items") or []:
        for f in c["findings"]:
            note = marks["containers"].get((c["name"], f["kind"]))
            if note is not None:
                f["expected"] = note
                f["base_state"] = f["state"]
                f["state"] = "ok"
        c["state"] = max((f["state"] for f in c["findings"]), key=ORDER.get, default="ok")
    return v
