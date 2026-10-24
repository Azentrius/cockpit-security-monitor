# SPDX-License-Identifier: Apache-2.0
"""Every check of Security Monitor: what is reachable from where, the SSH
configuration and keys, the logins of the last 14 days, the hardening of the
containers and, when installed, CrowdSec and fail2ban.

Lives in /usr/lib/cockpit-security-monitor (root-owned). Standard library
only. Reads only: the commands are listings (ip, ss, iptables-save, nft,
sshd -T, journalctl, cscli, fail2ban-client status and -d), fail2ban's
database is opened read-only, Docker is asked with GET only, files are read
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
import secstatus

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

    def sqlite_ro(self, path, queries, limit=1000):
        """Rows of a few queries against an SQLite file opened read-only
        (fail2ban's database): ({name: rows}, None) or (None, error)."""
        import sqlite3
        from urllib.parse import quote
        try:
            con = sqlite3.connect(f"file:{quote(path)}?mode=ro", uri=True, timeout=5)
        except sqlite3.Error as e:
            return None, str(e)
        try:
            out = {}
            for name, query, args in queries:
                out[name] = [list(r) for r in con.execute(query, args).fetchmany(limit)]
            return out, None
        except sqlite3.Error as e:
            return None, str(e)
        finally:
            con.close()

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

def scan(system=None, previous=None):
    """The state of this host. `previous`: the last state (or None), whose
    `first_seen` is carried over (secstatus.first_seen)."""
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
    f2b = collect_fail2ban(system, src, root, now)

    net = network(ifaces)
    # Without the addresses nothing says which classes a socket receives from: no public address
    # is then "not known" (null), never "none".
    addrs_ok = src.items.get("ip", {}).get("state") == "ok"
    fw["input_filter"] = {f: input_filter(rs, net, f) if src.items.get("rules", {}).get("state") == "ok" else
                          "unknown" for f in (4, 6)}
    fw["ufw"] = ufw
    fw["docker"] = docker["summary"] if docker else None
    fw["hetzner"] = hetzner
    doc["network"] = {"interfaces": [i for i in ifaces if i["kind"] != "container"] if ifaces else [],
                      "public": {str(f): bool(net[f]["internet"]) if addrs_ok else None for f in (4, 6)}}
    doc["firewall"] = fw
    rules_ok = src.items.get("rules", {}).get("state") == "ok"
    # Docker answered, or is not there: what it publishes is known. Its socket without an answer
    # (error, needs-root): a socket may be a port it publishes, whose mapping is not known.
    docker_read = src.items.get("docker", {}).get("state") in ("ok", "missing")
    doc["ports"] = assess_ports(rs if rules_ok else None, net, sockets or [], docker, hetzner, fw, addrs_ok,
                                docker_read)
    doc["ssh"] = assess_ssh(sshd, keys)
    doc["logins"] = logins
    doc["containers"] = assess_containers(docker)
    doc["crowdsec"] = assess_crowdsec(crowd, docker, rs if rules_ok else None)
    doc["fail2ban"] = assess_fail2ban(f2b, docker, rs if rules_ok else None, doc["ports"], now)
    doc["sources"] = src.items
    # When each port the internet reaches was first seen: kept from the last state.
    doc["first_seen"] = secstatus.first_seen(doc, previous.get("first_seen") if isinstance(previous, dict) else None)
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
    # A firewall applied to the server but missing from the API's answer: its rules are not known.
    unknown = [f for f in out["firewalls"] if isinstance(f, dict) and f.get("status", "applied") == "applied"
               and not isinstance(f.get("rules"), list)]
    if out["state"] == "ok" and unknown:
        src.note("hetzner", "partial", t0, missing="rules")
    else:
        src.note("hetzner", "ok" if out["state"] == "ok" else "error", t0, error=out.get("error"))
    return out


def hetzner_known(h):
    return bool(h and h.get("configured") and h.get("server") and h.get("ok_at"))


def _hz_ref(f):
    return {"firewall": seclib.clean(f.get("name"), 80), "id": f.get("id")}


def hetzner_reach(h, fam, proto, port):
    """What the Hetzner Cloud Firewall lets through to this server:
    (result, firewall/rule refs, sources); result none (no firewall applied),
    allows, restricted, blocks or unknown.

    Hetzner joins the incoming rules of every firewall applied: a connection
    passes when one rule of one of them lets it in, and a firewall without
    incoming rules ([]) lets nothing in. A firewall whose rules are not known
    (`rules` null: missing from the API's answer) may hold such a rule, so it
    never counts as protection: the answer is then unknown, its refs those
    firewalls. Only a known rule that lets the whole internet in still
    decides (allows), as it claims no protection."""
    fws = [f for f in (h.get("firewalls") or []) if isinstance(f, dict) and f.get("status", "applied") == "applied"]
    if not fws:
        return "none", [], []
    narrow = []
    refs = []
    unknown = []
    for f in fws:
        if not isinstance(f.get("rules"), list):
            unknown.append(_hz_ref(f))
            continue
        for r in f["rules"]:
            if not isinstance(r, dict) or r.get("direction") != "in" or r.get("protocol") != proto:
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
    if unknown:
        return "unknown", unknown, []
    if narrow:
        return "restricted", refs, sorted(set(narrow))
    return "blocks", [_hz_ref(f) for f in fws], []


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

def assess_ports(rs, net, sockets, docker, hetzner, fw, addrs=True, docker_read=True):
    """Every listening socket and published port with its reach and state.
    `addrs` False: `ip -j addr` failed, so the classes other than this host
    are unknown for every socket not on the loopback. `docker_read` False:
    Docker did not answer, so a socket that may be a port it publishes is
    unknown from the other classes (see port_reach)."""
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
            reach[str(fam)] = port_reach(rs, net, fam, proto, port, socks, pm, hetzner, addrs, docker_read)
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


def _loopback(addr):
    try:
        return ipaddress.ip_address(addr).is_loopback
    except ValueError:
        return False


def port_reach(rs, net, fam, proto, port, socks, maps, hetzner, addrs=True, docker_read=True):
    """Per class: result, path (input or forward) and the decisive steps;
    for restricted also the step that stops the rest of the class. Without
    the addresses (`addrs` False) the internet, the VPN and the private
    network are unknown (reason no-addresses), except for a socket on the
    loopback, which they never reach. When Docker did not answer
    (`docker_read` False), a socket of docker-proxy, or one on a port a DNAT
    rule names, may be a port Docker publishes: a new connection may be
    forwarded to a container past the input rules, and where to is not
    known. Those classes are then unknown (reason no-docker), never judged
    by the input rules; this host is judged as before."""
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
        dnat = not docker_read and rs is not None and _dnat_names(rs, fam, proto, port)
        for s in socks:
            if fam in s["families"]:
                e = {"path": "input", "addr": s["addr"], "iface": s["iface"]}
                if not docker_read and (dnat or any(p["name"] == "docker-proxy" for p in s["procs"])):
                    e["no_docker"] = True
                entries.append(e)
    out = {}
    if not entries:
        return {c: {"result": "absent"} for c in CLASSES}
    others = {c: [n for k, v in net[fam]["nets"].items() if k != c for n in v] for c in CLASSES}
    for c in CLASSES:
        best = None
        for e in entries:
            classes = _bind_classes(e["addr"], e["iface"], fam, net)
            ifaces = classes.get(c) or []
            if not addrs and c != "local":
                if _loopback(e["addr"]):
                    continue
                r = {"result": "unknown", "steps": [], "sources": [], "reason": "no-addresses"}
            elif not ifaces:
                continue
            elif rs is None:
                r = {"result": "unknown", "steps": [], "sources": [], "reason": "no-rules"}
            elif e.get("no_docker") and c != "local":
                r = {"result": "unknown", "steps": [], "sources": [], "reason": "no-docker"}
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
        # unknown (a firewall's rules missing): the host's result stands, as without an answer.
    for c in CLASSES:
        _trim(out[c])
    return out


def _dnat_names(rs, fam, proto, port):
    """Whether a DNAT rule of the family names the port, as Docker writes one
    for a port it publishes (whatever the destination address)."""
    return any(d["family"] == fam and d["proto"] in (None, proto) and d["ports"]
               and any(lo <= port <= hi for lo, hi in d["ports"]) for d in rs.dnat)


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


def _hetzner_answer(p, f, hetzner):
    """Whether the Hetzner Cloud Firewall answered for this port and family:
    not without a known answer, nor when the rules of a firewall are missing."""
    hz = p["reach"][f]["internet"].get("hetzner") or {}
    return hetzner_known(hetzner) and hz.get("result") != "unknown"


def port_state(p, fw, hetzner):
    """The state of a port before marks (spec 4.2) and why."""
    results = {f: p["reach"][f]["internet"]["result"] for f in ("4", "6")}
    if "open" in results.values():
        fams = [f for f, r in results.items() if r == "open"]
        if all(fw.get("input_filter", {}).get(int(f)) == "off" and not _hetzner_answer(p, f, hetzner) for f in fams):
            return "warning", "outside-only"
        return p["weight"], "public-" + {"danger": "danger", "info": "expected", "warning": "other"}[p["weight"]]
    if "restricted" in results.values():
        return ("warning" if p["weight"] == "danger" else "info"), "restricted"
    if "unknown" in results.values():
        return "none", "unknown"
    blocked = any(p["reach"][f]["internet"].get("hetzner", {}).get("result") == "blocks" for f in ("4", "6"))
    if blocked:
        return "ok", "hetzner"
    # A class whose reach is not known may reach it: never "this host only" then.
    others = [c for c in ("vpn", "private") if any(p["reach"][f][c]["result"] in ("open", "restricted", "unknown")
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
    # Only root can read /etc/shadow; without it nothing is said about locked accounts.
    accounts = seclib.parse_shadow(system.read("/etc/shadow", 4 << 20)) if root else {}
    today = int(system.now().timestamp() // 86400)
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
            entry = {"user": seclib.clean(name, 40), "file": path, "mode": oct(st.st_mode & 0o777)[2:],
                     "problems": problems, "keys": keys[:100]}
            acct = accounts.get(name)
            if acct:
                entry["account"] = {"password": acct["password"],
                                    "expired": acct["expire"] is not None and acct["expire"] <= today}
            out.append(entry)
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
    cfg = (sshd or {}).get("config") if (sshd or {}).get("state") == "ok" else None
    usepam = ((cfg or {}).get("usepam") or [""])[0].lower()
    for f in keys or []:
        f["state"] = "warning" if f["problems"] else "ok"
        for k in f["keys"]:
            k["state"] = max((x["state"] for x in k["findings"]), key=ORDER.get, default="ok")
            key_states.append(k["state"])
        f["state"] = max([f["state"]] + [k["state"] for k in f["keys"]], key=ORDER.get)
        # passwd -l closes the password only: with UsePAM, sshd does not check the lock, and the
        # keys still log in. Without PAM sshd refuses a locked account itself. root with a locked
        # password and keys is how Ubuntu sets up root, and "root may log in" says that already.
        acct = f.get("account")
        if acct and acct["password"] == "locked" and not acct["expired"] and f["keys"] \
                and f["user"] != "root" and usepam != "no":
            acct["finding"] = "locked-with-keys"
            f["state"] = max([f["state"], "warning"], key=ORDER.get)
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
    # Where the journal begins within the 14 days: rotation can leave fewer (journalctl
    # --lines=+N, the oldest entries, needs systemd 254 or newer; else unknown).
    first = system.run(["journalctl", "-o", "json", "--no-pager", "-q", "--since=-14d", "--lines=+1",
                        "--output-fields=__REALTIME_TIMESTAMP"], 30)
    data["journal_start"] = iso_ts(seclib.journal_first(first.out)) if first.ok else None
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
# fail2ban (spec 5.3): only shown

F2B_CLIENT = "/usr/bin/fail2ban-client"
F2B_DB = "/var/lib/fail2ban/fail2ban.sqlite3"
F2B_DB_RE = re.compile(r"^/var/lib/[A-Za-z0-9_./-]{1,200}$")
F2B_PERSIST = ("/etc/iptables/rules.v4", "/etc/iptables/rules.v6")
F2B_PERSIST_RE = re.compile(r"(?m)^(:f2b-|-A f2b-|-A \S+ .*-j f2b-)")
F2B_MAX_JAILS = 30
F2B_HISTORY_DAYS = 14
F2B_IDLE_DAYS = 3
# What the assessment needs (a part missing leaves it "not checked", never OK), in this order;
# "jails" stands for `status JAIL` failing for a jail, "skipped" for running jails past the first
# F2B_MAX_JAILS, which are not asked. The database is optional: without it only the history of
# bans is missing.
F2B_ESSENTIAL = ("ping", "config", "status")


def parse_systemd_time(text):
    """`ActiveEnterTimestamp` as systemctl prints it with TZ=UTC: ISO time or None."""
    m = re.search(r"(\d{4}-\d\d-\d\d) (\d\d:\d\d:\d\d)", text or "")
    return f"{m.group(1)}T{m.group(2)}Z" if m else None


def collect_fail2ban(system, src, root, now):
    t0 = time.monotonic()
    if not system.exists(F2B_CLIENT):
        src.note("fail2ban", "missing", t0)
        return None
    out = {"installed": True, "jails": {}, "logs": {}}
    unit = system.run(["systemctl", "show", "fail2ban.service", "-p", "ActiveState", "-p", "UnitFileState",
                       "-p", "ActiveEnterTimestamp"], 10)
    kv = seclib.parse_kv(unit.out) if unit.ok else {}
    out["active"] = seclib.clean(kv.get("ActiveState"), 20) or None
    out["unit_file"] = seclib.clean(kv.get("UnitFileState"), 20) or None
    out["since"] = parse_systemd_time(kv.get("ActiveEnterTimestamp")) if out["active"] == "active" else None
    ver = system.run([F2B_CLIENT, "--version"], 15)
    out["version"] = ".".join(map(str, seclib.version_tuple(ver.out + ver.err) or ())) or None
    errors = {}
    ping = system.run([F2B_CLIENT, "ping"], 15)
    out["running"] = bool(ping.ok and "pong" in ping.out)
    # No answer while systemd says the unit is active (or a call that hangs): whether fail2ban
    # runs is not known, which is not the same as "not running".
    if not out["running"] and (out["active"] == "active" or ping.timeout):
        errors["ping"] = _f2b_error(ping)
    dump = system.run([F2B_CLIENT, "-d"], 30)
    out["config"] = seclib.parse_f2b_dump(dump.out) if dump.ok else None
    if not dump.ok:
        errors["config"] = _f2b_error(dump)
    out["names"] = None          # the jails fail2ban runs, from `status`; None when not known
    out["jail_errors"] = {}      # jail -> why `status JAIL` failed
    if out["running"]:
        st = system.run([F2B_CLIENT, "status"], 15)
        names = seclib.parse_f2b_status(st.out) if st.ok else None
        if names is None:
            errors["status"] = _f2b_error(st)
        out["names"] = names
        # At most F2B_MAX_JAILS jails are asked; the rest have no answer of their own.
        for name in (names or [])[:F2B_MAX_JAILS]:
            r = system.run([F2B_CLIENT, "status", name], 15)
            js = seclib.parse_f2b_jail_status(r.out) if r.ok else None
            if js:
                out["jails"][name] = js
            else:
                out["jail_errors"][name] = _f2b_error(r)
    # The log files the jails read: there, size and age (journal-backed jails have none).
    paths = set()
    for j in ((out["config"] or {}).get("jails") or {}).values():
        if not str(j.get("backend") or "").startswith("systemd"):
            paths.update(j.get("logpaths") or [])
    for j in out["jails"].values():
        paths.update(j.get("files") or [])
    for p in sorted(paths)[:100]:
        st = system.lstat(p)
        out["logs"][p] = {"exists": st is not None, "size": getattr(st, "st_size", None) if st else None,
                          "mtime": iso_ts(getattr(st, "st_mtime", None)) if st else None}
    # Bans and their history from fail2ban's database, opened read-only.
    dbfile = ((out["config"] or {}).get("global") or {}).get("dbfile") or F2B_DB
    if dbfile and F2B_DB_RE.match(dbfile) and ".." not in dbfile:
        since = int(now.timestamp()) - F2B_HISTORY_DAYS * 86400
        rows, err = system.sqlite_ro(dbfile, [
            ("bips", "SELECT ip, jail, timeofban, bantime, bancount FROM bips ORDER BY timeofban DESC LIMIT 500", ()),
            ("history", "SELECT jail, COUNT(*), MAX(timeofban) FROM bans WHERE timeofban >= ? GROUP BY jail",
             (since,))])
        out["db"] = rows
        if err:
            errors["db"] = seclib.clean(err, 160)
    else:
        out["db"] = None
    out["persisted"] = [p for p in F2B_PERSIST if F2B_PERSIST_RE.search(system.read(p, 4 << 20) or "")]
    out["services"] = seclib.parse_services(system.read("/etc/services", 1 << 20))
    out["errors"] = errors
    missing = [k for k in F2B_ESSENTIAL if k in errors] + (["jails"] if out["jail_errors"] else []) + \
        (["skipped"] if len(out["names"] or []) > F2B_MAX_JAILS else []) + (["db"] if "db" in errors else [])
    if not root and not out["running"]:
        src.note("fail2ban", "needs-root", t0)
    else:
        src.note("fail2ban", "partial" if missing else "ok", t0, missing=",".join(missing) or None,
                 error=next(iter(list(errors.values()) + list(out["jail_errors"].values())), None))
    return out


def _f2b_error(res):
    """Why a call of fail2ban-client gave no usable answer, in short."""
    if res.missing:
        return "fail2ban-client not found"
    if res.timeout:
        return "timed out"
    if res.ok:
        return "unexpected answer"
    msg = (res.err or res.out or "").strip().splitlines()
    return seclib.clean(msg[-1] if msg else f"exit {res.rc}", 160)


def _f2b_addr(e):
    """An address of an nft set element as nft's JSON gives it."""
    if isinstance(e, dict):
        if "prefix" in e and isinstance(e["prefix"], dict):
            return f"{e['prefix'].get('addr')}/{e['prefix'].get('len')}"
        if "elem" in e and isinstance(e["elem"], dict):
            return _f2b_addr(e["elem"].get("val"))
        return None
    return str(e) if e is not None else None


def _norm_addr(text):
    try:
        n = ipaddress.ip_network(str(text), strict=False)
    except ValueError:
        return None
    return str(n.network_address) if n.prefixlen == n.max_prefixlen else str(n)


def f2b_firewall(rs):
    """What the packet filter holds of fail2ban: {"chains": {name: {"from": [...],
    "addrs": set}}, "sets": {jail: set}, "hooks": {chain: hook}}."""
    out = {"chains": {}, "sets": {}, "hooks": {}}
    if rs is None:
        return out
    for c in rs.chains.values():
        if secfw.owner(c.table, c.name) == "fail2ban":
            entry = out["chains"].setdefault(c.name, {"from": set(), "addrs": set()})
            if c.hook:
                out["hooks"][c.name] = c.hook
            for r in c.rules:
                for kind, neg, value in r.matches:
                    if kind == "saddr" and not neg:
                        for n in value:
                            a = _norm_addr(n)
                            if a:
                                entry["addrs"].add(a)
        for r in c.rules:
            if r.target and str(r.target).startswith("f2b-"):
                out["chains"].setdefault(r.target, {"from": set(), "addrs": set()})["from"].add(c.name)
    for (fam, table, name), elems in rs.sets.items():
        if table == "f2b-table" and str(name).startswith("addr-set-"):
            addrs = {_norm_addr(_f2b_addr(e)) for e in elems or []}
            out["sets"].setdefault(name[len("addr-set-"):], set()).update(a for a in addrs if a)
    return out


def f2b_action(a, jail, fwinfo, services):
    """Where an action bans: kind (iptables, nftables, other), the chains or
    hook, whether that is in front of Docker's forwarding, ports and protocols."""
    name, o = a["name"], a.get("opts") or {}
    plain = {k: v for k, v in o.items() if "<" not in v and "%(" not in v}
    allports = "allports" in name or str(plain.get("port", "")).strip() in ("0:65535", "1:65535")
    ranges = None if allports else seclib.f2b_ports(plain.get("port"), services)
    protocols = sorted({p.strip() for p in re.split(r"[,\s]+", plain.get("protocol") or "tcp") if p.strip()})
    out = {"name": name, "port": plain.get("port"), "protocols": protocols, "allports": allports,
           "ranges": ranges, "kind": "other", "where": [], "forward": None, "observed": False}
    chain_name = "f2b-" + (plain.get("name") or jail)
    if name.startswith(("iptables", "ip6tables")):
        out["kind"] = "iptables"
        out["where"] = [c for c in re.split(r"[,\s]+", plain.get("chain") or "INPUT") if c]
        seen = (fwinfo["chains"].get(chain_name) or {}).get("from")
        if seen:
            out["where"], out["observed"] = sorted(seen), True
        out["forward"] = any(c in ("FORWARD", "DOCKER-USER") for c in out["where"])
    elif name.startswith("nftables"):
        out["kind"] = "nftables"
        hook = plain.get("chain_hook") or "input"
        hooks = [h for c, h in fwinfo["hooks"].items() if c == (plain.get("chain") or "f2b-chain")]
        if hooks:
            hook, out["observed"] = hooks[0], True
        out["where"] = ["hook " + hook]
        out["forward"] = hook in ("forward", "prerouting")
    return out


def _in_ranges(port, ranges):
    return any(lo <= port <= hi for lo, hi in ranges or [])


def assess_fail2ban(f2b, docker, rs, ports, now):
    if not f2b:
        return {"installed": False}
    errors = f2b.get("errors") or {}
    jail_errors = f2b.get("jail_errors") or {}
    names = f2b.get("names")          # the jails fail2ban runs; None when not known
    findings = []
    # Not running: no answer to ping, and not because the call failed while the unit is active.
    down = not f2b.get("running") and "ping" not in errors
    if down:
        findings.append({"code": "not-running", "state": "warning", "value": f2b.get("active")})
    status = f2b.get("jails") or {}   # the answer of `status JAIL` for each jail that gave one
    # Running jails that were not asked (past the first F2B_MAX_JAILS): no answer of their own.
    skipped = [n for n in names or [] if n not in status and n not in jail_errors]
    # The essential parts that could not be read: what depends on them is "not checked".
    incomplete = [k for k in F2B_ESSENTIAL if k in errors] + (["jails"] if jail_errors else []) + \
        (["skipped"] if skipped else [])
    cfg = f2b.get("config") or {"global": {}, "jails": {}}
    fwinfo = f2b_firewall(rs)
    internet = {(p.get("proto"), p.get("port")) for p in ports or [] if any(
        (((p.get("reach") or {}).get(f) or {}).get("internet") or {}).get("result") in ("open", "restricted")
        for f in ("4", "6"))}
    # Container ports the internet reaches: a ban that never sees forwarded traffic leaves them open.
    published = sorted({(m["proto"], m["host_port"]) for m in docker_mappings(docker)} & internet)
    udp_open = sorted(port for proto, port in internet if proto == "udp")
    services = f2b.get("services") or {}
    db = f2b.get("db") or {}
    db_ok = f2b.get("db") is not None
    # Every running jail answered: its lists say whom fail2ban holds as banned.
    runtime = names is not None and not jail_errors and not skipped
    now_ts = int(now.timestamp())
    known = set()
    for js in status.values():
        known.update(a for a in (_norm_addr(x) for x in js.get("banned") or []) if a)
    bans = []
    for row in db.get("bips") or []:
        ip, jail, tob, bt, cnt = (list(row) + [None] * 5)[:5]
        if not isinstance(tob, int) or not isinstance(bt, int):
            continue
        until = None if bt < 0 else tob + bt
        if until is not None and until < now_ts:
            continue
        a = _norm_addr(ip)
        if not a:
            continue
        if not runtime:
            known.add(a)
        bans.append({"ip": a, "class": seclib.source_class(a), "jail": seclib.clean(jail, 64),
                     "since": iso_ts(tob), "until": iso_ts(until) if until else None, "count": cnt})
    if not bans and status:
        for name, js in sorted(status.items()):
            for x in js.get("banned") or []:
                a = _norm_addr(x)
                if a:
                    bans.append({"ip": a, "class": seclib.source_class(a), "jail": name, "since": None,
                                 "until": None, "count": None})
    history = {}
    for row in db.get("history") or []:
        if len(row) >= 2 and isinstance(row[1], int):
            history[seclib.clean(row[0], 64)] = row[1]
    # Addresses the packet filter blocks for fail2ban that fail2ban does not hold as banned: only
    # when that is known, from every running jail or from the database.
    if f2b.get("running") and (runtime or db_ok):
        stray = {}
        for cname, c in fwinfo["chains"].items():
            extra = sorted(c["addrs"] - known)
            if extra:
                stray[cname] = len(extra)
        for jail, addrs in fwinfo["sets"].items():
            extra = sorted(addrs - known)
            if extra:
                stray["addr-set-" + jail] = len(extra)
        if stray:
            findings.append({"code": "unmanaged-bans", "state": "warning", "value": sum(stray.values()),
                             "chains": sorted(stray)})
    for p in f2b.get("persisted") or []:
        findings.append({"code": "persisted-chains", "state": "info", "value": p})
    since = f2b.get("since")
    running_for = None
    if since:
        try:
            running_for = now_ts - int(datetime.strptime(since, "%Y-%m-%dT%H:%M:%SZ")
                                       .replace(tzinfo=timezone.utc).timestamp())
        except ValueError:
            running_for = None
    jails = []
    cfg_jails = cfg.get("jails") or {}
    for name in sorted(set(cfg_jails) | set(names or []) | set(status) | set(jail_errors)):
        jc, js = cfg_jails.get(name) or {}, status.get(name) or {}
        # Whether fail2ban runs the jail: from `status`; with fail2ban down, no; else not known.
        running = (name in names) if names is not None else (False if down else None)
        backend = jc.get("backend") or ("systemd" if js.get("journal") else None)
        file_backend = backend is not None and not str(backend).startswith("systemd")
        logs = (jc.get("logpaths") or js.get("files") or []) if file_backend else []
        actions = [f2b_action(a, name, fwinfo, services) for a in jc.get("actions") or []]
        jf = []
        for a in actions:
            if a["kind"] != "other" and not a["forward"]:
                hit = [f"{p}/{proto}" for proto, p in published
                       if proto in a["protocols"] and (a["allports"] or _in_ranges(p, a["ranges"]))]
                if hit and a["allports"]:
                    jf.append({"code": "allports-input", "state": "info", "value": ", ".join(hit[:6])})
                elif hit:
                    jf.append({"code": "input-only", "state": "warning", "value": ", ".join(hit[:6])})
            if a["kind"] != "other" and a["protocols"] == ["tcp"] and not a["allports"]:
                udp = [f"{p}/udp" for p in udp_open if _in_ranges(p, a["ranges"])]
                if udp:
                    jf.append({"code": "udp-open", "state": "warning", "value": ", ".join(udp[:6])})
        log_info = []
        for p in logs:
            li = (f2b.get("logs") or {}).get(p) or {"exists": None}
            log_info.append(dict(li, path=p))
            if li.get("exists") is False:
                jf.append({"code": "log-missing", "state": "warning", "value": p})
            elif li.get("mtime"):
                age = now_ts - int(datetime.strptime(li["mtime"], "%Y-%m-%dT%H:%M:%SZ")
                                   .replace(tzinfo=timezone.utc).timestamp())
                if age > F2B_IDLE_DAYS * 86400:
                    jf.append({"code": "log-idle", "state": "warning", "value": p, "days": age // 86400})
        if (file_backend and js.get("failed_total") == 0 and running_for is not None and running_for > 86400
                and any((li.get("size") or 0) > 0 for li in log_info)):
            jf.append({"code": "no-match", "state": "warning", "value": since})
        # Configured, fail2ban answers, and its list of running jails lacks this one: it bans nothing.
        if names is not None and name not in names and name in cfg_jails:
            jf.insert(0, {"code": "jail-not-running", "state": "warning"})
        state = max((f["state"] for f in jf), key=ORDER.get, default="ok")
        # OK only when it runs, answered (failed or not asked: no answer), and its configuration was
        # read; else not checked (a jail of a fail2ban that does not run has no finding of its own:
        # the whole has one).
        if (running is not True or name not in status or f2b.get("config") is None) and ORDER[state] < ORDER["info"]:
            state = "none"
        jail = {"name": name, "backend": backend, "logs": log_info,
                "journal": js.get("journal") or " + ".join(jc.get("journalmatch") or []) or None,
                "maxretry": jc.get("maxretry"), "findtime": jc.get("findtime"), "bantime": jc.get("bantime"),
                "failregex": jc.get("failregex"),
                "actions": [{k: v for k, v in a.items() if k != "ranges"} for a in actions],
                "running": running,
                "failed_now": js.get("failed_now"), "failed_total": js.get("failed_total"),
                "banned_now": js.get("banned_now"), "banned_total": js.get("banned_total"),
                "history": history.get(name), "findings": jf, "state": state}
        if name in jail_errors:
            jail["error"] = jail_errors[name]
        if name in skipped:
            jail["skipped"] = True
        jails.append(jail)
    out = {"installed": True, "version": f2b.get("version"), "active": f2b.get("active"),
           "running": f2b.get("running"), "since": since, "unit_file": f2b.get("unit_file"),
           "dbpurgeage": (cfg.get("global") or {}).get("dbpurgeage"), "jails": jails, "bans": bans[:100],
           "bans_total": len(bans) if (db_ok or runtime) else None,
           "history_total": sum(history.values()) if db.get("history") is not None else None,
           "history_days": F2B_HISTORY_DAYS, "findings": findings, "incomplete": incomplete, "errors": errors}
    out["state"] = max([f["state"] for f in findings] + [j["state"] for j in jails], key=ORDER.get, default="ok")
    if incomplete and ORDER[out["state"]] < ORDER["info"]:
        out["state"] = "none"
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
