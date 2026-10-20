# SPDX-License-Identifier: Apache-2.0
"""Shared functions of Security Monitor: address classes, the parsers of
`ip -j addr`, `ss`, UFW's files, `sshd -T`, authorized_keys, the journal and
cscli, the file of findings marked as expected, and a read-only Docker client.

Lives in /usr/lib/cockpit-security-monitor (root-owned). Standard library
only (Python 3.8), no side effects on import, nothing here runs a command:
the callers hand in the text. Every parser takes what it understands and
reports the rest instead of guessing.
"""

import base64
import binascii
import hashlib
import http.client
import ipaddress
import json
import os
import re
import shlex
import socket
import stat
import struct

# ---------------------------------------------------------------------------
# Address classes

NET = ipaddress.ip_network
PRIVATE = [NET("10.0.0.0/8"), NET("172.16.0.0/12"), NET("192.168.0.0/16"), NET("fc00::/7")]
CGNAT = NET("100.64.0.0/10")
LOOPBACK = [NET("127.0.0.0/8"), NET("::1/128")]
LINK = [NET("169.254.0.0/16"), NET("fe80::/10")]
# Never a source on the internet: everything that is not public unicast.
NOT_INTERNET = {
    4: [NET(x) for x in ("0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
                         "172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/4",
                         "240.0.0.0/4")],
    6: [NET(x) for x in ("::/8", "100::/64", "fc00::/7", "fe80::/10", "ff00::/8", "64:ff9b::/96")],
}
GLOBAL6 = NET("2000::/3")

VPN_IF = re.compile(r"^(wg|tun|tailscale|zt|nebula)[A-Za-z0-9_.-]*$")
CONTAINER_IF = re.compile(r"^(docker|br-|veth|virbr|lxcbr|lxdbr|cni|flannel|cali|vxlan|podman|cilium|kube)")


def family(addr):
    return 4 if ipaddress.ip_address(addr).version == 4 else 6


def is_public(addr):
    a = ipaddress.ip_address(addr)
    if a.version == 6:
        if a.ipv4_mapped:
            return is_public(str(a.ipv4_mapped))
        return a in GLOBAL6 and not any(a in n for n in NOT_INTERNET[6])
    return not any(a in n for n in NOT_INTERNET[4])


def source_class(addr, vpn_nets=()):
    """The class of a remote address: local, vpn, private, cgnat, link,
    internet or other (multicast and reserved)."""
    try:
        a = ipaddress.ip_address(addr)
    except ValueError:
        return "other"
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    if any(a in n for n in LOOPBACK if n.version == a.version):
        return "local"
    if any(a in n for n in vpn_nets if n.version == a.version):
        return "vpn"
    if any(a in n for n in PRIVATE if n.version == a.version):
        return "private"
    if a.version == 4 and a in CGNAT:
        return "cgnat"
    if any(a in n for n in LINK if n.version == a.version):
        return "link"
    return "internet" if is_public(str(a)) else "other"


def widen(net):
    """A host address on an interface (Hetzner's private networks use /32)
    stands for its network: the private block it is in, else a /24 or /64."""
    if net.prefixlen < net.max_prefixlen:
        return net
    for block in PRIVATE + [CGNAT]:
        if block.version == net.version and net.subnet_of(block):
            return block
    return net.supernet(new_prefix=24 if net.version == 4 else 64)


# ---------------------------------------------------------------------------
# ip -j addr

def parse_ip_addr(text):
    """Interfaces with their addresses and the class of each:
    [{"name", "kind": local|vpn|container|net, "up", "addrs": [{"addr", "prefix", "family", "class"}]}]."""
    data = json.loads(text)
    out = []
    for link in data if isinstance(data, list) else []:
        name = str(link.get("ifname") or "")
        if not name:
            continue
        flags = link.get("flags") or []
        kind = "local" if "LOOPBACK" in flags or name == "lo" else "vpn" if VPN_IF.match(name) else \
            "container" if CONTAINER_IF.match(name) else "net"
        addrs = []
        for a in link.get("addr_info") or []:
            fam = {"inet": 4, "inet6": 6}.get(a.get("family"))
            local = a.get("local")
            if not fam or not local:
                continue
            try:
                ip = ipaddress.ip_address(local)
            except ValueError:
                continue
            if kind == "local" or ip.is_loopback:
                cls = "local"
            elif kind == "vpn":
                cls = "vpn"
            elif kind == "container":
                cls = "container"
            elif ip.is_link_local:
                cls = "link"
            elif is_public(local):
                cls = "internet"
            else:
                cls = "private"
            addrs.append({"addr": str(ip), "prefix": int(a.get("prefixlen", ip.max_prefixlen)), "family": fam,
                          "class": cls})
        out.append({"name": name, "kind": kind, "up": "UP" in flags, "addrs": addrs})
    return out


def vpn_networks(interfaces):
    nets = []
    for i in interfaces:
        for a in i["addrs"]:
            if a["class"] == "vpn":
                nets.append(widen(NET(f"{a['addr']}/{a['prefix']}", strict=False)))
    return nets


# ---------------------------------------------------------------------------
# ss -H -tulpn

PROC_RE = re.compile(r'\("((?:[^"\\]|\\.)*)",pid=(\d+),fd=(\d+)\)')


def _endpoint(text):
    """'0.0.0.0:22', '*:80', '[::]:22', '127.0.0.53%lo:53', '[fe80::1%eth0]:53'
    -> (addr or '*', iface or None, port)."""
    host, _, port = text.rpartition(":")
    if not port.isdigit():
        raise ValueError(text)
    iface = None
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if "%" in host:
        host, iface = host.split("%", 1)
    return host, iface, int(port)


def parse_ss(text):
    """Listening TCP and bound UDP sockets: [{"proto", "addr", "iface", "port",
    "families": [4] | [6] | [4, 6], "procs": [{"name", "pid"}]}], one entry per
    socket address (the same address seen twice is merged)."""
    seen = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 6 or parts[0] not in ("tcp", "udp"):
            continue
        if parts[0] == "tcp" and parts[1] != "LISTEN":
            continue
        if parts[0] == "udp" and parts[1] not in ("UNCONN", "LISTEN"):
            continue
        try:
            host, iface, port = _endpoint(parts[4])
        except ValueError:
            continue
        if host == "*":
            addr, fams = "*", [4, 6]          # IPv6 wildcard without IPV6_V6ONLY: both families
        elif host == "0.0.0.0":
            addr, fams = "0.0.0.0", [4]
        elif host == "::":
            addr, fams = "::", [6]
        else:
            try:
                ip = ipaddress.ip_address(host)
            except ValueError:
                continue
            if ip.version == 6 and ip.ipv4_mapped:
                ip = ip.ipv4_mapped
            addr, fams = str(ip), [ip.version]
        procs = [{"name": m.group(1).replace('\\"', '"')[:40], "pid": int(m.group(2))}
                 for m in PROC_RE.finditer(" ".join(parts[6:]))]
        key = (parts[0], addr, iface, port)
        if key in seen:
            have = {p["pid"] for p in seen[key]["procs"]}
            seen[key]["procs"] += [p for p in procs if p["pid"] not in have]
            continue
        seen[key] = {"proto": parts[0], "addr": addr, "iface": iface, "port": port, "families": fams,
                     "procs": procs}
    return sorted(seen.values(), key=lambda s: (s["port"], s["proto"], s["addr"]))


# ---------------------------------------------------------------------------
# Ports with a name and a weight

KNOWN_PORTS = {
    ("tcp", 22): ("ssh", "danger"), ("tcp", 9090): ("cockpit", "danger"),
    ("tcp", 2375): ("docker-api", "danger"), ("tcp", 2376): ("docker-api", "danger"),
    ("tcp", 2377): ("docker-swarm", "danger"),
    ("tcp", 3306): ("mysql", "danger"), ("tcp", 5432): ("postgresql", "danger"),
    ("tcp", 6379): ("redis", "danger"), ("tcp", 27017): ("mongodb", "danger"),
    ("tcp", 9200): ("elasticsearch", "danger"), ("tcp", 9300): ("elasticsearch", "danger"),
    ("tcp", 11211): ("memcached", "danger"), ("udp", 11211): ("memcached", "danger"),
    ("tcp", 5984): ("couchdb", "danger"), ("tcp", 8086): ("influxdb", "danger"),
    ("tcp", 1433): ("mssql", "danger"), ("tcp", 9042): ("cassandra", "danger"),
    ("tcp", 2379): ("etcd", "danger"), ("tcp", 2380): ("etcd", "danger"),
    ("tcp", 6443): ("kubernetes-api", "danger"), ("tcp", 10250): ("kubelet", "danger"),
    ("tcp", 3389): ("rdp", "danger"), ("tcp", 5900): ("vnc", "danger"),
    ("tcp", 111): ("rpcbind", "danger"), ("udp", 111): ("rpcbind", "danger"),
    ("tcp", 2049): ("nfs", "danger"), ("tcp", 445): ("smb", "danger"),
    ("tcp", 80): ("http", "info"), ("tcp", 443): ("https", "info"), ("udp", 443): ("http3", "info"),
    ("udp", 51820): ("wireguard", "info"),
}


def known_port(proto, port, kernel=False, vpn=False):
    """(name, weight) of a port: danger for databases, Docker's API, Cockpit
    and SSH, info for web and WireGuard, else (None, "warning")."""
    if (proto, port) in KNOWN_PORTS:
        return KNOWN_PORTS[(proto, port)]
    if proto == "udp" and kernel and vpn:
        return ("wireguard", "info")      # a UDP socket of the kernel on a host with a VPN interface
    return (None, "warning")


# ---------------------------------------------------------------------------
# UFW

def parse_kv(text):
    """KEY=value lines (ufw.conf, /etc/default/ufw); quotes removed."""
    out = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out


TUPLE_RE = re.compile(r"^### tuple ### (.+)$")


def parse_ufw_rules(text, fam):
    """UFW's own rules from user.rules / user6.rules ("### tuple ###" lines):
    [{"action", "log", "route", "proto", "port", "to", "sport", "from", "app",
      "direction", "iface_in", "iface_out", "comment", "family"}]."""
    out = []
    for line in (text or "").splitlines():
        m = TUPLE_RE.match(line.strip())
        if not m:
            continue
        f = m.group(1).split()
        comment = ""
        if f and f[-1].startswith("comment="):
            try:
                comment = bytes.fromhex(f.pop()[len("comment="):]).decode("utf-8", "replace")
            except ValueError:
                comment = ""
        if len(f) < 7:
            continue
        action = f[0]
        route = action.startswith("route:")
        if route:
            action = action[len("route:"):]
        log = ""
        if "_" in action:
            action, log = action.split("_", 1)
        direction = f[-1]
        dapp = sapp = ""
        if len(f) >= 9:
            dapp, sapp = f[6], f[7]
        d, _, ifaces = direction.partition("_")
        iface_in = iface_out = ""
        if ifaces:
            if "!" in ifaces:
                iface_in, iface_out = ifaces.split("!", 1)
                iface_out = iface_out[len("out_"):] if iface_out.startswith("out_") else iface_out
            elif d == "out":
                iface_out = ifaces
            else:
                iface_in = ifaces
        app = " ".join(x.replace("%20", " ") for x in (dapp, sapp) if x and x != "-")
        out.append({"action": action, "log": log, "route": route, "proto": f[1], "port": f[2], "to": f[3],
                    "sport": f[4], "from": f[5], "app": app[:60], "direction": d, "iface_in": iface_in,
                    "iface_out": iface_out, "comment": clean(comment, 120), "family": fam})
    return out


# ---------------------------------------------------------------------------
# Text from the system

_INVISIBLE = [(0x00, 0x1F), (0x7F, 0x9F), (0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x2069), (0xFEFF, 0xFEFF)]
CTRL_RE = re.compile("[" + "".join(re.escape(chr(a)) + "-" + re.escape(chr(b)) for a, b in _INVISIBLE) + "]")


def clean(text, limit=200):
    """Text from the system for the state: control, zero-width and bidi
    characters removed, at most `limit` characters."""
    return CTRL_RE.sub(" ", str(text or "")).strip()[:limit]


# ---------------------------------------------------------------------------
# sshd -T

def parse_sshd_t(text):
    """`sshd -T`: key -> list of values (one per line, keys in lower case)."""
    out = {}
    for line in (text or "").splitlines():
        parts = line.strip().split(None, 1)
        if not parts:
            continue
        out.setdefault(parts[0].lower(), []).append(parts[1] if len(parts) > 1 else "")
    return out


def _one(cfg, key, default=""):
    v = cfg.get(key)
    return v[0].strip().lower() if v else default


def assess_sshd(cfg):
    """Findings of the effective sshd configuration:
    [{"key", "value", "state", "code"}], in a fixed order."""
    out = []

    def add(key, state, code, value=None):
        out.append({"key": key, "value": value if value is not None else _one(cfg, key), "state": state,
                    "code": code})

    pw = _one(cfg, "passwordauthentication", "yes")
    add("passwordauthentication", "warning" if pw == "yes" else "ok", "password-" + ("on" if pw == "yes" else "off"))
    kbd = _one(cfg, "kbdinteractiveauthentication", _one(cfg, "challengeresponseauthentication", "no"))
    pam = _one(cfg, "usepam", "no")
    if kbd == "yes" and pam == "yes":
        add("kbdinteractiveauthentication", "warning", "kbd-pam", kbd)
    else:
        add("kbdinteractiveauthentication", "ok", "kbd-off" if kbd != "yes" else "kbd-no-pam", kbd)
    if _one(cfg, "permitemptypasswords") == "yes" and pw == "yes":
        add("permitemptypasswords", "warning", "empty-passwords")
    root = _one(cfg, "permitrootlogin", "prohibit-password")
    add("permitrootlogin", "warning" if root == "yes" else "info" if root in ("prohibit-password", "without-password")
        else "ok", "root-" + {"yes": "yes", "prohibit-password": "key", "without-password": "key",
                              "forced-commands-only": "forced"}.get(root, "no"))
    pub = _one(cfg, "pubkeyauthentication", "yes")
    add("pubkeyauthentication", "ok" if pub == "yes" else "info", "pubkey-" + ("on" if pub == "yes" else "off"))
    try:
        tries = int(_one(cfg, "maxauthtries", "6"))
    except ValueError:
        tries = 6
    add("maxauthtries", "info" if tries > 6 else "ok", "tries-many" if tries > 6 else "tries-ok", str(tries))
    allow = [v for k in ("allowusers", "allowgroups") for v in cfg.get(k, []) if v.strip()]
    add("allowusers", "ok" if allow else "info", "allow-list" if allow else "no-allow-list",
        str(len(" ".join(allow).split())) if allow else "")
    x11 = _one(cfg, "x11forwarding", "no")
    add("x11forwarding", "info" if x11 == "yes" else "ok", "x11-" + ("on" if x11 == "yes" else "off"))
    agent = _one(cfg, "allowagentforwarding", "yes")
    add("allowagentforwarding", "info" if agent == "yes" else "ok", "agent-" + ("on" if agent == "yes" else "off"))
    return out


MATCH_RE = re.compile(r"^\s*Match\s", re.I | re.M)


def has_match_block(text):
    return bool(MATCH_RE.search(text or ""))


def sshd_error(err):
    """A short reason why `sshd -T` failed."""
    e = (err or "").strip()
    if "privilege separation directory" in e.lower():
        return "privsep-dir-missing", clean(e.splitlines()[0] if e else "", 160)
    return "error", clean(e.splitlines()[0] if e else "", 160)


# ---------------------------------------------------------------------------
# /etc/passwd and authorized_keys

NOLOGIN = {"/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false", "/bin/sync", "/sbin/halt",
           "/sbin/shutdown", "/usr/sbin/halt", "/usr/sbin/shutdown", ""}


def login_accounts(passwd):
    """Accounts with a login shell: [(name, uid, home)]."""
    out = []
    for line in (passwd or "").splitlines():
        f = line.split(":")
        if len(f) < 7 or not f[0] or f[0].startswith(("#", "+", "-")):
            continue
        if f[6].strip() in NOLOGIN:
            continue
        try:
            uid = int(f[2])
        except ValueError:
            continue
        out.append((f[0], uid, f[5] or "/"))
    return out


def key_files(spec_values, name, home):
    """The authorized_keys files of an account from AuthorizedKeysFile
    (%h, %u, %%; relative paths below the home)."""
    tokens = " ".join(spec_values).split() if spec_values else [".ssh/authorized_keys", ".ssh/authorized_keys2"]
    out = []
    for tok in tokens:
        if tok.lower() == "none":
            continue
        p = tok.replace("%%", "\0").replace("%h", home.rstrip("/") or "/").replace("%u", name)
        if "%" in p:
            continue                    # a token this check does not know (%U, %i …)
        p = p.replace("\0", "%")
        if not p.startswith("/"):
            p = os.path.join(home, p)
        p = os.path.normpath(p)
        if p not in out:
            out.append(p)
    return out


KEY_TYPES = {"ssh-rsa", "ssh-dss", "ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
             "ecdsa-sha2-nistp521", "sk-ecdsa-sha2-nistp256@openssh.com", "sk-ssh-ed25519@openssh.com"}
CERT = "-cert-v01@openssh.com"


def _is_type(word):
    """A key type, or its certificate (ssh-ed25519-cert-v01@openssh.com,
    sk-ssh-ed25519-cert-v01@openssh.com)."""
    if word in KEY_TYPES:
        return True
    base = word[:-len(CERT)] if word.endswith(CERT) else None
    return bool(base) and (base in KEY_TYPES or base + "@openssh.com" in KEY_TYPES)


def _split_options(line):
    """The options of a key line and the rest: options end at the first
    whitespace outside double quotes."""
    quoted = False
    i = 0
    while i < len(line):
        c = line[i]
        if c == "\\" and quoted and i + 1 < len(line):
            i += 2
            continue
        if c == '"':
            quoted = not quoted
        elif c in " \t" and not quoted:
            break
        i += 1
    return line[:i], line[i:].strip()


def _options(text):
    out = []
    cur, quoted, escaped = "", False, False
    for c in text:
        if escaped:
            cur += c
            escaped = False
            continue
        if c == "\\" and quoted:
            cur += c
            escaped = True
            continue
        if c == '"':
            quoted = not quoted
        if c == "," and not quoted:
            out.append(cur)
            cur = ""
        else:
            cur += c
    if cur:
        out.append(cur)
    return [o.strip() for o in out if o.strip()]


def _ssh_string(blob, pos):
    if pos + 4 > len(blob):
        raise ValueError("short blob")
    n = struct.unpack(">I", blob[pos:pos + 4])[0]
    if pos + 4 + n > len(blob):
        raise ValueError("short blob")
    return blob[pos + 4:pos + 4 + n], pos + 4 + n


def key_bits(ktype, blob):
    """The size of a public key in bits, from its blob."""
    name, pos = _ssh_string(blob, 0)
    name = name.decode("ascii", "replace")
    if name != ktype:
        raise ValueError("type mismatch")
    base = ktype[:-len(CERT)] if ktype.endswith(CERT) else ktype
    if ktype.endswith(CERT):
        _, pos = _ssh_string(blob, pos)             # nonce
    if base == "ssh-rsa":
        _, pos = _ssh_string(blob, pos)             # e
        n, pos = _ssh_string(blob, pos)
        return int.from_bytes(n, "big").bit_length()
    if base == "ssh-dss":
        p, pos = _ssh_string(blob, pos)
        return int.from_bytes(p, "big").bit_length()
    if base.startswith("ecdsa-sha2-nistp") or base.startswith("sk-ecdsa-sha2-nistp"):
        return int(re.search(r"nistp(\d+)", base).group(1))
    if "ed25519" in base:
        return 256
    raise ValueError("unknown type")


def parse_authorized_keys(text):
    """Keys of an authorized_keys file: [{"line", "type", "bits", "fingerprint",
    "comment", "options", "findings": [{"code", "state"}]}]; a line that is no
    key is reported with type null."""
    out = []
    for n, raw in enumerate((text or "").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        words = line.split()
        opts = []
        if not _is_type(words[0]):
            o, rest = _split_options(line)
            opts = _options(o)
            words = rest.split()
        if len(words) < 2 or not _is_type(words[0]):
            out.append({"line": n, "type": None, "bits": None, "fingerprint": None, "comment": "", "options": [],
                        "findings": [{"code": "unreadable", "state": "info"}]})
            continue
        ktype, b64 = words[0], words[1]
        comment = clean(" ".join(words[2:]), 100)
        try:
            blob = base64.b64decode(b64, validate=True)
            bits = key_bits(ktype, blob)
            fp = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
        except (binascii.Error, ValueError, AttributeError):
            out.append({"line": n, "type": ktype, "bits": None, "fingerprint": None, "comment": comment,
                        "options": [], "findings": [{"code": "unreadable", "state": "info"}]})
            continue
        names = [o.split("=", 1)[0].lower() for o in opts]
        findings = []
        base = ktype[:-len(CERT)] if ktype.endswith(CERT) else ktype
        if base == "ssh-dss":
            findings.append({"code": "dsa", "state": "warning"})
        elif base == "ssh-rsa" and bits < 3072:
            findings.append({"code": "rsa-short", "state": "warning"})
        if "from" not in names:
            findings.append({"code": "no-from", "state": "info"})
        out.append({"line": n, "type": ktype, "bits": bits, "fingerprint": fp, "comment": comment,
                    "options": [clean(o, 120) for o in opts][:10], "findings": findings})
    return out


def file_problems(st, owner_uid, parent_st=None):
    """Why sshd (StrictModes) or another user could change a key file:
    writable by group or others, or owned by someone else."""
    out = []
    for s, what in ((st, "file"), (parent_st, "dir")):
        if s is None:
            continue
        if s.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            out.append(what + "-writable")
        if s.st_uid not in (0, owner_uid):
            out.append(what + "-owner")
    return out


# ---------------------------------------------------------------------------
# The journal: logins of the last 14 days

ACCEPTED = re.compile(r"^Accepted (\S+) for (\S+) from (\S+) port \d+")
FAILED = re.compile(r"^Failed (\S+) for (?:invalid user )?(\S*) from (\S+) port \d+")
INVALID = re.compile(r"^Invalid user (\S*) from (\S+) port \d+")
SUDO_CMD = re.compile(r"^\s*(\S+) : (?:.* ; )?TTY=.* ; USER=(\S+) ; COMMAND=")
SUDO_FAIL = re.compile(r"^\s*(\S+) : (?:\d+ incorrect password attempts?|user NOT in sudoers|"
                       r"a password is required)")
PAM_FAIL = re.compile(r"pam_unix\((\w[\w-]*):auth\): authentication failure;.*?rhost=(\S*)\s+user=(\S+)")
PAM_OPEN = re.compile(r"pam_unix\((cockpit):session\): session opened for user ([^\s(]+)")


def _message(entry):
    m = entry.get("MESSAGE")
    if isinstance(m, list):
        try:
            return bytes(m).decode("utf-8", "replace")
        except (TypeError, ValueError):
            return ""
    return m if isinstance(m, str) else ""


def parse_journal(text, vpn_nets=(), limit_success=200, limit_sources=100):
    """Logins from `journalctl -o json` of sshd, sshd-session, sudo and
    cockpit-session: successful logins with source, user and method; failed
    attempts counted per source (one per connection, i.e. per process)."""
    success, failed, sudo = [], {}, {}
    cockpit_open = 0
    seen_fail = set()
    lines = 0
    for raw in (text or "").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            e = json.loads(raw)
        except ValueError:
            continue
        lines += 1
        ident = e.get("SYSLOG_IDENTIFIER") or e.get("_COMM") or ""
        msg = _message(e)
        try:
            ts = int(e.get("__REALTIME_TIMESTAMP") or 0) // 1000000
        except (TypeError, ValueError):
            ts = 0
        pid = str(e.get("_PID") or "")
        if ident in ("sshd", "sshd-session"):
            m = ACCEPTED.match(msg)
            if m:
                success.append({"ts": ts, "service": "ssh", "method": clean(m.group(1), 40),
                                "user": clean(m.group(2), 40), "source": clean(m.group(3), 60),
                                "class": source_class(m.group(3), vpn_nets)})
                continue
            m = FAILED.match(msg)
            src, user = (m.group(3), m.group(2)) if m else (None, None)
            if not m:
                m = INVALID.match(msg)
                if m:
                    src, user = m.group(2), m.group(1)
            if src:
                _fail(failed, seen_fail, ("ssh", pid or ts, src), src, user, ts, vpn_nets, "ssh")
        elif ident == "sudo":
            m = SUDO_FAIL.match(msg)
            if m:
                s = sudo.setdefault(clean(m.group(1), 40), {"uses": 0, "failures": 0, "last": 0})
                s["failures"] += 1
                continue
            m = SUDO_CMD.match(msg)
            if m:
                s = sudo.setdefault(clean(m.group(1), 40), {"uses": 0, "failures": 0, "last": 0})
                s["uses"] += 1
                s["last"] = max(s["last"], ts)
        elif ident == "cockpit-session":
            if PAM_OPEN.search(msg):
                cockpit_open += 1
                m = PAM_OPEN.search(msg)
                success.append({"ts": ts, "service": "cockpit", "method": "password", "user": clean(m.group(2), 40),
                                "source": None, "class": None})
                continue
            m = PAM_FAIL.search(msg)
            if m and m.group(2):
                _fail(failed, seen_fail, ("cockpit", pid or ts, m.group(2)), m.group(2), m.group(3), ts, vpn_nets,
                      "cockpit")
    success.sort(key=lambda s: -s["ts"])
    srcs = sorted(failed.values(), key=lambda f: (-f["count"], -f["last"]))
    for f in srcs:
        f["users"] = len(f.pop("_users"))
    return {"entries": lines, "success": success[:limit_success], "success_total": len(success),
            "failed": srcs[:limit_sources], "failed_sources": len(srcs),
            "failed_total": sum(f["count"] for f in srcs),
            "sudo": [dict(user=u, **v) for u, v in sorted(sudo.items())][:50]}


def _fail(failed, seen, key, src, user, ts, vpn_nets, service):
    if key in seen:
        return
    seen.add(key)
    src = clean(src, 60)
    f = failed.setdefault(src, {"source": src, "class": source_class(src, vpn_nets), "count": 0, "last": 0,
                                "services": [], "_users": set()})
    f["count"] += 1
    f["last"] = max(f["last"], ts)
    if service not in f["services"]:
        f["services"].append(service)
    if user:
        f["_users"].add(user)


# ---------------------------------------------------------------------------
# CrowdSec (cscli -o json, the bouncer's YAML)

def parse_json_list(text):
    """cscli prints `null` for an empty list."""
    try:
        data = json.loads(text or "null")
    except ValueError:
        return None
    if data is None:
        return []
    return data if isinstance(data, list) else None


VERSION_RE = re.compile(r"v?(\d+)\.(\d+)\.(\d+)")


def version_tuple(text):
    m = VERSION_RE.search(text or "")
    return tuple(int(x) for x in m.groups()) if m else None


def yaml_keys(text, keys):
    """A few top-level keys of a simple YAML file: scalars and lists
    (`key: [a, b]` or `- a` lines below the key). Enough for the
    firewall bouncer's configuration; anything nested is ignored."""
    out = {}
    cur = None
    for line in (text or "").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith((" ", "\t", "-")):
            cur = None
            k, _, v = line.partition(":")
            k = k.strip()
            if k in keys:
                v = v.split(" #", 1)[0].strip()
                if v.startswith("[") and v.endswith("]"):
                    out[k] = [x.strip().strip("'\"") for x in v[1:-1].split(",") if x.strip()]
                elif v:
                    out[k] = v.strip("'\"")
                else:
                    out[k] = []
                    cur = k
            continue
        s = line.strip()
        if cur and s.startswith("- "):
            out[cur].append(s[2:].split(" #", 1)[0].strip().strip("'\""))
    return out


# ---------------------------------------------------------------------------
# Findings marked as expected (/etc/cockpit-security-monitor/exposure.conf)

PORT_KEY_RE = re.compile(r"^([0-9]{1,5})/(tcp|udp)$")
CONTAINER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
CONTAINER_KINDS = ("docker-socket", "privileged", "pid-host", "cap-add", "host-mount", "network-host", "root-user",
                   "no-new-privileges", "apparmor-unconfined")
NOTE_MAX = 200


def valid_port_key(key):
    m = PORT_KEY_RE.match(key or "")
    return bool(m) and 1 <= int(m.group(1)) <= 65535


def valid_note(note):
    return isinstance(note, str) and len(note) <= NOTE_MAX and not CTRL_RE.search(note)


def parse_marks(text):
    """The lines of exposure.conf:
         port 8080/tcp <note>
         container <name> <finding> <note>
    -> ({"ports": {key: note}, "containers": {(name, kind): note}}, [errors])."""
    marks = {"ports": {}, "containers": {}}
    errors = []
    for n, line in enumerate((text or "").splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        f = s.split(None, 3)
        if f[0] == "port" and len(f) >= 2 and valid_port_key(f[1]):
            note = s.split(None, 2)[2] if len(f) > 2 else ""
            if valid_note(note):
                marks["ports"][f[1]] = note
                continue
        elif f[0] == "container" and len(f) >= 3 and CONTAINER_RE.match(f[1]) and f[2] in CONTAINER_KINDS:
            note = f[3] if len(f) > 3 else ""
            if valid_note(note):
                marks["containers"][(f[1], f[2])] = note
                continue
        errors.append(n)
    return marks, errors


MARKS_HEADER = ("# Security Monitor: findings marked as expected. Written by the page (\"Mark as expected\");\n"
                "# you may edit it by hand. One line each:\n"
                "#   port <port>/<tcp|udp> <note>\n"
                "#   container <name> <finding> <note>\n")


def format_marks(marks):
    lines = [MARKS_HEADER.rstrip("\n")]
    for key in sorted(marks["ports"], key=lambda k: (int(k.split("/")[0]), k)):
        lines.append(f"port {key} {marks['ports'][key]}".rstrip())
    for (name, kind) in sorted(marks["containers"]):
        lines.append(f"container {name} {kind} {marks['containers'][(name, kind)]}".rstrip())
    return "\n".join(lines) + "\n"


def trusted_file(st):
    """A settings file counts only when root owns it and nobody else can write it."""
    return st is not None and stat.S_ISREG(st.st_mode) and st.st_uid == 0 and not st.st_mode & (stat.S_IWGRP |
                                                                                                stat.S_IWOTH)


# ---------------------------------------------------------------------------
# Docker, read only: GET over the Unix socket

DOCKER_SOCKET = "/var/run/docker.sock"
DOCKER_PATH_RE = re.compile(r"^/(info|version|networks|containers/json(\?all=0)?|containers/[0-9a-f]{12,64}/json)$")
DOCKER_MAX = 16 << 20


class _UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path, timeout):
        super().__init__("localhost", timeout=timeout)
        self._unix = path

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(self._unix)
        self.sock = s


def docker_get(path, sock=DOCKER_SOCKET, timeout=10):
    """GET a fixed path of Docker's API. Only GET, only the paths of
    DOCKER_PATH_RE; raises OSError or ValueError on any failure."""
    if not DOCKER_PATH_RE.match(path):
        raise ValueError("path not allowed: " + path)
    conn = _UnixHTTP(sock, timeout)
    try:
        conn.request("GET", path, headers={"Accept": "application/json", "User-Agent": "cockpit-security-monitor"})
        resp = conn.getresponse()
        body = resp.read(DOCKER_MAX + 1)
        if len(body) > DOCKER_MAX:
            raise ValueError("answer too large")
        if resp.status != 200:
            raise ValueError(f"HTTP {resp.status}")
        return json.loads(body.decode("utf-8"))
    except http.client.HTTPException as e:
        raise ValueError(str(e)) from e
    finally:
        conn.close()


def quote(argv):
    return " ".join(shlex.quote(a) for a in argv)
