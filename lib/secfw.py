# SPDX-License-Identifier: Apache-2.0
"""Security Monitor's model of the packet filter: what `iptables-save`,
`ip6tables-save` and `nft -j list ruleset` print, turned into chains of rules,
and an evaluator that follows a new connection through them.

Lives in /usr/lib/cockpit-security-monitor (root-owned). Standard library
only, no side effects on import, nothing here runs a command.

Why both sources: iptables-nft keeps the matches of iptables extensions
(conntrack, multiport, addrtype, recent) as "xt" expressions, and nft's JSON
names such an expression without its options. The tables iptables manages
(UFW's and Docker's in iptables mode) are therefore read from iptables-save;
nft's JSON supplies every other table (nftables.conf, Docker's nftables mode,
fail2ban, CrowdSec).

What the evaluator understands: addresses, ports, protocols, interfaces,
connection state, original destination (conntrack), address types, sets,
verdict maps, jumps, policies. A match it cannot read makes it follow both
ways; when they end differently, the answer is "unknown" with that rule.
Sources are symbolic (all of the internet, a VPN network, a private
network, the members of an ipset whose contents are not known): a rule that
names only part of a class yields a narrower sample that is followed on its
own ("reachable only from ..."). A source port is the sender's choice: a rule
that lets some source port in lets the sender in.
"""

import ipaddress
import re
import shlex

from seclib import GLOBAL6, NOT_INTERNET

NET = ipaddress.ip_network
ACCEPT, DROP, RETURN, UNKNOWN, CONTINUE = "accept", "drop", "return", "unknown", "continue"
YES, NO, MAYBE = "yes", "no", "maybe"
CHOICE = "choice"           # matches or not as the sender likes (its source port)
MAX_FORKS = 64
MAX_DEPTH = 32
MAX_CANDIDATES = 24
HOOK_ORDER = {"ingress": 0, "prerouting": 1, "input": 2, "forward": 2}

# The built-in chains of iptables: hook, priority and type as nftables sees them.
BUILTIN = {
    ("raw", "PREROUTING"): ("prerouting", -300, "filter"),
    ("mangle", "PREROUTING"): ("prerouting", -150, "filter"),
    ("mangle", "INPUT"): ("input", -150, "filter"),
    ("mangle", "FORWARD"): ("forward", -150, "filter"),
    ("nat", "PREROUTING"): ("prerouting", -100, "nat"),
    ("filter", "INPUT"): ("input", 0, "filter"),
    ("filter", "FORWARD"): ("forward", 0, "filter"),
    ("security", "INPUT"): ("input", 50, "filter"),
    ("security", "FORWARD"): ("forward", 50, "filter"),
}
CONTINUE_TARGETS = {"LOG", "NFLOG", "ULOG", "TRACE", "AUDIT", "MARK", "CONNMARK", "CT", "NOTRACK", "TCPMSS",
                    "CHECKSUM", "TOS", "DSCP", "SET", "CLASSIFY", "LED", "SECMARK", "CONNSECMARK", "TEE",
                    "IDLETIMER", "HMARK", "SNAT", "MASQUERADE", "DNAT", "REDIRECT", "NETMAP", "TTL", "HL"}
PROTOS = {"6": "tcp", "17": "udp", "1": "icmp", "58": "ipv6-icmp", "icmpv6": "ipv6-icmp"}


class Rule:
    """One rule: matches (kind, negated, value), a verdict and where it lives."""

    def __init__(self, src, family, table, chain, index, text, matches, verdict, target=None, vmap=None,
                 comment=""):
        self.src, self.family, self.table, self.chain, self.index = src, family, table, chain, index
        self.text, self.matches, self.verdict, self.target = text, matches, verdict, target
        self.vmap, self.comment = vmap, comment

    def ref(self):
        return {"src": self.src, "family": self.family, "table": self.table, "chain": self.chain,
                "index": self.index, "text": self.text[:240], "comment": self.comment[:120],
                "owner": owner(self.table, self.chain)}


class Chain:
    def __init__(self, src, family, table, name, hook=None, prio=0, policy=None, ctype="filter", devices=()):
        self.src, self.family, self.table, self.name = src, family, table, name
        self.hook, self.prio, self.policy, self.ctype, self.devices = hook, prio, policy, ctype, list(devices)
        self.rules = []

    def ref(self):
        return {"src": self.src, "family": self.family, "table": self.table, "chain": self.name,
                "policy": self.policy, "owner": owner(self.table, self.name)}


def owner(table, chain):
    """Who keeps a chain: ufw, docker, fail2ban, crowdsec, or None."""
    c = chain or ""
    if c.startswith(("ufw-", "ufw6-")):
        return "ufw"
    if c.startswith("DOCKER") or table == "docker-bridges":
        return "docker"
    if c.startswith("f2b-") or table == "f2b-table":
        return "fail2ban"
    if "crowdsec" in c.lower() or "crowdsec" in (table or ""):
        return "crowdsec"
    return None


class Ruleset:
    def __init__(self):
        self.chains = {}        # (src, family, table, name) -> Chain
        self.sets = {}          # (family, table, name) -> elements
        self.dnat = []          # port mappings found in nat chains
        self.problems = []      # what could not be read

    def chain(self, src, family, table, name, **kw):
        key = (src, family, table, name)
        if key not in self.chains:
            self.chains[key] = Chain(src, family, table, name, **kw)
        else:
            for k, v in kw.items():
                setattr(self.chains[key], k if k != "ctype" else "ctype", v)
        return self.chains[key]

    def find(self, rule_or_chain, name):
        c = rule_or_chain
        return self.chains.get((c.src, c.family, c.table, name))

    def base_chains(self, fam, hooks, iif=None):
        fams = {"ip", "inet"} if fam == 4 else {"ip6", "inet"}
        out = []
        for c in self.chains.values():
            if c.hook not in hooks or c.ctype != "filter":
                continue
            if c.family == "netdev":
                if iif not in c.devices:
                    continue
            elif c.family not in fams:
                continue
            out.append(c)
        return sorted(out, key=lambda c: (HOOK_ORDER.get(c.hook, 9), c.prio))

    def has_chain(self, name, fam=None):
        return any(c.name == name and (fam is None or c.family == ("ip" if fam == 4 else "ip6"))
                   for c in self.chains.values())


# ---------------------------------------------------------------------------
# Values

def nets_of(text, fam=None):
    out = []
    for part in str(text).split(","):
        part = part.strip()
        if not part:
            continue
        n = NET(part, strict=False)
        if fam is None or n.version == fam:
            out.append(n)
    return out


def port_ranges(text, sep=":"):
    out = []
    for part in str(text).split(","):
        part = part.strip()
        if not part:
            continue
        if sep in part:
            lo, hi = part.split(sep, 1)
            out.append((int(lo or 0), int(hi or 65535)))
        else:
            out.append((int(part), int(part)))
    return out


def iface_match(names, iface):
    if iface is None:
        return False
    for n in names:
        n = str(n)
        if n.endswith("+") or n.endswith("*"):
            if iface.startswith(n[:-1]):
                return True
        elif n == iface:
            return True
    return False


# ---------------------------------------------------------------------------
# iptables-save

def parse_iptables_save(text, fam, rs, src="iptables"):
    """Adds the tables of iptables-save (fam 4) or ip6tables-save (fam 6)."""
    family = "ip" if fam == 4 else "ip6"
    table = None
    counts = {}
    for line in (text or "").splitlines():
        line = line.rstrip("\n")
        if line.startswith("*"):
            table = line[1:].strip()
        elif line.startswith(":") and table:
            parts = line[1:].split()
            if not parts:
                continue
            name, policy = parts[0], (parts[1] if len(parts) > 1 else "-")
            hook, prio, ctype = BUILTIN.get((table, name), (None, 0, "filter"))
            if (table, name) not in BUILTIN and name in ("OUTPUT", "POSTROUTING", "INPUT", "PREROUTING") \
                    and table in ("nat", "raw", "mangle"):
                ctype = "other"
            rs.chain(src, family, table, name, hook=hook, prio=prio,
                     policy=policy.lower() if policy != "-" else None, ctype=ctype)
        elif line.startswith("-A ") and table:
            try:
                tokens = shlex.split(line)
            except ValueError:
                tokens = line.split()
            if len(tokens) < 2:
                continue
            chain = tokens[1]
            c = rs.chain(src, family, table, chain)
            counts[chain] = counts.get(chain, 0) + 1
            text_part = line.split(None, 2)[2] if len(line.split(None, 2)) > 2 else ""
            matches, verdict, target, comment, dnat = parse_ipt_tokens(tokens[2:], fam)
            r = Rule(src, family, table, chain, counts[chain], text_part, matches, verdict, target, comment=comment)
            c.rules.append(r)
            if dnat and table == "nat":
                rs.dnat.append(dnat_entry(fam, matches, dnat, r))
        elif line.strip() == "COMMIT":
            table = None
    # A jump to a chain that is not there is unknown; a target that is a chain is a jump.
    for c in list(rs.chains.values()):
        if c.src != src:
            continue
        for r in c.rules:
            if r.verdict == "target":
                if rs.find(r, r.target):
                    r.verdict = "jump"
                else:
                    r.verdict = UNKNOWN


def parse_ipt_tokens(t, fam):
    """Matches, verdict, target, comment and a DNAT destination of one
    iptables-save rule (the tokens after "-A CHAIN")."""
    matches = []
    verdict, target, comment, dnat = CONTINUE, None, "", None
    module = None
    neg = False
    i = 0

    def val(k=1):
        return t[i + k] if i + k < len(t) else ""

    while i < len(t):
        tok = t[i]
        if tok == "!":
            neg = True
            i += 1
            continue
        step = 2
        if tok in ("-s", "--source"):
            matches.append(("saddr", neg, nets_of(val(), fam)))
        elif tok in ("-d", "--destination"):
            matches.append(("daddr", neg, nets_of(val(), fam)))
        elif tok in ("-i", "--in-interface"):
            matches.append(("iif", neg, [val()]))
        elif tok in ("-o", "--out-interface"):
            matches.append(("oif", neg, [val()]))
        elif tok in ("-p", "--protocol"):
            p = PROTOS.get(val().lower(), val().lower())
            if p not in ("all", "0"):
                matches.append(("proto", neg, {p}))
            if p in ("tcp", "udp") and not neg and module is None:
                module = p          # -p tcp loads the tcp match: --dport may follow without -m tcp
        elif tok in ("-f", "--fragment"):
            matches.append(("never", False, "fragment") if not neg else ("always", False, "not a fragment"))
            step = 1
        elif tok in ("-m", "--match"):
            module = val()
            if module == "rt":
                # an IPv6 routing header (ufw drops type 0): a plain connection carries none
                matches.append(("never", False, "routing header") if not neg else ("always", False, "rt"))
            elif module not in ("tcp", "udp", "multiport", "conntrack", "state", "comment", "addrtype", "limit",
                                "recent", "icmp", "icmp6", "pkttype", "hashlimit", "connlimit", "set"):
                matches.append(("unknown", False, "-m " + module))
        elif tok in ("-j", "--jump", "-g", "--goto"):
            tg = val()
            if tok in ("-g", "--goto"):
                verdict, target = "goto", tg
            elif tg == "ACCEPT":
                verdict = ACCEPT
            elif tg in ("DROP", "REJECT"):
                verdict = DROP
            elif tg == "RETURN":
                verdict = RETURN
            elif tg in ("QUEUE", "NFQUEUE"):
                verdict = UNKNOWN
            elif tg in CONTINUE_TARGETS:
                verdict = CONTINUE
            else:
                verdict, target = "target", tg
            module = "target:" + tg
        elif module == "target:DNAT" and tok == "--to-destination":
            dnat = val()
        elif tok == "--comment":
            comment = val()
        elif tok in ("--dport", "--destination-port") and module in ("tcp", "udp"):
            matches.append(("dport", neg, port_ranges(val())))
        elif tok in ("--sport", "--source-port") and module in ("tcp", "udp"):
            matches.append(("sport", neg, port_ranges(val())))
        elif tok in ("--dports", "--destination-ports") and module == "multiport":
            matches.append(("dport", neg, port_ranges(val())))
        elif tok in ("--sports", "--source-ports") and module == "multiport":
            matches.append(("sport", neg, port_ranges(val())))
        elif tok == "--ports" and module == "multiport":
            matches.append(("anyport", neg, port_ranges(val())))
        elif tok in ("--ctstate", "--state") and module in ("conntrack", "state"):
            matches.append(("ct", neg, {s.lower() for s in val().split(",")}))
        elif tok == "--ctorigdst" and module == "conntrack":
            matches.append(("ctorigdst", neg, nets_of(val(), fam)))
        elif tok == "--ctorigdstport" and module == "conntrack":
            matches.append(("ctorigdstport", neg, port_ranges(val())))
        elif tok == "--ctstatus" and module == "conntrack":
            matches.append(("ctstatus", neg, {s.lower() for s in val().split(",")}))
        elif tok.startswith("--ct") and module == "conntrack":
            matches.append(("unknown", False, "conntrack " + tok))
        elif tok in ("--dst-type", "--src-type") and module == "addrtype":
            matches.append(("addrtype_" + ("dst" if tok == "--dst-type" else "src"), neg,
                            {s.upper() for s in val().split(",")}))
        elif tok in ("--limit-iface-in", "--limit-iface-out") and module == "addrtype":
            step = 1
        elif module == "limit" and tok in ("--limit", "--limit-burst"):
            if not matches or matches[-1] != ("always", False, "limit"):
                matches.append(("always", False, "limit"))
        elif module == "recent":
            if tok in ("--set",):
                step = 1
            elif tok in ("--update", "--rcheck", "--remove"):
                # A first connection is not in the list yet (ufw limit).
                matches.append(("never", False, "recent " + tok) if not neg else ("always", False, "recent"))
                step = 1
            elif tok in ("--rsource", "--rdest", "--rttl", "--reap"):
                step = 1
        elif module == "hashlimit" and tok.startswith("--hashlimit"):
            if tok == "--hashlimit-above":
                matches.append(("never", False, "hashlimit above"))
            elif tok == "--hashlimit-upto":
                matches.append(("always", False, "hashlimit upto"))
        elif module == "connlimit" and tok.startswith("--connlimit"):
            if tok == "--connlimit-above":
                matches.append(("never", False, "connlimit above") if not neg else ("always", False, "connlimit"))
            elif tok == "--connlimit-upto":
                matches.append(("always", False, "connlimit upto"))
            elif tok in ("--connlimit-saddr", "--connlimit-daddr"):
                step = 1
        elif tok == "--pkt-type" and module == "pkttype":
            matches.append(("pkttype", neg, {val().lower()}))
        elif module == "set" and tok.startswith("--"):
            # an ipset: its members are not in iptables-save. As the source it is a sample of its
            # own; any other use (dst, several dimensions, counters) is not read.
            if tok == "--match-set":
                if val(2) == "src":
                    matches.append(("saddr_set", neg, val()))
                else:
                    matches.append(("unknown", False, f"--match-set {val()} {val(2)}"))
                step = 3
            elif tok in ("--return-nomatch", "--update-counters", "--update-subcounters"):
                step = 1
            else:
                matches.append(("unknown", False, "set " + tok))
                if i + 1 >= len(t) or t[i + 1].startswith("-"):
                    step = 1
        elif tok == "--syn":
            matches.append(("tcpflags", neg, ({"SYN", "RST", "ACK", "FIN"}, {"SYN"})))
            step = 1
        elif tok == "--tcp-flags":
            matches.append(("tcpflags", neg, (set(val().split(",")), set(val(2).split(",")) - {"NONE"})))
            step = 3
        elif tok in ("--icmp-type", "--icmpv6-type"):
            pass
        elif module and module.startswith("target:"):
            # options of the target (--reject-with, --log-prefix …); one value each
            if tok.startswith("--") and (i + 1 >= len(t) or t[i + 1].startswith("--")):
                step = 1
        elif module and tok.startswith("--"):
            # an option of a module this model does not read; already marked unknown
            if i + 1 >= len(t) or t[i + 1].startswith("-"):
                step = 1
        else:
            matches.append(("unknown", False, tok))
            step = 1
        neg = False
        i += step
    return matches, verdict, target, comment, dnat


def dnat_entry(fam, matches, to, rule):
    m = re.match(r"^\[?([0-9a-fA-F.:]+?)\]?(?::(\d+)(?:-\d+)?)?$", to.strip())
    addr = m.group(1) if m else None
    port = int(m.group(2)) if m and m.group(2) else None
    if fam == 6 and to.startswith("[") and "]:" in to:
        addr, port = to[1:].split("]:", 1)
        port = int(port.split("-")[0])
    elif fam == 6 and not to.startswith("["):
        addr, port = to, None
    proto = next((v for k, n, v in matches if k == "proto" and not n), None)
    ports = next((v for k, n, v in matches if k == "dport" and not n), None)
    daddr = next((v for k, n, v in matches if k == "daddr" and not n), None)
    return {"family": fam, "proto": sorted(proto)[0] if proto else None, "ports": ports, "daddr": daddr,
            "to_addr": addr, "to_port": port, "rule": rule}


# ---------------------------------------------------------------------------
# nft -j list ruleset

IPT_TABLES = {"filter", "nat", "mangle", "raw", "security"}


def parse_nft_json(doc, rs, skip_iptables=()):
    """Adds the tables of `nft -j list ruleset`. skip_iptables: the families
    ("ip", "ip6") whose iptables tables came from iptables-save already."""
    items = (doc or {}).get("nftables") or []
    skip = {(f, t) for f in skip_iptables for t in IPT_TABLES}
    rules = []
    counts = {}
    for it in items:
        if not isinstance(it, dict):
            continue
        if "chain" in it:
            c = it["chain"]
            if (c.get("family"), c.get("table")) in skip:
                continue
            dev = c.get("dev") or c.get("devices") or []
            rs.chain("nft", c.get("family"), c.get("table"), c.get("name"), hook=c.get("hook"),
                     prio=_prio(c.get("prio")), policy=c.get("policy") if c.get("hook") else None,
                     ctype=c.get("type") or "filter", devices=[dev] if isinstance(dev, str) else dev)
        elif "set" in it or "map" in it:
            s = it.get("set") or it.get("map")
            rs.sets[(s.get("family"), s.get("table"), s.get("name"))] = s.get("elem") or []
        elif "rule" in it:
            rules.append(it["rule"])
    for r in rules:
        fam, table, chain = r.get("family"), r.get("table"), r.get("chain")
        if (fam, table) in skip:
            continue
        c = rs.chain("nft", fam, table, chain)
        counts[(fam, table, chain)] = counts.get((fam, table, chain), 0) + 1
        rule = nft_rule(rs, r, counts[(fam, table, chain)])
        c.rules.append(rule)
        if c.ctype == "nat" or any(rule_has_dnat(e) for e in r.get("expr") or []):
            for e in r.get("expr") or []:
                if isinstance(e, dict) and "dnat" in e and isinstance(e["dnat"], dict):
                    d = e["dnat"]
                    fams = (4,) if fam == "ip" else (6,) if fam == "ip6" else ((4,) if d.get("family") == "ip"
                                                                               else (6,) if d.get("family") == "ip6"
                                                                               else (4, 6))
                    for f in fams:
                        addr = d.get("addr")
                        rs.dnat.append({"family": f, "proto": _nft_proto(rule.matches),
                                        "ports": next((v for k, n, v in rule.matches if k == "dport" and not n),
                                                      None),
                                        "daddr": next((v for k, n, v in rule.matches if k == "daddr" and not n),
                                                      None),
                                        "to_addr": addr if isinstance(addr, str) else None,
                                        "to_port": d.get("port") if isinstance(d.get("port"), int) else None,
                                        "rule": rule})


def rule_has_dnat(e):
    return isinstance(e, dict) and "dnat" in e


def _prio(p):
    if isinstance(p, int):
        return p
    names = {"raw": -300, "mangle": -150, "dstnat": -100, "filter": 0, "security": 50, "srcnat": 100}
    if isinstance(p, str):
        m = re.match(r"^(\w+)\s*([+-])\s*(\d+)$", p)
        if m:
            return names.get(m.group(1), 0) + (int(m.group(3)) if m.group(2) == "+" else -int(m.group(3)))
        return names.get(p, 0)
    return 0


def _nft_proto(matches):
    p = next((v for k, n, v in matches if k == "proto" and not n), None)
    return sorted(p)[0] if p else None


def nft_rule(rs, r, index):
    fam, table, chain = r.get("family"), r.get("table"), r.get("chain")
    matches, verdict, target, vmap = [], CONTINUE, None, None
    words = []
    for e in r.get("expr") or []:
        if not isinstance(e, dict) or not e:
            continue
        key = next(iter(e))
        v = e[key]
        if key == "match":
            m, w = _nft_match(rs, fam, table, v)
            matches.extend(m)
            words.append(w)
        elif key in ("accept", "drop", "return", "continue"):
            verdict = key if key != "continue" else CONTINUE
            words.append(key)
        elif key == "reject":
            verdict = DROP
            words.append("reject")
        elif key in ("jump", "goto"):
            verdict, target = key, (v or {}).get("target")
            words.append(f"{key} {target}")
        elif key in ("counter", "log", "mangle", "notrack", "flow", "dup", "ct helper", "reset", "set", "masquerade",
                     "snat", "redirect", "dnat", "secmark", "synproxy_none"):
            if key in ("dnat", "snat", "masquerade", "redirect"):
                words.append(key)
            continue
        elif key in ("limit", "quota", "ct count"):
            inv = isinstance(v, dict) and v.get("inv")
            matches.append(("never", False, key + " over") if inv else ("always", False, key))
            words.append(key + (" over" if inv else ""))
        elif key == "vmap":
            vmap = _nft_vmap(rs, fam, table, v)
            verdict = "vmap"
            words.append("vmap")
        elif key == "xt":
            name = (v or {}).get("name", "?")
            if (v or {}).get("type") == "target":
                if name in ("REJECT",):
                    verdict = DROP
                elif name in CONTINUE_TARGETS:
                    pass
                else:
                    verdict = UNKNOWN
            elif name != "comment":
                matches.append(("unknown", False, "xt " + name))
            words.append(f"xt {name}")
        else:
            verdict = UNKNOWN
            words.append(key)
    text = " ".join(w for w in words if w)
    return Rule("nft", fam, table, chain, index, text, matches, verdict, target, vmap=vmap,
                comment=str(r.get("comment") or ""))


def _left(left):
    """The kind of a left-hand expression: (kind, extra) or (None, text)."""
    if not isinstance(left, dict):
        return None, str(left)
    if "payload" in left:
        p = left["payload"]
        proto, field = p.get("protocol"), p.get("field")
        if proto in ("ip", "ip6") and field in ("saddr", "daddr"):
            return field, proto
        if proto in ("tcp", "udp", "th", "sctp", "dccp", "udplite") and field in ("dport", "sport"):
            return field, proto
        if (proto, field) in (("ip", "protocol"), ("ip6", "nexthdr")):
            return "proto", None
        return None, f"{proto} {field}"
    if "meta" in left:
        k = left["meta"].get("key")
        return {"l4proto": ("proto", None), "nfproto": ("nfproto", None), "iifname": ("iif", None),
                "oifname": ("oif", None), "iif": ("iif", None), "oif": ("oif", None),
                "pkttype": ("pkttype", None)}.get(k, (None, "meta " + str(k)))
    if "ct" in left:
        c = left["ct"]
        k, d = c.get("key"), c.get("dir")
        if k == "state":
            return "ct", None
        if k == "status":
            return "ctstatus", None
        if d == "original" and k in ("proto-dst",):
            return "ctorigdstport", None
        if d == "original" and k in ("daddr", "ip daddr", "ip6 daddr"):
            return "ctorigdst", None
        return None, "ct " + str(k)
    if "fib" in left:
        f = left["fib"]
        if f.get("result") == "type" and "daddr" in (f.get("flags") or []):
            return "fibtype", None
        if f.get("result") == "oif" and "saddr" in (f.get("flags") or []):
            return "rpf", None
        return None, "fib"
    return None, next(iter(left), "?")


def _elements(rs, fam, table, right):
    """The values of a right-hand side: list of str/int/ip_network/(lo, hi)."""
    if isinstance(right, str) and right.startswith("@"):
        elems = rs.sets.get((fam, table, right[1:]))
        if elems is None:
            return None
        return _flat(elems)
    if isinstance(right, dict) and "set" in right:
        return _flat(right["set"])
    if isinstance(right, list):
        return _flat(right)
    return _flat([right])


def _flat(elems):
    out = []
    for x in elems or []:
        if isinstance(x, dict) and "elem" in x:
            x = x["elem"].get("val") if isinstance(x["elem"], dict) else x["elem"]
        if isinstance(x, dict) and "prefix" in x:
            p = x["prefix"]
            try:
                out.append(NET(f"{p.get('addr')}/{p.get('len')}", strict=False))
            except ValueError:
                return None
        elif isinstance(x, dict) and "range" in x:
            lo, hi = x["range"]
            if isinstance(lo, int) and isinstance(hi, int):
                out.append((lo, hi))
            else:
                try:
                    out.extend(ipaddress.summarize_address_range(ipaddress.ip_address(lo), ipaddress.ip_address(hi)))
                except (ValueError, TypeError):
                    return None
        elif isinstance(x, dict) and "concat" in x:
            return None
        elif isinstance(x, (int, str)):
            out.append(x)
        elif isinstance(x, list) and len(x) == 2:
            out.append(tuple(x))     # map element [key, data]
        else:
            return None
    return out


def _nft_match(rs, fam, table, m):
    left, right, op = m.get("left"), m.get("right"), m.get("op", "==")
    kind, extra = _left(left)
    neg = op == "!="
    text = _render(left, op, right)
    if kind is None:
        return [("unknown", False, text)], text
    vals = _elements(rs, fam, table, right)
    if vals is None:
        return [("unknown", False, text)], text
    out = []
    if kind in ("saddr", "daddr", "ctorigdst"):
        nets = []
        for v in vals:
            if isinstance(v, str):
                try:
                    nets.append(NET(v, strict=False))
                except ValueError:
                    return [("unknown", False, text)], text
            elif isinstance(v, ipaddress._BaseNetwork):
                nets.append(v)
        out.append((kind, neg, nets))
    elif kind in ("dport", "sport", "ctorigdstport"):
        ranges = []
        for v in vals:
            if isinstance(v, int):
                ranges.append((v, v))
            elif isinstance(v, tuple) and all(isinstance(x, int) for x in v):
                ranges.append(v)
            elif isinstance(v, str) and v.isdigit():
                ranges.append((int(v), int(v)))
            else:
                return [("unknown", False, text)], text
        if op in ("<", "<=", ">", ">=") and len(ranges) == 1:
            n = ranges[0][0]
            ranges = [{"<": (0, n - 1), "<=": (0, n), ">": (n + 1, 65535), ">=": (n, 65535)}[op]]
            neg = False
        if extra in ("tcp", "udp"):
            out.append(("proto", False, {extra}))
        out.append((kind, neg, ranges))
    elif kind == "proto":
        out.append(("proto", neg, {PROTOS.get(str(v), str(v)) for v in vals}))
    elif kind == "nfproto":
        out.append(("nfproto", neg, {str(v) for v in vals}))
    elif kind in ("iif", "oif"):
        out.append((kind, neg, [str(v) for v in vals]))
    elif kind in ("ct", "ctstatus"):
        out.append((kind, neg, {str(v).lower() for v in vals}))
    elif kind == "pkttype":
        out.append(("pkttype", neg, {str(v).lower() for v in vals}))
    elif kind == "fibtype":
        out.append(("fibtype", neg, {str(v).lower() for v in vals}))
    elif kind == "rpf":
        # "fib saddr . iif oif missing drop": the samples are routed back, so never "missing"
        out.append(("never", False, "rpf") if not neg and vals in ([False], ["missing"], [0]) else
                   ("unknown", False, text))
    return out, text


def _nft_vmap(rs, fam, table, v):
    kind, _ = _left(v.get("key"))
    data = v.get("data")
    elems = _elements(rs, fam, table, data) if not (isinstance(data, dict) and "set" in data) else data["set"]
    if kind is None or elems is None:
        return {"kind": None, "map": []}
    out = []
    for el in elems:
        if isinstance(el, tuple):
            key, verdict = el
        elif isinstance(el, list) and len(el) == 2:
            key, verdict = el
        else:
            return {"kind": None, "map": []}
        keys = _flat([key])
        if keys is None or not isinstance(verdict, dict) or not verdict:
            return {"kind": None, "map": []}
        vk = next(iter(verdict))
        target = (verdict[vk] or {}).get("target") if isinstance(verdict[vk], dict) else None
        out.append((keys, vk, target))
    return {"kind": kind, "map": out}


def _render(left, op, right):
    def r(x):
        if isinstance(x, dict):
            if "payload" in x:
                return f"{x['payload'].get('protocol')} {x['payload'].get('field')}"
            if "meta" in x:
                return f"meta {x['meta'].get('key')}"
            if "ct" in x:
                return "ct " + " ".join(str(v) for k, v in x["ct"].items() if k in ("dir", "key"))
            if "prefix" in x:
                return f"{x['prefix'].get('addr')}/{x['prefix'].get('len')}"
            if "range" in x:
                return "-".join(str(v) for v in x["range"])
            if "set" in x:
                items = x["set"] if isinstance(x["set"], list) else [x["set"]]
                return "{ " + ", ".join(r(i) for i in items[:8]) + (", …" if len(items) > 8 else "") + " }"
            if "fib" in x:
                return "fib " + " . ".join(x["fib"].get("flags") or []) + " " + str(x["fib"].get("result"))
            return next(iter(x), "?")
        if isinstance(x, list):
            return ",".join(r(i) for i in x)
        if isinstance(x, str) and not x.startswith("@") and not re.match(r"^[\w.:/-]+$", x):
            return '"' + x + '"'
        return str(x)
    o = "" if op in ("==", "in") else op + " "
    return f"{r(left)} {o}{r(right)}".strip()


# ---------------------------------------------------------------------------
# Samples and packets

class IpSet:
    """The members of an ipset as a source: a part of a sample whose
    addresses are not known."""

    def __init__(self, name):
        self.name = name

    def __eq__(self, other):
        return isinstance(other, IpSet) and other.name == self.name

    def __hash__(self):
        return hash(("ipset", self.name))

    def __str__(self):
        return "ipset " + self.name


class Sample:
    """A symbolic source: all of the internet of a family, a network, or the
    members of an ipset. `avoid` are the networks of other classes the sample
    is not in."""

    def __init__(self, fam, net=None, internet=False, avoid=(), ipset=None):
        self.fam, self.net, self.internet, self.ipset = fam, net, internet, ipset
        self.avoid = [n for n in avoid if n.version == fam]

    def label(self):
        return "internet" if self.internet else str(IpSet(self.ipset)) if self.ipset else str(self.net)

    def covered(self, n):
        if self.internet or self.ipset:
            return n.prefixlen == 0 or (self.fam == 6 and GLOBAL6.subnet_of(n))
        return self.net.subnet_of(n)

    def in_set(self, name, cands):
        """Whether the sample is in an ipset: the members of that set are; of
        any other sample they are a part, followed on its own."""
        if self.ipset is not None:
            return YES if self.ipset == name else MAYBE
        if IpSet(name) not in cands:
            cands.append(IpSet(name))
        return NO

    def part(self, n):
        """A narrower network inside the sample, or None."""
        if self.internet:
            if any(n.subnet_of(x) for x in NOT_INTERNET[self.fam]) or any(n.subnet_of(x) for x in self.avoid):
                return None
            return n
        if n.subnet_of(self.net) and n != self.net and not any(n.subnet_of(x) for x in self.avoid):
            return n
        return None

    def test(self, nets, cands):
        nets = [n for n in nets if n.version == self.fam]
        if any(self.covered(n) for n in nets):
            return YES
        if self.ipset is not None:
            return MAYBE if nets else NO        # whether its members are in a network is not known
        for n in nets:
            p = self.part(n)
            if p is not None and p not in cands:
                cands.append(p)
        return NO


class Packet:
    def __init__(self, fam, proto, iif, src, dst, dport, path, oif=None, orig_dst=None, orig_dport=None,
                 dnat=False):
        self.fam, self.proto, self.iif, self.src, self.dst, self.dport = fam, proto, iif, src, dst, dport
        self.path, self.oif, self.dnat = path, oif, dnat
        self.orig_dst = orig_dst if orig_dst is not None else dst
        self.orig_dport = orig_dport if orig_dport is not None else dport


class Outcome:
    def __init__(self, kind, rule=None, chain=None):
        self.kind, self.rule, self.chain = kind, rule, chain
        self.policy = False


# ---------------------------------------------------------------------------
# The evaluator

class Evaluator:
    def __init__(self, rs):
        self.rs = rs
        self.forks = 0
        self.cands = []

    def match(self, rule, pkt):
        """YES, NO, MAYBE or CHOICE (the sender decides) for a packet; source
        parts go to self.cands when the rest of the rule matches and the rule
        does not drop."""
        result = YES
        pending = []
        for kind, neg, value in rule.matches:
            if kind in ("saddr", "saddr_set"):
                local = []
                r = pkt.src.test(value, local) if kind == "saddr" else pkt.src.in_set(value, local)
                # A part of the sample takes the other way: worth following unless that way
                # only drops it (a ban list), i.e. unless a plain match leads to a drop.
                if neg or rule.verdict != DROP:
                    pending.extend(local)
            else:
                r = self._one(kind, value, pkt)
            if r in (MAYBE, CHOICE):
                if result == YES or (result == CHOICE and r == MAYBE):
                    result = r
                continue
            if neg:
                r = NO if r == YES else YES
            if r == NO and kind not in ("saddr", "saddr_set"):
                return NO
            if r == NO:
                result = NO
        if result == NO and not pending:
            return NO
        if pending:
            for p in pending:
                if p not in self.cands and len(self.cands) < MAX_CANDIDATES:
                    self.cands.append(p)
        return result

    def _one(self, kind, value, pkt):
        if kind == "proto":
            return YES if pkt.proto in value else NO
        if kind == "daddr":
            return YES if any(pkt.dst in n for n in value if n.version == pkt.fam) else NO
        if kind == "ctorigdst":
            return YES if any(pkt.orig_dst in n for n in value if n.version == pkt.fam) else NO
        if kind == "iif":
            return YES if iface_match(value, pkt.iif) else NO
        if kind == "oif":
            return YES if iface_match(value, pkt.oif) else NO
        if kind == "dport":
            return YES if any(lo <= pkt.dport <= hi for lo, hi in value) else NO
        if kind == "anyport":
            return YES if any(lo <= pkt.dport <= hi for lo, hi in value) else CHOICE
        if kind == "sport":
            return CHOICE                        # the sender picks its port
        if kind == "ctorigdstport":
            return YES if any(lo <= pkt.orig_dport <= hi for lo, hi in value) else NO
        if kind == "ct":
            return YES if "new" in value else NO
        if kind == "ctstatus":
            have = {"dnat"} if pkt.dnat else set()
            return YES if value & have else NO
        if kind == "addrtype_dst":
            have = {"UNICAST"} | ({"LOCAL"} if pkt.path == "input" else set())
            return YES if value & have else NO
        if kind == "addrtype_src":
            return YES if "UNICAST" in value else NO
        if kind == "fibtype":
            have = {"unicast"} | ({"local"} if pkt.path == "input" else set())
            return YES if value & have else NO
        if kind == "pkttype":
            return YES if "unicast" in value or "host" in value else NO
        if kind == "nfproto":
            return YES if ("ipv4" if pkt.fam == 4 else "ipv6") in value else NO
        if kind == "tcpflags":
            mask, comp = value
            if pkt.proto != "tcp":
                return NO
            return YES if ({"SYN"} & mask) == comp & mask else NO
        if kind == "always":
            return YES
        if kind == "never":
            return NO
        return MAYBE

    def run(self, base, pkt):
        """The verdict of one base chain: ACCEPT or DROP (by a rule or the
        policy, then Outcome.policy is True) or UNKNOWN. The walk keeps its
        own stack of (chain, next rule), so a rule it cannot read is followed
        both ways to the end of the base chain."""
        return self._walk([[base, 0]], pkt, base)

    def _policy(self, base):
        o = Outcome(ACCEPT if (base.policy or "accept") == "accept" else DROP, None, base)
        o.policy = True
        return o

    def _walk(self, stack, pkt, base):
        while True:
            if not stack:
                return self._policy(base)
            frame = stack[-1]
            chain, idx = frame
            if chain is None:
                return Outcome(UNKNOWN, None, base)
            if idx >= len(chain.rules):
                stack.pop()
                continue
            r = chain.rules[idx]
            frame[1] = idx + 1
            m = self.match(r, pkt)
            if m == NO:
                continue
            if m in (MAYBE, CHOICE):
                self.forks += 1
                if self.forks > MAX_FORKS:
                    return Outcome(UNKNOWN, r, chain)
                taken_stack = [list(f) for f in stack]
                taken = self._apply(taken_stack, r, chain, pkt)
                if taken is None:
                    taken = self._walk(taken_stack, pkt, base)
                skipped = self._walk([list(f) for f in stack], pkt, base)
                if taken.kind == skipped.kind and taken.kind != UNKNOWN:
                    return skipped
                if m == CHOICE and ACCEPT in (taken.kind, skipped.kind):
                    # the sender takes the way that lets it in
                    return taken if taken.kind == ACCEPT else skipped
                return Outcome(UNKNOWN, r, chain)
            o = self._apply(stack, r, chain, pkt)
            if o is not None:
                return o

    def _apply(self, stack, r, chain, pkt, verdict=None, target=None):
        """Applies a verdict: an Outcome when the base chain is decided, None
        to walk on (the stack changed for jump, goto and return)."""
        v = verdict or r.verdict
        target = target if verdict else r.target
        if v in (ACCEPT, DROP, UNKNOWN):
            return Outcome(v, r, chain)
        if v == "reject":
            return Outcome(DROP, r, chain)
        if v == CONTINUE:
            return None
        if v == RETURN:
            stack.pop()
            return None
        if v in ("jump", "goto"):
            sub = self.rs.find(r, target)
            if sub is None or len(stack) > MAX_DEPTH:
                return Outcome(UNKNOWN, r, chain)
            if v == "goto":
                stack[-1] = [sub, 0]
            else:
                stack.append([sub, 0])
            return None
        if v == "vmap":
            vm = r.vmap or {}
            kind = vm.get("kind")
            if kind is None or kind == "saddr":
                return Outcome(UNKNOWN, r, chain)
            for keys, verdict2, target2 in vm["map"]:
                hit = self._one(kind, _key_values(kind, keys), pkt)
                if hit in (MAYBE, CHOICE):
                    return Outcome(UNKNOWN, r, chain)
                if hit == YES:
                    return self._apply(stack, r, chain, pkt, verdict2 if verdict2 != "continue" else CONTINUE,
                                       target2)
            return None
        return Outcome(UNKNOWN, r, chain)

    def hook(self, pre, post, hooks):
        """Follows a packet through every base chain of the hooks (pre: before
        DNAT, post: after). Returns (kind, steps): one step per base chain
        with its result and the rule (or policy) that decided it."""
        steps = []
        unknown = None
        for c in self.rs.base_chains(post.fam, hooks, pre.iif):
            p = pre if c.hook in ("ingress", "prerouting") else post
            o = self.run(c, p)
            step = {"chain": c.ref(), "result": o.kind, "rule": o.rule.ref() if o.rule else None,
                    "policy": bool(getattr(o, "policy", False))}
            steps.append(step)
            if o.kind == DROP:
                return DROP, steps
            if o.kind == UNKNOWN and unknown is None:
                unknown = step
        if unknown:
            return UNKNOWN, steps
        return ACCEPT, steps


def _key_values(kind, keys):
    if kind in ("dport", "sport", "ctorigdstport"):
        return [(k, k) if isinstance(k, int) else k for k in keys]
    if kind in ("proto",):
        return {PROTOS.get(str(k), str(k)) for k in keys}
    if kind in ("ct", "ctstatus", "pkttype", "fibtype", "nfproto"):
        return {str(k).lower() for k in keys}
    return keys


# ---------------------------------------------------------------------------
# Reach of a port from a class of sources

def reach(rs, make, samples, avoid=()):
    """How a class of sources reaches a port. make(iface, sample) -> (pre,
    post, hooks); samples: [(iface, Sample)]. Returns {"result": open |
    restricted | closed | unknown, "steps", "sources", "unknown",
    "limited_by"}: for restricted, steps are those of an allowed source and
    limited_by is the step that stops the rest of the class."""
    results = []
    for iface, sample in samples:
        ev = Evaluator(rs)
        pre, post, hooks = make(iface, sample)
        kind, steps = ev.hook(pre, post, hooks)
        cands = list(ev.cands)
        if kind == ACCEPT:
            results.append({"result": "open", "steps": steps, "sources": [], "iface": iface})
            continue
        if kind == UNKNOWN:
            results.append({"result": "unknown", "steps": steps, "sources": [], "iface": iface,
                            "unknown": next((s for s in steps if s["result"] == UNKNOWN), None)})
            continue
        allowed, steps_allowed, unknown = [], None, None
        for c in cands[:MAX_CANDIDATES]:
            ev2 = Evaluator(rs)
            s2 = Sample(sample.fam, ipset=c.name) if isinstance(c, IpSet) else Sample(sample.fam, net=c, avoid=avoid)
            pre, post, hooks = make(iface, s2)
            k2, st2 = ev2.hook(pre, post, hooks)
            if k2 == ACCEPT:
                allowed.append(str(c))
                steps_allowed = steps_allowed or st2
            elif k2 == UNKNOWN and unknown is None:
                unknown = st2
        if allowed:
            # hook() ends with the base chain that dropped the class as a whole
            results.append({"result": "restricted", "steps": steps_allowed, "sources": allowed, "iface": iface,
                            "limited_by": steps[-1]})
        elif unknown:
            # only a part could get in, and for it a rule cannot be read: never "closed"
            results.append({"result": "unknown", "steps": unknown, "sources": [], "iface": iface,
                            "unknown": next((s for s in unknown if s["result"] == UNKNOWN), None)})
        else:
            results.append({"result": "closed", "steps": steps, "sources": [], "iface": iface})
    if not results:
        return {"result": "absent", "steps": [], "sources": []}
    for want in ("open", "unknown", "restricted"):
        hit = [r for r in results if r["result"] == want]
        if hit:
            out = dict(hit[0])
            if want == "restricted":
                out["sources"] = sorted({s for r in hit for s in r["sources"]})
            return out
    return results[0]


def find_dnat(rs, fam, proto, port, host_addr=None):
    """The DNAT of a published port: (to_addr, to_port, rule) or None."""
    for d in rs.dnat:
        if d["family"] != fam or (d["proto"] and d["proto"] != proto):
            continue
        if not d["ports"] or not any(lo <= port <= hi for lo, hi in d["ports"]):
            continue
        if d["daddr"] and host_addr not in (None, "0.0.0.0", "::"):
            try:
                a = ipaddress.ip_address(host_addr)
            except ValueError:
                continue
            if not any(a in n for n in d["daddr"]):
                continue
        elif d["daddr"] and host_addr in (None, "0.0.0.0", "::"):
            continue
        if d["to_addr"]:
            return d["to_addr"], d["to_port"] or port, d["rule"]
    return None
