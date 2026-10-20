#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The packet filter model (secfw.py): iptables-save and nft's JSON read into
chains, and the evaluator on UFW's, Docker's and hand-made rules: rate limits,
routing headers, DOCKER-USER with the original port, sources that cover only
part of a class, rules it cannot read, verdict maps, goto, missing chains.
Offline, no root needed."""

import ipaddress
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.join(HERE, "..", "lib"))
import secfw  # noqa: E402

FIX = os.path.join(HERE, "fixtures")
IP = ipaddress.ip_address
NET = ipaddress.ip_network


def fixture(*parts):
    with open(os.path.join(FIX, *parts), encoding="utf-8") as f:
        return f.read()


def ruleset(v4=None, v6=None, nft=None, skip=("ip", "ip6")):
    rs = secfw.Ruleset()
    if v4 is not None:
        secfw.parse_iptables_save(v4, 4, rs)
    if v6 is not None:
        secfw.parse_iptables_save(v6, 6, rs)
    if nft is not None:
        secfw.parse_nft_json(nft, rs, skip_iptables=skip)
    return rs


def verdict(rs, port, iif="eth0", src=None, fam=4, proto="tcp", dst=None, path="input", **kw):
    sample = secfw.Sample(fam, internet=True) if src is None else secfw.Sample(fam, net=NET(src))
    dst = IP(dst or ("203.0.113.10" if fam == 4 else "2001:db8:10::1"))
    pkt = secfw.Packet(fam, proto, iif, sample, dst, port, path, **kw)
    ev = secfw.Evaluator(rs)
    kind, steps = ev.hook(pkt, pkt, ("ingress", "prerouting", path))
    return kind, steps, ev


UFW4 = fixture("ufw-docker", "commands", "iptables-save.txt")
UFW6 = fixture("ufw-docker", "commands", "ip6tables-save.txt")


def table(text, rules):
    """A filter table with INPUT policy DROP and the rules given (iptables-save lines)."""
    return "*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n" + text + \
        "".join(r + "\n" for r in rules) + "COMMIT\n"


class Parsing(unittest.TestCase):
    def test_iptables_save(self):
        rs = ruleset(UFW4)
        c = rs.chains[("iptables", "ip", "filter", "INPUT")]
        self.assertEqual((c.hook, c.prio, c.policy), ("input", 0, "drop"))
        self.assertEqual(len(c.rules), 6)
        self.assertEqual(rs.chains[("iptables", "ip", "filter", "ufw-user-input")].rules[1].text,
                         "-p tcp -m multiport --dports 80,443 -j ACCEPT")
        self.assertEqual(rs.chains[("iptables", "ip", "nat", "PREROUTING")].ctype, "nat")
        self.assertIsNone(rs.chains[("iptables", "ip", "filter", "DOCKER")].hook)
        self.assertEqual(sorted((d["proto"], d["ports"], d["to_addr"], d["to_port"]) for d in rs.dnat),
                         [("tcp", [(5432, 5432)], "172.18.0.2", 5432), ("tcp", [(6379, 6379)], "172.18.0.3", 6379),
                          ("tcp", [(8080, 8080)], "172.17.0.2", 80)])
        self.assertEqual(secfw.find_dnat(rs, 4, "tcp", 8080, "0.0.0.0")[:2], ("172.17.0.2", 80))
        self.assertEqual(secfw.find_dnat(rs, 4, "tcp", 6379, "10.8.0.1")[:2], ("172.18.0.3", 6379))
        self.assertIsNone(secfw.find_dnat(rs, 4, "tcp", 6379, "0.0.0.0"), "a mapping bound to one address")
        self.assertIsNone(secfw.find_dnat(rs, 4, "udp", 8080, "0.0.0.0"))
        self.assertIsNone(secfw.find_dnat(rs, 6, "tcp", 8080, "::"))

    def test_owner(self):
        self.assertEqual(secfw.owner("filter", "ufw-user-input"), "ufw")
        self.assertEqual(secfw.owner("filter", "DOCKER-USER"), "docker")
        self.assertEqual(secfw.owner("f2b-table", "f2b-chain"), "fail2ban")
        self.assertEqual(secfw.owner("crowdsec", "crowdsec-chain"), "crowdsec")
        self.assertIsNone(secfw.owner("filter", "input"))

    def test_nft_json(self):
        rs = ruleset(nft=json.loads(fixture("nft-native", "commands", "nft.json")))
        self.assertNotIn(("nft", "ip", "filter", "INPUT"), rs.chains, "iptables-nft tables come from iptables-save")
        inp = rs.chains[("nft", "inet", "filter", "input")]
        self.assertEqual((inp.hook, inp.policy, len(inp.rules)), ("input", "drop", 10))
        self.assertEqual(inp.rules[0].verdict, "vmap")
        self.assertEqual(inp.rules[5].text, "tcp dport { 80, 443 } accept")
        self.assertEqual([c.name for c in rs.base_chains(4, ("input",))], ["input"])
        self.assertEqual([c.name for c in rs.base_chains(6, ("input",))], ["input"], "inet covers both")
        self.assertEqual(secfw._prio("dstnat - 5"), -105)
        self.assertEqual(secfw._prio("filter"), 0)

    def test_nft_sets(self):
        rs = ruleset(nft=json.loads(fixture("hetzner-open", "commands", "nft.json")))
        r = rs.chains[("nft", "ip", "crowdsec", "crowdsec-chain")].rules[0]
        self.assertEqual(r.matches, [("saddr", False, [NET("192.0.2.50/32"), NET("192.0.2.77/32")])])

    def test_broken_lines(self):
        rs = ruleset(table("", ['-A INPUT -p tcp --dport 22 -m comment --comment "unterminated -j ACCEPT',
                                "-A INPUT -j no-such-chain", "-A INPUT -m bpf --bytecode x -j ACCEPT"]))
        rules = rs.chains[("iptables", "ip", "filter", "INPUT")].rules
        self.assertEqual(len(rules), 3)
        self.assertEqual(rules[1].verdict, secfw.UNKNOWN)
        self.assertEqual(rules[2].matches[0][0], "unknown")


class Ufw(unittest.TestCase):
    def test_default_deny_and_allowed(self):
        rs = ruleset(UFW4, UFW6)
        self.assertEqual(verdict(rs, 22)[0], "drop")
        kind, steps, _ = verdict(rs, 443)
        self.assertEqual(kind, "accept")
        self.assertEqual(steps[0]["rule"]["chain"], "ufw-user-input")
        self.assertEqual(verdict(rs, 443, proto="udp")[0], "accept")
        self.assertEqual(verdict(rs, 22, iif="wg0", src="10.8.0.0/24")[0], "accept")
        self.assertEqual(verdict(rs, 22, iif="lo", src="127.0.0.0/8", dst="127.0.0.1")[0], "accept")
        kind, steps, _ = verdict(rs, 22)
        self.assertTrue(steps[-1]["policy"], "the policy drops it")

    def test_ipv6_routing_header_rule_is_no_obstacle(self):
        rs = ruleset(UFW4, UFW6)
        self.assertEqual(verdict(rs, 443, fam=6)[0], "accept")
        self.assertEqual(verdict(rs, 8080, fam=6)[0], "drop")

    def test_limit_lets_a_first_connection_in(self):
        rs = ruleset(table(fixture("hetzner-open", "files", "etc", "ufw", "user.rules").split("### RULES ###")[0]
                           .replace("*filter\n", "").replace(":ufw-user-input - [0:0]\n", ""),
                           [":ufw-user-input - [0:0]", "-A INPUT -j ufw-user-input",
                            "-A ufw-user-input -p tcp --dport 9090 -m conntrack --ctstate NEW -m recent --set",
                            "-A ufw-user-input -p tcp --dport 9090 -m conntrack --ctstate NEW -m recent --update "
                            "--seconds 30 --hitcount 6 -j ufw-user-limit",
                            "-A ufw-user-input -p tcp --dport 9090 -j ufw-user-limit-accept",
                            "-A ufw-user-limit -j REJECT", "-A ufw-user-limit-accept -j ACCEPT"]))
        kind, steps, ev = verdict(rs, 9090)
        self.assertEqual(kind, "accept")
        self.assertEqual(ev.forks, 0, "recent is read, not guessed")


class DockerUser(unittest.TestCase):
    def forward(self, rules, src=None, iif="eth0"):
        text = UFW4.replace("-A DOCKER -d 172.17.0.2/32", "\n".join(rules) + ("\n" if rules else "") +
                            "-A DOCKER -d 172.17.0.2/32", 1)
        rs = ruleset(text)
        sample = secfw.Sample(4, internet=True) if src is None else secfw.Sample(4, net=NET(src))
        pre = secfw.Packet(4, "tcp", iif, sample, IP("203.0.113.10"), 8080, "input")
        post = secfw.Packet(4, "tcp", iif, sample, IP("172.17.0.2"), 80, "forward", oif="docker0",
                            orig_dst=IP("203.0.113.10"), orig_dport=8080, dnat=True)
        ev = secfw.Evaluator(rs)
        return ev.hook(pre, post, ("ingress", "prerouting", "forward"))[0], ev

    def test_past_ufw(self):
        self.assertEqual(self.forward([])[0], "accept")

    def test_new_from_outside_dropped(self):
        rules = ["-A DOCKER-USER -o docker0 -m conntrack --ctstate NEW ! -s 10.8.0.0/24 -j DROP"]
        self.assertEqual(self.forward(rules)[0], "drop")
        self.assertEqual(self.forward(rules, src="10.8.0.0/24", iif="wg0")[0], "accept")

    def test_original_port(self):
        rules = ["-A DOCKER-USER -p tcp -m conntrack --ctorigdstport 8080 -j DROP"]
        self.assertEqual(self.forward(rules)[0], "drop")
        rules = ["-A DOCKER-USER -p tcp -m conntrack --ctorigdstport 9999 -j DROP"]
        self.assertEqual(self.forward(rules)[0], "accept")

    def test_only_from_one_network(self):
        rules = ["-A DOCKER-USER -i eth0 -s 198.51.100.0/24 -j RETURN", "-A DOCKER-USER -i eth0 -j DROP"]
        kind, ev = self.forward(rules)
        self.assertEqual(kind, "drop")
        self.assertEqual(ev.cands, [NET("198.51.100.0/24")], "the allowed part of the internet is followed")
        rs = ruleset(UFW4.replace("-A DOCKER -d 172.17.0.2/32", "\n".join(rules) + "\n-A DOCKER -d 172.17.0.2/32", 1))

        def make(iface, sample):
            pre = secfw.Packet(4, "tcp", iface, sample, IP("203.0.113.10"), 8080, "input")
            post = secfw.Packet(4, "tcp", iface, sample, IP("172.17.0.2"), 80, "forward", oif="docker0",
                                orig_dst=IP("203.0.113.10"), orig_dport=8080, dnat=True)
            return pre, post, ("ingress", "prerouting", "forward")
        r = secfw.reach(rs, make, [("eth0", secfw.Sample(4, internet=True))])
        self.assertEqual((r["result"], r["sources"]), ("restricted", ["198.51.100.0/24"]))
        lim = r["limited_by"]
        self.assertEqual((lim["result"], lim["chain"]["chain"], lim["rule"]["chain"], lim["rule"]["text"]),
                         ("drop", "FORWARD", "DOCKER-USER", "-i eth0 -j DROP"), "the rule that keeps the rest out")
        self.assertEqual(r["steps"][-1]["rule"]["chain"], "DOCKER", "the steps are those of the allowed network")

    def test_ban_lists_are_not_followed(self):
        rules = ["-A DOCKER-USER -s 192.0.2.50/32 -j DROP", "-A DOCKER-USER -s 192.0.2.51/32 -j DROP"]
        kind, ev = self.forward(rules)
        self.assertEqual((kind, ev.cands), ("accept", []))


class Unknown(unittest.TestCase):
    def test_both_ways_end_the_same(self):
        rs = ruleset(table("", ["-A INPUT -m mark --mark 0x1 -j DROP"]))
        kind, _, ev = verdict(rs, 22)
        self.assertEqual((kind, ev.forks), ("drop", 1), "dropped either way")

    def test_both_ways_differ(self):
        rs = ruleset(table("", ["-A INPUT -m mark --mark 0x1 -j ACCEPT"]))
        kind, steps, _ = verdict(rs, 22)
        self.assertEqual(kind, "unknown")
        self.assertEqual(steps[0]["rule"]["text"], "-m mark --mark 0x1 -j ACCEPT")

    def test_fork_across_chains(self):
        rs = ruleset(table(":sub - [0:0]\n", ["-A INPUT -j sub", "-A sub -m mark --mark 0x1 -j DROP",
                                              "-A INPUT -p tcp --dport 22 -j ACCEPT"]))
        self.assertEqual(verdict(rs, 22)[0], "unknown", "drop in sub vs accept after its return")
        self.assertEqual(verdict(rs, 23)[0], "drop", "drop in sub vs the policy")

    def test_too_many_forks(self):
        rs = ruleset(table("", [f"-A INPUT -m mark --mark {i} -j DROP" for i in range(80)]))
        kind, _, ev = verdict(rs, 22)
        self.assertEqual(kind, "unknown")
        self.assertGreater(ev.forks, secfw.MAX_FORKS)

    def test_queue(self):
        rs = ruleset(table("", ["-A INPUT -p tcp --dport 22 -j NFQUEUE --queue-num 1"]))
        self.assertEqual(verdict(rs, 22)[0], "unknown")

    def test_ipset_as_destination(self):
        rs = ruleset(table("", ["-A INPUT -m set --match-set mine dst -j ACCEPT"]))
        kind, steps, _ = verdict(rs, 22)
        self.assertEqual(kind, "unknown", "whether the host's own address is in the set is not known")
        self.assertEqual(steps[0]["rule"]["text"], "-m set --match-set mine dst -j ACCEPT")

    def test_part_that_cannot_be_read(self):
        """Only a part of the internet could get in, and for that part a rule cannot be read:
        unknown, not closed."""
        rs = ruleset(table("", ["-A INPUT -s 198.51.100.0/24 -m mark --mark 0x1 -j ACCEPT"]))

        def make(iface, sample):
            pkt = secfw.Packet(4, "tcp", iface, sample, IP("203.0.113.10"), 22, "input")
            return pkt, pkt, ("ingress", "prerouting", "input")
        r = secfw.reach(rs, make, [("eth0", secfw.Sample(4, internet=True))])
        self.assertEqual(r["result"], "unknown")
        self.assertEqual(r["unknown"]["rule"]["text"], "-s 198.51.100.0/24 -m mark --mark 0x1 -j ACCEPT")


class IpSets(unittest.TestCase):
    """An ipset as the source (its members are not in iptables-save): a sample of its own,
    "reachable only from the addresses in set …" (a geo list of public-host's RustDesk)."""

    def reach(self, rules, port=21115):
        rs = ruleset(table("", rules))

        def make(iface, sample):
            pkt = secfw.Packet(4, "tcp", iface, sample, IP("203.0.113.10"), port, "input")
            return pkt, pkt, ("ingress", "prerouting", "input")
        return secfw.reach(rs, make, [("eth0", secfw.Sample(4, internet=True))])

    def test_parsing(self):
        rs = ruleset(table("", ["-A INPUT -p tcp -m multiport --dports 21115,21116 -m set ! --match-set germany src "
                                "--return-nomatch -j DROP"]))
        r = rs.chains[("iptables", "ip", "filter", "INPUT")].rules[0]
        self.assertEqual(r.matches, [("proto", False, {"tcp"}), ("dport", False, [(21115, 21115), (21116, 21116)]),
                                     ("saddr_set", True, "germany")])

    def test_only_from_the_members(self):
        rules = ["-A INPUT -p tcp -m multiport --dports 21115,21116 -m set ! --match-set germany src -j DROP",
                 "-A INPUT -p tcp --dport 21115 -j ACCEPT"]
        kind, _, ev = verdict(ruleset(table("", rules)), 21115)
        self.assertEqual((kind, ev.cands, ev.forks), ("drop", [secfw.IpSet("germany")], 0))
        r = self.reach(rules)
        self.assertEqual((r["result"], r["sources"]), ("restricted", ["ipset germany"]))
        self.assertEqual(r["steps"][0]["rule"]["text"], "-p tcp --dport 21115 -j ACCEPT")
        self.assertEqual(r["limited_by"]["rule"]["text"],
                         "-p tcp -m multiport --dports 21115,21116 -m set ! --match-set germany src -j DROP",
                         "the geo rule keeps the rest out")
        self.assertEqual(self.reach(rules, port=21117)["result"], "closed", "other ports: the policy")
        self.assertNotIn("limited_by", self.reach(rules, port=21117))

    def test_allow_list(self):
        r = self.reach(["-A INPUT -m set --match-set office src -j ACCEPT"])
        self.assertEqual((r["result"], r["sources"]), ("restricted", ["ipset office"]))
        lim = r["limited_by"]
        self.assertEqual((lim["result"], lim["rule"], lim["policy"], lim["chain"]["policy"]),
                         ("drop", None, True, "drop"), "everyone else: the policy")

    def test_ban_list_is_not_followed(self):
        rules = ["-A INPUT -m set --match-set banned src -j DROP", "-A INPUT -p tcp --dport 21115 -j ACCEPT"]
        kind, _, ev = verdict(ruleset(table("", rules)), 21115)
        self.assertEqual((kind, ev.cands, ev.forks), ("accept", [], 0), "open to all but the banned")

    def test_members_against_networks(self):
        r = self.reach(["-A INPUT -m set --match-set office src -j x", "-A x -s 0.0.0.0/0 -j ACCEPT"])
        self.assertEqual((r["result"], r["sources"]), ("restricted", ["ipset office"]))
        r = self.reach(["-A INPUT -m set --match-set office src -j x", "-A x -s 198.51.100.0/24 -j ACCEPT"])
        self.assertEqual(r["result"], "unknown", "whether the members are in that network is not known")
        self.assertEqual(r["unknown"]["rule"]["text"], "-s 198.51.100.0/24 -j ACCEPT")


class SourcePort(unittest.TestCase):
    """The sender picks its source port: a rule for some source port lets it in."""

    def test_dhcp_reply_rule(self):
        rs = ruleset(table("", ["-A INPUT -p udp -m udp --sport 67 --dport 68 -j ACCEPT"]))
        kind, steps, ev = verdict(rs, 68, proto="udp")
        self.assertEqual((kind, ev.forks), ("accept", 1))
        self.assertEqual(steps[0]["rule"]["text"], "-p udp -m udp --sport 67 --dport 68 -j ACCEPT")
        self.assertEqual(verdict(rs, 69, proto="udp")[0], "drop")

    def test_drop_by_source_port_is_avoided(self):
        rs = ruleset(table("", ["-A INPUT -p tcp -m tcp --sport 1:1023 -j DROP", "-A INPUT -p tcp --dport 22 -j ACCEPT"]))
        self.assertEqual(verdict(rs, 22)[0], "accept")
        rs = ruleset(table("", ["-A INPUT -p tcp -m tcp --sport 1:1023 -j DROP"]))
        self.assertEqual(verdict(rs, 22)[0], "drop", "dropped either way")

    def test_any_port(self):
        rs = ruleset(table("", ["-A INPUT -p tcp -m multiport --ports 5000 -j ACCEPT"]))
        self.assertEqual(verdict(rs, 22)[0], "accept", "from source port 5000")
        self.assertEqual(verdict(rs, 5000)[0], "accept")

    def test_with_a_rule_it_cannot_read(self):
        rs = ruleset(table("", ["-A INPUT -p udp -m udp --sport 67 -m mark --mark 0x1 -j ACCEPT"]))
        self.assertEqual(verdict(rs, 68, proto="udp")[0], "unknown")


class Chains(unittest.TestCase):
    def test_goto_returns_from_the_caller(self):
        rs = ruleset(table(":a - [0:0]\n:b - [0:0]\n", ["-A INPUT -j a", "-A INPUT -p tcp --dport 22 -j ACCEPT",
                                                         "-A a -g b", "-A a -j DROP", "-A b -p tcp --dport 80 -j DROP"]))
        self.assertEqual(verdict(rs, 22)[0], "accept", "b returns to INPUT, not to a")
        self.assertEqual(verdict(rs, 80)[0], "drop")

    def test_two_base_chains(self):
        nft = {"nftables": [
            {"chain": {"family": "inet", "table": "t", "name": "in", "hook": "input", "prio": -10, "type": "filter",
                       "policy": "accept"}},
            {"rule": {"family": "inet", "table": "t", "chain": "in", "expr": [
                {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 5432}},
                {"drop": None}]}}]}
        rs = ruleset(table("", ["-A INPUT -j ACCEPT"]), nft=nft)
        self.assertEqual(verdict(rs, 5432)[0], "drop", "a drop in any base chain is final")
        self.assertEqual(verdict(rs, 22)[0], "accept")

    def test_vmap(self):
        rs = ruleset(nft=json.loads(fixture("nft-native", "commands", "nft.json")))
        self.assertEqual(verdict(rs, 9090, iif="wg0", src="10.8.0.0/24", dst="10.8.0.4")[0], "accept")
        self.assertEqual(verdict(rs, 9090, dst="198.51.100.30")[0], "drop")
        self.assertEqual(verdict(rs, 1234, iif="lo", src="127.0.0.0/8", dst="127.0.0.1")[0], "accept")
        kind, _, ev = verdict(rs, 60001, dst="198.51.100.30")
        self.assertEqual((kind, ev.cands), ("drop", [NET("192.0.2.0/24")]))

    def test_netdev_ingress(self):
        nft = {"nftables": [
            {"chain": {"family": "netdev", "table": "edge", "name": "ingress", "hook": "ingress", "prio": -500,
                       "type": "filter", "dev": "eth0", "policy": "accept"}},
            {"rule": {"family": "netdev", "table": "edge", "chain": "ingress", "expr": [
                {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 22}},
                {"drop": None}]}}]}
        rs = ruleset(table("", ["-A INPUT -j ACCEPT"]), nft=nft)
        self.assertEqual(verdict(rs, 22)[0], "drop")
        self.assertEqual(verdict(rs, 22, iif="wg0", src="10.8.0.0/24")[0], "accept", "only on its device")


class Samples(unittest.TestCase):
    def test_internet(self):
        s = secfw.Sample(4, internet=True)
        c = []
        self.assertEqual(s.test([NET("0.0.0.0/0")], c), secfw.YES)
        self.assertEqual(s.test([NET("10.0.0.0/8")], c), secfw.NO)
        self.assertEqual(c, [])
        self.assertEqual(s.test([NET("198.51.100.0/24")], c), secfw.NO)
        self.assertEqual(c, [NET("198.51.100.0/24")])
        s6 = secfw.Sample(6, internet=True)
        self.assertEqual(s6.test([NET("2000::/3")], []), secfw.YES)
        self.assertEqual(s6.test([NET("fd00::/8")], []), secfw.NO)

    def test_network(self):
        s = secfw.Sample(4, net=NET("10.0.0.0/8"), avoid=[NET("10.8.0.0/24")])
        c = []
        self.assertEqual(s.test([NET("10.0.0.0/8")], c), secfw.YES)
        self.assertEqual(s.test([NET("10.8.0.0/24")], c), secfw.NO)
        self.assertEqual(c, [], "another class's network is not a part of this one")
        self.assertEqual(s.test([NET("10.0.1.0/24")], c), secfw.NO)
        self.assertEqual(c, [NET("10.0.1.0/24")])


if __name__ == "__main__":
    unittest.main(verbosity=1)
