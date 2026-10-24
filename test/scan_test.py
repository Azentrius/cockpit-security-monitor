#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Every check of seccheck.py against the scenarios in test/fixtures/ (through
test/fakesys.py): reach of each port from each class with the reason, the
assessment of spec 4.2, SSH, logins, containers, CrowdSec, fail2ban; variants
of the scenarios (a DOCKER-USER rule, no Hetzner token, a stale Hetzner answer,
Hetzner rules not known, no root, Docker failing, iptables-legacy rules, the
addresses or the sockets not read, fail2ban not read completely); the marks;
and that the state-*.json and status-*.json fixtures are current. Offline."""

import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.dont_write_bytecode = True
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "lib"))
sys.path.insert(0, os.path.join(HERE, "fixtures"))
import fakesys  # noqa: E402
import make_states  # noqa: E402
import seccheck  # noqa: E402
import secproc  # noqa: E402

FIX = os.path.join(HERE, "fixtures")


def scan(scenario, **kw):
    return seccheck.scan(fakesys.FakeSystem(scenario, **kw))


def ports(doc):
    return {f"{p['port']}/{p['proto']}": p for p in doc["ports"]}


def reach(p, fam="4"):
    return {c: p["reach"][fam][c]["result"] for c in seccheck.CLASSES}


def fixture(*parts):
    with open(os.path.join(FIX, *parts), encoding="utf-8") as f:
        return f.read()


class UfwDocker(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc = scan("ufw-docker")
        cls.p = ports(cls.doc)

    def test_sources(self):
        self.assertEqual({k: v["state"] for k, v in self.doc["sources"].items()},
                         {"ip": "ok", "ss": "ok", "docker": "ok", "rules": "ok", "ufw": "ok", "hetzner": "skipped",
                          "sshd": "ok", "keys": "ok", "journal": "ok", "crowdsec": "missing",
                          "fail2ban": "missing"})
        self.assertEqual(self.doc["firewall"]["input_filter"], {4: "on", 6: "on"})
        self.assertEqual(self.doc["firewall"]["iptables"], {"version": "1.8.10", "variant": "nf_tables"})
        self.assertEqual(self.doc["network"]["public"], {"4": True, "6": True})

    def test_states(self):
        got = {k: (p["state"], p["why"]) for k, p in self.p.items()}
        self.assertEqual(got, {
            "22/tcp": ("ok", "only-vpn"), "53/tcp": ("ok", "local"), "53/udp": ("ok", "local"),
            "80/tcp": ("info", "public-expected"), "323/udp": ("ok", "local"), "443/tcp": ("info", "public-expected"),
            "443/udp": ("info", "public-expected"), "5432/tcp": ("ok", "local"), "6379/tcp": ("ok", "only-vpn"),
            "8080/tcp": ("warning", "public-other"), "9090/tcp": ("ok", "only-vpn"), "9100/tcp": ("ok", "only-vpn"),
            "51820/udp": ("info", "public-expected")})

    def test_docker_past_ufw(self):
        """Docker publishes 0.0.0.0:8080: forwarded past UFW to the container; IPv6 goes to
        docker-proxy on the host, where UFW applies."""
        p = self.p["8080/tcp"]
        self.assertEqual(reach(p, "4"), {"internet": "open", "vpn": "open", "private": "open", "local": "open"})
        inet = p["reach"]["4"]["internet"]
        self.assertEqual(inet["path"], "forward")
        self.assertEqual(inet["to"]["addr"], "172.17.0.2")
        self.assertEqual(inet["to"]["port"], 80)
        self.assertEqual(inet["steps"][0]["rule"]["chain"], "DOCKER")
        self.assertEqual(inet["steps"][0]["rule"]["owner"], "docker")
        v6 = p["reach"]["6"]["internet"]
        self.assertEqual((v6["result"], v6["path"], v6.get("proxy")), ("closed", "input", True))
        self.assertTrue(v6["steps"][-1]["policy"])
        self.assertEqual(p["service"]["containers"], ["web"])
        self.assertEqual(p["service"]["container_ports"], [80])

    def test_bound_addresses(self):
        self.assertEqual(reach(self.p["6379/tcp"]), {"internet": "absent", "vpn": "open", "private": "absent",
                                                     "local": "open"})
        self.assertEqual(reach(self.p["5432/tcp"]), {"internet": "absent", "vpn": "absent", "private": "absent",
                                                     "local": "open"})
        self.assertEqual(reach(self.p["53/udp"])["local"], "open")
        self.assertEqual(reach(self.p["22/tcp"], "6")["vpn"], "absent", "wg0 has no IPv6 address")

    def test_ufw_and_services(self):
        ufw = self.doc["firewall"]["ufw"]
        self.assertEqual((ufw["enabled"], ufw["loaded"], ufw["rules_total"]), (True, {"4": True, "6": True}, 8))
        self.assertEqual(self.p["22/tcp"]["service"]["processes"], ["sshd"], "systemd's socket is left out")
        self.assertEqual(self.p["51820/udp"]["service"]["kind"], "kernel")
        self.assertEqual(self.p["51820/udp"]["name"], "wireguard")
        self.assertEqual(self.p["9090/tcp"]["name"], "cockpit")
        inet = self.p["9090/tcp"]["reach"]["4"]["internet"]
        self.assertEqual((inet["result"], inet["steps"][-1]["policy"]), ("closed", True))
        vpn = self.p["9090/tcp"]["reach"]["4"]["vpn"]
        self.assertEqual(vpn["steps"][0]["rule"]["text"], "-i wg0 -j ACCEPT")

    def test_ssh(self):
        ssh = self.doc["ssh"]
        self.assertEqual(ssh["sshd"], {"state": "ok", "match": []})
        self.assertEqual({f["key"]: f["state"] for f in ssh["findings"] if f["state"] != "ok"},
                         {"permitrootlogin": "info", "allowusers": "info", "x11forwarding": "info",
                          "allowagentforwarding": "info"})
        files = {f["user"]: f for f in ssh["keys"]}
        self.assertEqual(sorted(files), ["alex", "root"])
        self.assertEqual((files["alex"]["problems"], files["alex"]["state"]), (["file-writable"], "warning"))
        self.assertEqual(files["root"]["state"], "ok")
        self.assertEqual(ssh["state"], "warning")
        self.assertEqual(ssh["ports"], ["22"])

    def test_locked_account_with_keys(self):
        """alex's password is locked with passwd -l ("!" before a hash), but sshd uses PAM and
        does not check the lock: the keys still log in. root's "*" is no lock but no password."""
        files = {f["user"]: f for f in self.doc["ssh"]["keys"]}
        self.assertEqual(files["alex"]["account"], {"password": "locked", "expired": False,
                                                    "finding": "locked-with-keys"})
        self.assertEqual(files["root"]["account"], {"password": "none", "expired": False})

    def test_locked_account_variants(self):
        def alex(**kw):
            doc = scan("ufw-docker", **kw)
            return next(f for f in doc["ssh"]["keys"] if f["user"] == "alex").get("account")
        shadow = fixture("ufw-docker", "files", "etc", "shadow")
        expired = shadow.replace(":20370:0:99999:7:::", ":20370:0:99999:7::20000:")
        self.assertEqual(alex(files={"/etc/shadow": expired}), {"password": "locked", "expired": True},
                         "an expired account refuses keys too")
        nopam = fixture("ufw-docker", "commands", "sshd-T.txt").replace("usepam yes", "usepam no")
        self.assertEqual(alex(results={"sshd-T": nopam}), {"password": "locked", "expired": False},
                         "without PAM sshd refuses a locked account itself")
        alex_line = next(line for line in shadow.splitlines() if line.startswith("alex:"))
        keyonly = shadow.replace(alex_line, "alex:!:20370:0:99999:7:::")
        self.assertEqual(alex(files={"/etc/shadow": keyonly}), {"password": "none", "expired": False},
                         "an account without a password is key-only by design")
        self.assertIsNone(alex(uid=1000), "without root /etc/shadow is not read")
        self.assertIsNone(alex(files={"/etc/shadow": None}))

    def test_logins(self):
        lg = self.doc["logins"]
        self.assertEqual((lg["state"], lg["success_total"], lg["outside"], lg["failed_total"]), ("ok", 3, 0, 1))
        self.assertEqual(lg["success"][0]["time"], "2026-10-20T11:55:00Z")
        self.assertEqual(lg["assessment"], "ok")

    def test_journal_start(self):
        """The oldest entry within the 14 days (journalctl --lines=+1): here 9 days and 4 hours
        back. Without an answer (systemd before 254) it stays unknown."""
        self.assertEqual(self.doc["logins"]["journal_start"], "2026-10-11T08:00:00Z")
        self.assertIsNone(scan("hetzner-open")["logins"]["journal_start"])
        bad = scan("ufw-docker", results={"journal-start": secproc.Result(1, "", "journalctl: invalid option")})
        self.assertIsNone(bad["logins"]["journal_start"])
        empty = scan("ufw-docker", results={"journal-start": ""})
        self.assertIsNone(empty["logins"]["journal_start"])

    def test_containers(self):
        items = {c["name"]: [(f["kind"], f["state"]) for f in c["findings"]] for c in self.doc["containers"]["items"]}
        self.assertEqual(items["runner"], [("docker-socket", "danger"), ("root-user", "info"),
                                           ("no-new-privileges", "info")])
        self.assertEqual(items["cache"], [])
        self.assertEqual(self.doc["firewall"]["docker"], {"version": "28.5.1", "backend": "iptables",
                                                          "backend_known": True, "containers": 4})


class HetznerOpen(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc = scan("hetzner-open")
        cls.p = ports(cls.doc)

    def test_protected_by_hetzner(self):
        self.assertEqual(self.doc["firewall"]["input_filter"], {4: "off", 6: "off"})
        self.assertEqual(self.doc["firewall"]["hetzner"]["state"], "ok")
        got = {k: (p["state"], p["why"]) for k, p in self.p.items()}
        self.assertEqual(got, {
            "22/tcp": ("ok", "hetzner"), "53/tcp": ("ok", "local"), "53/udp": ("ok", "local"),
            "80/tcp": ("info", "public-expected"), "443/tcp": ("info", "public-expected"),
            "443/udp": ("info", "public-expected"), "5432/tcp": ("ok", "hetzner"),
            "8443/tcp": ("info", "restricted"), "21115/tcp": ("ok", "hetzner"), "21116/tcp": ("ok", "hetzner"),
            "21116/udp": ("ok", "hetzner")})
        pg = self.p["5432/tcp"]["reach"]["4"]["internet"]
        self.assertEqual((pg["host_result"], pg["hetzner"]["result"]), ("open", "blocks"))
        self.assertEqual(pg["hetzner"]["refs"], [{"firewall": "web", "id": 38}])
        office = self.p["8443/tcp"]["reach"]["4"]["internet"]
        self.assertEqual((office["result"], office["sources"]), ("restricted", ["198.51.100.0/24"]))
        self.assertNotIn("limited_by", office, "the host lets everyone in; the Hetzner firewall limits it")
        self.assertEqual(self.p["8443/tcp"]["reach"]["6"]["internet"]["result"], "closed",
                         "the rule names no IPv6 source")
        self.assertEqual(reach(self.p["5432/tcp"])["private"], "open", "Hetzner's private network is not filtered")

    def test_without_token(self):
        """Firewall off and the Hetzner firewall unknown: only rules outside this host could protect
        the ports (spec 4.2), for databases too."""
        doc = scan("hetzner-open", files={seccheck.HETZNER_TOKEN: None})
        got = {k: (p["state"], p["why"]) for k, p in ports(doc).items() if p["why"] != "local"}
        self.assertEqual(set(got.values()), {("warning", "outside-only")})
        h = doc["sources"]["hetzner"]
        self.assertEqual((h["state"], h["reason"]), ("skipped", "no-token"))

    def test_stale_answer_still_counts(self):
        h = json.loads(fixture("hetzner-open", "files", "var", "lib", "cockpit-security-hetzner", "hetzner.json"))
        h.update(tried_at="2026-10-20T11:59:00Z", error="HTTP 503 unavailable", ok_at="2026-10-20T08:00:00Z")
        doc = scan("hetzner-open", files={seccheck.HETZNER_FILE: json.dumps(h)})
        hz = doc["firewall"]["hetzner"]
        self.assertEqual((hz["state"], hz["ok_at"], hz["error"]), ("stale", "2026-10-20T08:00:00Z",
                                                                   "HTTP 503 unavailable"))
        self.assertEqual(ports(doc)["5432/tcp"]["why"], "hetzner")

    def test_not_matched_or_unreadable(self):
        h = json.loads(fixture("hetzner-open", "files", "var", "lib", "cockpit-security-hetzner", "hetzner.json"))
        h.update(server=None, firewalls=[])
        doc = scan("hetzner-open", files={seccheck.HETZNER_FILE: json.dumps(h)})
        self.assertEqual(doc["firewall"]["hetzner"]["state"], "not-matched")
        self.assertEqual(ports(doc)["5432/tcp"]["why"], "outside-only")
        doc = scan("hetzner-open", files={seccheck.HETZNER_FILE: "{broken"})
        self.assertEqual(doc["firewall"]["hetzner"]["state"], "unreadable")
        doc = scan("hetzner-open", files={seccheck.HETZNER_FILE: None})
        self.assertEqual(doc["firewall"]["hetzner"]["state"], "pending")

    def test_unknown_rules_never_protect(self):
        """A firewall applied to the server but missing from the API's answer (rules null, as
        security-hetzner.py writes it) may let anything in: it counts as no answer, so with the
        host's filter off the ports are "only rules outside could protect it", never blocked."""
        def unknown(h):
            h["firewalls"][0]["rules"] = None
        doc = scan("hetzner-open", **fakesys.hetzner_firewalls(unknown))
        p = ports(doc)
        pg = p["5432/tcp"]["reach"]["4"]["internet"]
        self.assertEqual((p["5432/tcp"]["state"], p["5432/tcp"]["why"]), ("warning", "outside-only"))
        self.assertEqual((pg["result"], pg["hetzner"]["result"], pg["hetzner"]["refs"]),
                         ("open", "unknown", [{"firewall": "web", "id": 38}]))
        self.assertNotIn("host_result", pg)
        got = {k: (x["state"], x["why"]) for k, x in p.items() if x["why"] != "local"}
        self.assertEqual(set(got.values()), {("warning", "outside-only")}, "80 and 443 are not known as allowed either")
        self.assertEqual((doc["sources"]["hetzner"]["state"], doc["sources"]["hetzner"]["missing"]), ("partial", "rules"))

        def unnamed(h):
            h["firewalls"][0].update(name=None, rules=None)
        pg = ports(scan("hetzner-open", **fakesys.hetzner_firewalls(unnamed)))["5432/tcp"]
        self.assertEqual((pg["why"], pg["reach"]["4"]["internet"]["hetzner"]["refs"]),
                         ("outside-only", [{"firewall": "", "id": 38}]))

    def test_empty_rule_list_blocks_everything(self):
        """[] is known: a firewall without incoming rules lets nothing in."""
        doc = scan("hetzner-open", **fakesys.hetzner_firewalls(lambda h: h["firewalls"][0].update(rules=[])))
        got = {k: (x["state"], x["why"]) for k, x in ports(doc).items() if x["why"] != "local"}
        self.assertEqual(set(got.values()), {("ok", "hetzner")})
        self.assertEqual(doc["sources"]["hetzner"]["state"], "ok")

    def test_several_firewalls(self):
        """Hetzner joins the rules of every firewall applied. One whose rules are not known makes a
        port unknown unless a known rule lets the whole internet in anyway."""
        def add(second):
            return fakesys.hetzner_firewalls(
                lambda h: h["firewalls"].append(dict({"id": 39, "status": "applied"}, **second)))
        p = ports(scan("hetzner-open", **add({"name": "lost", "rules": None})))
        self.assertEqual((p["80/tcp"]["state"], p["80/tcp"]["why"]), ("info", "public-expected"), "web allows 80 to all")
        self.assertEqual(p["80/tcp"]["reach"]["4"]["internet"]["hetzner"]["result"], "allows")
        self.assertEqual(p["5432/tcp"]["why"], "outside-only")
        self.assertEqual(p["5432/tcp"]["reach"]["4"]["internet"]["hetzner"]["refs"], [{"firewall": "lost", "id": 39}])
        self.assertEqual(p["8443/tcp"]["why"], "outside-only", "restricted by web, but lost may let everyone in")
        p = ports(scan("hetzner-open", **add({"name": "db", "rules": [
            {"direction": "in", "protocol": "tcp", "port": "5432", "source_ips": ["0.0.0.0/0"], "description": "PG"}]})))
        self.assertEqual((p["5432/tcp"]["state"], p["5432/tcp"]["why"]), ("danger", "public-danger"),
                         "the union of the rules")
        self.assertEqual(p["22/tcp"]["why"], "hetzner", "neither lets 22 in")
        p = ports(scan("hetzner-open", **add({"name": "empty", "rules": []})))
        self.assertEqual((p["5432/tcp"]["why"], p["8443/tcp"]["why"]), ("hetzner", "restricted"), "[] adds no rule")

    def test_logins_from_outside(self):
        lg = self.doc["logins"]
        self.assertEqual((lg["outside"], lg["assessment"], lg["failed_sources"]), (1, "warning", 3))

    def test_crowdsec(self):
        cs = self.doc["crowdsec"]
        self.assertEqual([f["code"] for f in cs["findings"]], ["old-engine", "bouncer-input-only"])
        self.assertEqual((cs["state"], cs["sharing"], cs["decisions_total"], cs["alerts_total"]),
                         ("warning", True, 2, 3))
        self.assertEqual(cs["scenarios"][0], {"scenario": "crowdsecurity/ssh-bf", "count": 2})
        self.assertEqual(cs["bouncers"][0]["version"], "v0.0.25-debian-pragmatic-e2cba8fa")

    def test_crowdsec_bouncer_with_forward_hook(self):
        conf = fixture("hetzner-open", "files", "etc", "crowdsec", "bouncers", "crowdsec-firewall-bouncer.yaml")
        conf = conf.replace("mode: nftables", "mode: nftables\nnftables_hooks:\n  - input\n  - forward")
        doc = scan("hetzner-open", files={seccheck.BOUNCER_CONF: conf})
        self.assertEqual([f["code"] for f in doc["crowdsec"]["findings"]], ["old-engine"])

    def test_ssh_passwords(self):
        self.assertEqual({f["code"] for f in self.doc["ssh"]["findings"] if f["state"] == "warning"},
                         {"password-on", "root-yes"})

    def test_containers(self):
        items = {c["name"]: [f["kind"] for f in c["findings"] if f["state"] == "warning"]
                 for c in self.doc["containers"]["items"]}
        self.assertEqual(items, {"caddy": [], "onlyoffice": ["privileged"], "postgres": [], "rustdesk": ["cap-add"]})


class NftNative(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc = scan("nft-native")
        cls.p = ports(cls.doc)

    def test_states(self):
        got = {k: (p["state"], p["why"]) for k, p in self.p.items()}
        self.assertEqual(got, {
            "22/tcp": ("ok", "only-vpn"), "53/tcp": ("ok", "local"), "53/udp": ("ok", "local"),
            "80/tcp": ("info", "public-expected"), "443/tcp": ("info", "public-expected"),
            "2222/tcp": ("ok", "only-vpn"), "3000/tcp": ("warning", "public-other"),
            "9090/tcp": ("ok", "only-vpn"), "9100/tcp": ("ok", "only-vpn"), "51820/udp": ("info", "public-expected"),
            "60001/tcp": ("info", "restricted")})
        inet = self.p["60001/tcp"]["reach"]["4"]["internet"]
        self.assertEqual(inet["sources"], ["192.0.2.0/24"])
        self.assertEqual(inet["steps"][-1]["rule"]["text"], "tcp dport 60000-60010 ip saddr 192.0.2.0/24 accept")
        lim = inet["limited_by"]
        self.assertEqual((lim["result"], lim["rule"], lim["policy"], lim["chain"]["chain"], lim["chain"]["family"]),
                         ("drop", None, True, "input", "inet"), "everyone else: the policy of nft's input chain")
        self.assertEqual(self.p["9100/tcp"]["service"]["containers"], ["monitor"], "from the process's cgroup")
        self.assertEqual(self.doc["network"]["public"], {"4": True, "6": False})

    def test_sshd_not_checkable(self):
        ssh = self.doc["ssh"]
        self.assertEqual((ssh["sshd"]["state"], ssh["sshd"]["reason"]), ("error", "privsep-dir-missing"))
        self.assertEqual(ssh["sshd"]["match"], ["/etc/ssh/sshd_config.d/20-vpn.conf"])
        self.assertEqual(ssh["findings"], [])
        ci = [f for f in ssh["keys"] if f["user"] == "ci"][0]
        self.assertEqual((ci["problems"], ci["keys"][0]["state"]), (["dir-writable"], "warning"))

    def test_containers(self):
        items = {c["name"]: [f["kind"] for f in c["findings"]] for c in self.doc["containers"]["items"]}
        self.assertEqual(items["monitor"], ["pid-host", "network-host", "no-new-privileges", "apparmor-unconfined"],
                         "the read-only / mount is no finding")
        self.assertEqual(items["runner"][:2], ["docker-socket", "privileged"])


class Recorded(unittest.TestCase):
    """Four real servers, recorded read only (test/fixtures/capture.sh) and made anonymous: every
    port with its state and reason, and what made each of them worth recording."""

    @classmethod
    def setUpClass(cls):
        cls.docs = {s: scan(s) for s in ("recorded-ci", "recorded-edge", "recorded-ipv6", "recorded-services")}

    def states(self, s):
        return {k: (p["state"], p["why"]) for k, p in ports(self.docs[s]).items()}

    def test_every_source_read(self):
        for s, doc in self.docs.items():
            self.assertEqual({k: v["state"] for k, v in doc["sources"].items()},
                             {"ip": "ok", "ss": "ok", "docker": "ok", "rules": "ok", "ufw": "ok", "hetzner": "skipped",
                              "sshd": "ok", "keys": "ok", "journal": "ok", "crowdsec": "missing",
                          "fail2ban": "missing"}, s)
            self.assertEqual(doc["firewall"]["iptables"]["variant"], "nf_tables", s)
            self.assertFalse(doc["firewall"]["legacy_rules"], s)
            self.assertEqual([p["port"] for p in doc["ports"] if p["why"] == "unknown"], [], s)

    def test_ci(self):
        """UFW lets in only the VPN, but Docker publishes the gateway on the public address: past UFW."""
        self.assertEqual(self.states("recorded-ci"), {
            "22/tcp": ("ok", "only-vpn"), "53/tcp": ("ok", "local"), "53/udp": ("ok", "local"),
            "80/tcp": ("info", "public-expected"), "323/udp": ("ok", "local"), "443/tcp": ("info", "public-expected"),
            "2222/tcp": ("ok", "only-vpn"), "8088/tcp": ("ok", "only-vpn"), "42469/tcp": ("ok", "local"),
            "58507/udp": ("ok", "only-vpn")})
        p = ports(self.docs["recorded-ci"])
        inet = p["443/tcp"]["reach"]["4"]["internet"]
        self.assertEqual((inet["path"], inet["to"]["addr"]), ("forward", "172.19.0.15"))
        self.assertEqual(inet["steps"][-1]["rule"]["chain"], "DOCKER")
        vpn = p["443/tcp"]["reach"]["4"]["vpn"]
        self.assertEqual(vpn["to"]["addr"], "172.19.0.10", "the VPN address has a mapping of its own")
        self.assertEqual(p["443/tcp"]["service"]["containers"], ["gateway", "web"])
        self.assertEqual(p["58507/udp"]["name"], "wireguard", "the kernel's socket of a WireGuard peer")
        self.assertEqual(self.docs["recorded-ci"]["firewall"]["input_filter"], {4: "on", 6: "on"})
        self.assertEqual(self.docs["recorded-ci"]["ssh"]["sshd"], {"state": "ok", "match": []},
                         "sshd -T works since /run/sshd exists")
        socket = [c["name"] for c in self.docs["recorded-ci"]["containers"]["items"]
                  if any(f["kind"] == "docker-socket" for f in c["findings"])]
        self.assertEqual(socket, ["runner-1", "runner-2", "runner-3", "runner-4", "socket-proxy"])

    def test_edge(self):
        """The WireGuard edge: UFW, Cockpit and the apps on the VPN address, SSH from the VPN and
        the private network, the DHCP client let in by UFW's rule for source port 67."""
        self.assertEqual(self.states("recorded-edge"), {
            "22/tcp": ("ok", "only-vpn-private"), "53/tcp": ("ok", "only-vpn"), "53/udp": ("ok", "only-vpn"),
            "68/udp": ("info", "public-expected"), "323/udp": ("ok", "local"), "443/tcp": ("ok", "only-vpn"),
            "3000/tcp": ("ok", "only-vpn"), "8080/tcp": ("ok", "only-vpn"), "9090/tcp": ("ok", "only-vpn"),
            "51820/udp": ("info", "public-expected")})
        p = ports(self.docs["recorded-edge"])
        self.assertEqual(reach(p["22/tcp"]), {"internet": "closed", "vpn": "open", "private": "restricted",
                                              "local": "open"})
        self.assertEqual(p["22/tcp"]["reach"]["4"]["private"]["sources"], ["10.0.0.0/24"])
        dhcp = p["68/udp"]["reach"]["4"]["internet"]
        self.assertEqual(dhcp["steps"][-1]["rule"]["text"], "-p udp -m udp --sport 67 --dport 68 -j ACCEPT")
        self.assertEqual(p["68/udp"]["name"], "dhcp-client")

    def test_ipv6_only(self):
        """No public IPv4 (a shared address of 100.64.0.0/10), IPv6 closed but for the VPN; wg-quick's
        own nftables table is read next to UFW's."""
        doc = self.docs["recorded-ipv6"]
        self.assertEqual(doc["network"]["public"], {"4": False, "6": True})
        self.assertEqual(self.states("recorded-ipv6"), {
            "22/tcp": ("ok", "only-vpn"), "53/tcp": ("ok", "local"), "53/udp": ("ok", "local"),
            "68/udp": ("ok", "only-private"), "323/udp": ("ok", "local"), "18789/tcp": ("ok", "local"),
            "36797/tcp": ("ok", "local"), "38554/udp": ("ok", "local")})
        self.assertIn({"src": "nft", "family": "ip", "table": "wg-quick-wg0", "chains": 3, "rules": 3, "owners": []},
                      doc["firewall"]["tables"])
        self.assertEqual(reach(ports(doc)["22/tcp"], "6")["internet"], "closed")

    def test_services(self):
        """UFW off and no Hetzner token: every public port is "outside-only". The relay is limited to
        an ipset (a country list) in DOCKER-USER for IPv4, but its IPv6 goes to docker-proxy on
        the host, where nothing filters: that rule does not cover IPv6."""
        self.assertEqual(self.states("recorded-services"), {
            "22/tcp": ("warning", "outside-only"), "53/tcp": ("ok", "local"), "53/udp": ("ok", "local"),
            "68/udp": ("warning", "outside-only"), "80/tcp": ("warning", "outside-only"),
            "443/tcp": ("warning", "outside-only"), "1411/tcp": ("ok", "local"), "3000/tcp": ("ok", "local"),
            "3001/tcp": ("ok", "local"), "3002/tcp": ("ok", "local"), "3003/tcp": ("ok", "local"),
            "3010/tcp": ("ok", "local"), "3011/tcp": ("ok", "local"), "5006/tcp": ("ok", "local"),
            "8000/tcp": ("ok", "local"), "8080/tcp": ("ok", "local"), "8089/tcp": ("ok", "local"),
            "8091/tcp": ("ok", "local"), "21115/tcp": ("warning", "outside-only"),
            "21116/tcp": ("warning", "outside-only"), "21116/udp": ("warning", "outside-only"),
            "21117/tcp": ("warning", "outside-only"), "21118/tcp": ("warning", "outside-only"),
            "21119/tcp": ("warning", "outside-only")})
        doc = self.docs["recorded-services"]
        self.assertEqual(doc["firewall"]["input_filter"], {4: "off", 6: "off"})
        self.assertEqual((doc["firewall"]["ufw"]["installed"], doc["firewall"]["ufw"]["enabled"]), (True, False))
        relay = ports(doc)["21116/udp"]
        v4, v6 = relay["reach"]["4"]["internet"], relay["reach"]["6"]["internet"]
        self.assertEqual((v4["result"], v4["path"], v4["sources"]), ("restricted", "forward", ["ipset germany"]))
        self.assertEqual(v4["steps"][-1]["rule"]["chain"], "DOCKER", "Docker's rule lets the members in")
        lim = v4["limited_by"]
        self.assertEqual((lim["result"], lim["chain"]["chain"], lim["rule"]["chain"]), ("drop", "FORWARD", "DOCKER-USER"))
        self.assertEqual(lim["rule"]["text"], "-p udp -m udp --dport 21116 -m set ! --match-set germany src -j DROP",
                         "the geo rule keeps everyone else out")
        self.assertEqual((v6["result"], v6["path"], v6.get("proxy")), ("open", "input", True))
        self.assertNotIn("limited_by", v6)
        self.assertEqual(reach(ports(doc)["8080/tcp"]), {"internet": "absent", "vpn": "absent", "private": "absent",
                                                         "local": "open"}, "the office suite on 127.0.0.1")
        f2b = [t for t in doc["firewall"]["tables"] if "fail2ban" in t["owners"]]
        self.assertEqual([(t["family"], t["table"]) for t in f2b], [("ip", "filter")])


class Variants(unittest.TestCase):
    def test_docker_user_rule_makes_it_vpn_only(self):
        """Spec 4.7: with a DOCKER-USER rule the published port is reachable from the VPN only."""
        text = fixture("ufw-docker", "commands", "iptables-save.txt").replace(
            "-A DOCKER -d 172.17.0.2/32",
            "-A DOCKER-USER -o docker0 -m conntrack --ctstate NEW ! -s 10.8.0.0/24 -j DROP\n"
            "-A DOCKER -d 172.17.0.2/32", 1)
        doc = scan("ufw-docker", results={"iptables-save": text})
        p = ports(doc)["8080/tcp"]
        self.assertEqual(reach(p), {"internet": "closed", "vpn": "open", "private": "closed", "local": "open"})
        self.assertEqual((p["state"], p["why"]), ("ok", "only-vpn"))
        self.assertEqual(p["reach"]["4"]["internet"]["steps"][0]["rule"]["chain"], "DOCKER-USER")
        self.assertEqual(doc["firewall"]["docker_user"], {"4": 1, "6": 0})

    def test_without_root(self):
        denied = secproc.Result(1, "", "iptables-save v1.8.10 (nf_tables): Could not fetch rule set generation id: "
                                       "Permission denied (you must be root)\n")
        doc = scan("ufw-docker", uid=1000, results={"iptables-save": denied, "ip6tables-save": denied,
                                                    "nft": secproc.Result(1, "", "Operation not permitted\n")},
                   docker_error=PermissionError(13, "Permission denied"))
        self.assertEqual(doc["sources"]["rules"]["state"], "needs-root")
        self.assertEqual(doc["sources"]["docker"]["state"], "needs-root")
        self.assertFalse(doc["root"])
        inet = [p for p in doc["ports"] if any(p["reach"][f]["internet"]["result"] != "absent" for f in ("4", "6"))]
        self.assertEqual({p["state"] for p in inet}, {"none"})
        self.assertEqual((ports(doc)["6379/tcp"]["state"], ports(doc)["6379/tcp"]["why"]), ("ok", "only-vpn"),
                         "on the VPN address: the VPN is not known, so not \"this host only\"")
        self.assertEqual(doc["containers"]["state"], "skipped")

    def test_docker_failing(self):
        """Docker does not answer (the review's case): the docker-proxy socket of 8080 was judged by
        UFW's input chain, closed, though Docker forwards 8080 past UFW. A socket of docker-proxy,
        or on a port a DNAT rule names, is not assessable from outside this host (no-docker),
        never closed; every other port is judged as with Docker's answer."""
        base = {k: (p["state"], p["why"]) for k, p in ports(scan("ufw-docker")).items()}
        for err in (ConnectionRefusedError(111, "Connection refused"), TimeoutError("timed out")):
            doc = scan("ufw-docker", docker_error=err)
            self.assertEqual(doc["sources"]["docker"]["state"], "error")
            p = ports(doc)
            self.assertEqual([k for k, x in p.items() if x["service"]["kind"] == "docker"], [],
                             "no mapping is known without Docker's answer")
            web = p["8080/tcp"]
            self.assertEqual((web["state"], web["why"]), ("none", "unknown"), "not ok/closed through UFW's input")
            for f, classes in (("4", ("internet", "vpn", "private")), ("6", ("internet",))):
                for c in classes:
                    self.assertEqual((web["reach"][f][c]["result"], web["reach"][f][c]["reason"]), ("unknown", "no-docker"),
                                     f + " " + c)
            self.assertEqual(reach(web)["local"], "open", "the host itself still reaches it")
            redis = p["6379/tcp"]
            self.assertEqual(reach(redis), {"internet": "absent", "vpn": "unknown", "private": "absent", "local": "open"},
                             "docker-proxy on the VPN address: the VPN is not known")
            self.assertEqual(redis["reach"]["4"]["vpn"]["reason"], "no-docker")
            self.assertEqual((redis["state"], redis["why"]), ("ok", "only-vpn"), "never \"this host only\"")
            self.assertEqual({k: (x["state"], x["why"]) for k, x in p.items() if k != "8080/tcp"},
                             {k: v for k, v in base.items() if k != "8080/tcp"}, "the rest as with Docker's answer")

    def test_docker_answering_unchanged(self):
        """With Docker's answer 8080 is still forwarded past UFW (warning), whatever docker-proxy holds."""
        p = ports(scan("ufw-docker"))["8080/tcp"]
        self.assertEqual((p["state"], p["why"], p["reach"]["4"]["internet"]["path"]), ("warning", "public-other", "forward"))
        self.assertNotIn("no-docker", json.dumps(scan("ufw-docker")["ports"]))

    def test_no_docker(self):
        doc = scan("ufw-docker", meta={"exists": []})
        self.assertEqual(doc["sources"]["docker"]["state"], "missing")
        p = ports(doc)["8080/tcp"]
        self.assertEqual((p["service"]["kind"], reach(p)["internet"]), ("process", "closed"),
                         "without Docker's mapping the docker-proxy socket is a plain socket behind UFW")

    def test_legacy_rules_apply_too(self):
        legacy = "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n" \
                 "-A INPUT -p tcp -m tcp --dport 443 -j DROP\nCOMMIT\n"
        doc = scan("ufw-docker", results={"iptables-legacy-save": legacy},
                   files={"/proc/net/ip_tables_names": "filter\n"})
        self.assertTrue(doc["firewall"]["legacy_rules"])
        self.assertEqual(reach(ports(doc)["443/tcp"])["internet"], "closed")

    def test_unreadable_rule_makes_unknown(self):
        text = fixture("ufw-docker", "commands", "iptables-save.txt").replace(
            "-A ufw-user-input -i wg0 -j ACCEPT",
            "-A ufw-user-input -m mark --mark 0x1 -j ACCEPT\n-A ufw-user-input -i wg0 -j ACCEPT")
        doc = scan("ufw-docker", results={"iptables-save": text})
        p = ports(doc)["9090/tcp"]
        self.assertEqual((p["state"], p["why"]), ("none", "unknown"))
        unk = p["reach"]["4"]["internet"]["unknown"]
        self.assertEqual(unk["rule"]["text"], "-m mark --mark 0x1 -j ACCEPT")

    def test_ipset_as_source_restricts(self):
        """An ipset is no unreadable rule when it names the source: the port is reachable from its
        members only (whatever they are)."""
        text = fixture("ufw-docker", "commands", "iptables-save.txt").replace(
            "-A ufw-user-input -i wg0 -j ACCEPT",
            "-A ufw-user-input -m set --match-set office src -j ACCEPT\n-A ufw-user-input -i wg0 -j ACCEPT")
        doc = scan("ufw-docker", results={"iptables-save": text})
        p = ports(doc)["9090/tcp"]
        self.assertEqual((p["state"], p["why"]), ("warning", "restricted"), "Cockpit, so a warning")
        inet = p["reach"]["4"]["internet"]
        self.assertEqual((inet["result"], inet["sources"]), ("restricted", ["ipset office"]))
        self.assertEqual(p["reach"]["6"]["internet"]["result"], "closed", "ip6tables names no set")


LO_ONLY = json.dumps([{"ifindex": 1, "ifname": "lo", "flags": ["LOOPBACK", "UP", "LOWER_UP"], "operstate": "UP",
                       "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8, "scope": "host"},
                                     {"family": "inet6", "local": "::1", "prefixlen": 128, "scope": "host"}]}])


class NetworkData(unittest.TestCase):
    """The exposure rests on the addresses (`ip -j addr`) and the sockets (`ss`): when they cannot
    be read, nothing may look closed or "only this host"; a host that really has no public
    address or no listening socket stays OK."""

    LOOPBACK_ONLY = {"53/tcp", "53/udp", "323/udp", "5432/tcp"}

    def test_addresses_not_read(self):
        for broken in (fakesys.failing("Cannot open netlink socket: Permission denied"), "not json"):
            doc = scan("ufw-docker", results={"ip-addr": broken})
            self.assertEqual(doc["sources"]["ip"]["state"], "error")
            self.assertEqual(doc["network"]["public"], {"4": None, "6": None}, "not known, not false")
            self.assertEqual(doc["firewall"]["input_filter"], {4: "unknown", 6: "unknown"})
            got = {k: (p["state"], p["why"]) for k, p in ports(doc).items()}
            self.assertEqual({k for k, v in got.items() if v == ("ok", "local")}, self.LOOPBACK_ONLY,
                             "only a socket on the loopback is out of reach without the addresses")
            self.assertEqual({v for k, v in got.items() if k not in self.LOOPBACK_ONLY}, {("none", "unknown")})
            p = ports(doc)["6379/tcp"]
            for c in ("internet", "vpn", "private"):
                self.assertEqual((p["reach"]["4"][c]["result"], p["reach"]["4"][c]["reason"]), ("unknown", "no-addresses"))
            self.assertEqual(reach(ports(doc)["8080/tcp"])["local"], "open", "the host itself still reaches it")

    def test_no_public_address_is_ok(self):
        """Read, and only the loopback: a real "no public address"."""
        doc = scan("ufw-docker", results={"ip-addr": LO_ONLY})
        self.assertEqual((doc["sources"]["ip"]["state"], doc["network"]["public"]), ("ok", {"4": False, "6": False}))
        self.assertEqual({(p["state"], p["why"]) for p in doc["ports"]}, {("ok", "local")})

    def test_sockets_not_read(self):
        doc = scan("ufw-docker", results={"ss": fakesys.failing("ss: cannot open netlink socket")})
        self.assertEqual(doc["sources"]["ss"]["state"], "error")
        self.assertEqual({k: (p["state"], p["why"]) for k, p in ports(doc).items()}, {
            "5432/tcp": ("ok", "local"), "6379/tcp": ("ok", "only-vpn"), "8080/tcp": ("warning", "public-other")},
            "only what Docker publishes is known")
        doc = scan("ufw-docker", meta={"exists": []}, results={"ss": fakesys.failing("ss: failed")})
        self.assertEqual((doc["sources"]["ss"]["state"], doc["ports"]), ("error", []))

    def test_no_listening_socket_is_ok(self):
        doc = scan("ufw-docker", meta={"exists": []}, results={"ss": ""})
        self.assertEqual((doc["sources"]["ss"]["state"], doc["ports"]), ("ok", []))


class Fail2ban(unittest.TestCase):
    """fail2ban (spec 5.3): jails, bans, where a ban takes effect, and what makes one fail."""

    def setUp(self):
        self.doc = scan("fail2ban")
        self.f = self.doc["fail2ban"]
        self.j = {j["name"]: j for j in self.f["jails"]}

    def codes(self, name, doc=None):
        jails = {j["name"]: j for j in (doc or self.doc)["fail2ban"]["jails"]}
        return [(f["code"], f["state"], f.get("value")) for f in jails[name]["findings"]]

    def test_service(self):
        self.assertEqual((self.f["version"], self.f["active"], self.f["running"], self.f["since"], self.f["dbpurgeage"]),
                         ("1.0.2", "active", True, "2026-10-18T08:00:00Z", "1d"))
        self.assertEqual(sorted(self.j), ["nginx-botsearch", "recidive", "sshd", "web"])
        self.assertEqual((self.doc["sources"]["fail2ban"]["state"], self.f["state"]), ("ok", "warning"))
        self.assertEqual((self.f["history_total"], self.j["sshd"]["history"], self.j["nginx-botsearch"]["history"]),
                         (11, 7, None))
        self.assertEqual((self.j["sshd"]["failed_total"], self.j["sshd"]["banned_now"], self.j["sshd"]["journal"]),
                         (41, 1, "_SYSTEMD_UNIT=ssh.service + _COMM=sshd"))

    def test_where_each_jail_bans(self):
        a = {n: self.j[n]["actions"][0] for n in self.j}
        self.assertEqual([a["sshd"][k] for k in ("kind", "where", "observed", "forward")], ["iptables", ["INPUT"], True, False])
        self.assertEqual([a["web"][k] for k in ("kind", "where", "observed", "forward")],
                         ["nftables", ["hook input"], True, False])
        self.assertEqual((a["recidive"]["allports"], a["recidive"]["where"]), (True, ["INPUT"]))
        self.assertEqual((a["nginx-botsearch"]["observed"], a["nginx-botsearch"]["where"]), (False, ["INPUT"]),
                         "no chain before the first ban: iptables' default")

    def test_findings_per_jail(self):
        self.assertEqual(self.codes("sshd"), [])
        self.assertEqual(self.codes("web"), [("input-only", "warning", "8080/tcp"), ("udp-open", "warning", "443/udp")])
        self.assertEqual(self.codes("recidive"), [("allports-input", "info", "8080/tcp"),
                                                  ("log-idle", "warning", "/var/log/fail2ban.log")])
        self.assertEqual(self.j["recidive"]["findings"][1]["days"], 5)
        self.assertEqual(self.codes("nginx-botsearch"), [("udp-open", "warning", "443/udp"),
                                                         ("no-match", "warning", "2026-10-18T08:00:00Z")])

    def test_unmanaged_and_persisted(self):
        g = {f["code"]: f for f in self.f["findings"]}
        self.assertEqual((g["unmanaged-bans"]["value"], g["unmanaged-bans"]["chains"]), (1, ["f2b-sshd"]))
        self.assertEqual((g["persisted-chains"]["state"], g["persisted-chains"]["value"]), ("info", "/etc/iptables/rules.v4"))

    def test_bans_now(self):
        self.assertEqual([(b["ip"], b["jail"], b["class"]) for b in self.f["bans"]],
                         [("203.0.113.50", "sshd", "internet"), ("198.51.100.20", "recidive", "internet"),
                          ("192.0.2.80", "web", "internet")], "the expired ban is left out")
        self.assertEqual((self.f["bans"][1]["since"], self.f["bans"][1]["until"]), ("2026-10-19T12:00:00Z", "2026-10-26T12:00:00Z"))

    def test_ports_unchanged(self):
        base = scan("ufw-docker")
        self.assertEqual({k: (p["state"], p["why"]) for k, p in ports(self.doc).items()},
                         {k: (p["state"], p["why"]) for k, p in ports(base).items()})

    def test_log_missing(self):
        doc = scan("fail2ban", files={"/var/log/web/access.log": None})
        self.assertIn(("log-missing", "warning", "/var/log/web/access.log"), self.codes("web", doc))

    def test_not_running(self):
        doc = scan("fail2ban", results={
            "f2b-ping": secproc.Result(255, "", "ERROR   Failed to access socket path"),
            "systemctl-show-fail2ban": "ActiveState=failed\nUnitFileState=enabled\nActiveEnterTimestamp=\n"})
        f = doc["fail2ban"]
        self.assertEqual([(x["code"], x["value"]) for x in f["findings"] if x["state"] == "warning"],
                         [("not-running", "failed")])
        self.assertEqual(len(f["bans"]), 3, "the database still says who is banned")
        self.assertNotIn("no-match", [c for c, _, _ in self.codes("nginx-botsearch", doc)])

    def test_database_unreadable(self):
        doc = scan("fail2ban", meta={"db_error": "unable to open database file"})
        f = doc["fail2ban"]
        self.assertEqual(doc["sources"]["fail2ban"]["state"], "partial")
        self.assertEqual(sorted(b["ip"] for b in f["bans"]), ["192.0.2.80", "198.51.100.20", "203.0.113.50"],
                         "from fail2ban-client status")
        self.assertIsNone(f["history_total"])

    def test_where_the_packet_filter_says(self):
        dump = fixture("fail2ban", "commands", "f2b-dump.txt").replace(
            "['name', 'sshd'], ['port', 'ssh'], ['protocol', 'tcp'], ['chain', '<known/chain>']",
            "['name', 'sshd'], ['port', '8080'], ['protocol', 'tcp'], ['chain', 'DOCKER-USER']")
        doc = scan("fail2ban", results={"f2b-dump": dump})
        sshd = {j["name"]: j for j in doc["fail2ban"]["jails"]}["sshd"]
        self.assertEqual((sshd["actions"][0]["where"], self.codes("sshd", doc)), (["INPUT"], [
            ("input-only", "warning", "8080/tcp")]), "the chain the packet filter jumps from, not the configuration")
        ipt = fixture("fail2ban", "commands", "iptables-save.txt").replace(
            "-A INPUT -p tcp -m multiport --dports 22 -j f2b-sshd\n", "-A DOCKER-USER -p tcp -m multiport --dports 80 -j f2b-sshd\n")
        doc = scan("fail2ban", results={"f2b-dump": dump, "iptables-save": ipt})
        sshd = {j["name"]: j for j in doc["fail2ban"]["jails"]}["sshd"]
        self.assertEqual((sshd["actions"][0]["where"], sshd["actions"][0]["forward"], self.codes("sshd", doc)),
                         (["DOCKER-USER"], True, []))
        nft = json.loads(fixture("fail2ban", "commands", "nft.json"))
        for e in nft["nftables"]:
            if "chain" in e and e["chain"]["name"] == "f2b-chain":
                e["chain"]["hook"] = "forward"
        doc = scan("fail2ban", results={"nft": json.dumps(nft)})
        web = {j["name"]: j for j in doc["fail2ban"]["jails"]}["web"]
        self.assertEqual((web["actions"][0]["where"], self.codes("web", doc)), (["hook forward"], [
            ("udp-open", "warning", "443/udp")]))

    def test_not_installed(self):
        self.assertEqual(scan("ufw-docker")["fail2ban"], {"installed": False})

    def test_complete(self):
        self.assertEqual((self.f["incomplete"], self.f["errors"]), ([], {}))
        self.assertEqual({j["name"]: j["running"] for j in self.f["jails"]}, dict.fromkeys(self.j, True))
        self.assertNotIn("error", self.j["sshd"])


class Fail2banRead(unittest.TestCase):
    """What fail2ban-client and the database could not answer (findings 3 and 4 of the review):
    a part the assessment needs missing leaves it "not checked" (none), never OK; a jail that is
    configured but not running is a warning; the database only feeds the history. On the
    scenario cut down to the jail sshd, which has no finding (fakesys.fail2ban_quiet)."""

    def quiet(self, results=None, files=None, meta=None):
        doc = scan("fail2ban", meta=meta, **fakesys.fail2ban_quiet(results, files))
        return doc, doc["fail2ban"], {j["name"]: j for j in doc["fail2ban"]["jails"]}

    def test_quiet_is_ok(self):
        doc, f, j = self.quiet()
        self.assertEqual((f["state"], f["findings"], f["incomplete"], f["errors"]), ("ok", [], [], {}))
        self.assertEqual((list(j), j["sshd"]["running"], j["sshd"]["state"], j["sshd"]["findings"]),
                         (["sshd"], True, "ok", []))
        self.assertEqual((f["bans_total"], doc["sources"]["fail2ban"]["state"]), (3, "ok"))

    def test_config_and_status_failing(self):
        """The review's case: ping answers, `-d` and `status` fail; without other findings this
        was OK with an empty list of jails."""
        doc, f, j = self.quiet({"f2b-dump": fakesys.failing("ERROR  Failed to read the configuration", 255),
                                "f2b-status": fakesys.failing("ERROR  NOK: ('status',)", 255)})
        self.assertEqual((f["state"], f["incomplete"], f["findings"], j), ("none", ["config", "status"], [], {}))
        self.assertEqual(f["errors"], {"config": "ERROR  Failed to read the configuration",
                                       "status": "ERROR  NOK: ('status',)"})
        self.assertEqual(f["bans_total"], 3, "the database still says who is banned")
        self.assertEqual((doc["sources"]["fail2ban"]["state"], doc["sources"]["fail2ban"]["missing"]),
                         ("partial", "config,status"))

    def test_status_failing(self):
        doc, f, j = self.quiet({"f2b-status": fakesys.failing("ERROR  timed out", 255)})
        self.assertEqual((f["state"], f["incomplete"]), ("none", ["status"]))
        self.assertEqual((j["sshd"]["running"], j["sshd"]["state"], j["sshd"]["findings"]), (None, "none", []),
                         "not known whether it runs: no warning, and no OK")
        doc, f, j = self.quiet({"f2b-status": "Status\nnothing to read here\n"})
        self.assertEqual((f["state"], f["errors"]["status"]), ("none", "unexpected answer"))

    def test_config_failing(self):
        doc, f, j = self.quiet({"f2b-dump": fakesys.failing("ERROR  bad jail.local", 255)})
        self.assertEqual((f["state"], f["incomplete"], j["sshd"]["running"], j["sshd"]["state"]),
                         ("none", ["config"], True, "none"), "where its ban takes effect is not known")

    def test_no_answer_while_active(self):
        """systemd says active, ping gets no answer: not known, which is not "not running"."""
        doc, f, j = self.quiet({"f2b-ping": secproc.Result(None, "", "", timeout=True)})
        self.assertEqual((f["state"], f["running"], f["incomplete"], f["findings"]), ("none", False, ["ping"], []))
        self.assertEqual((f["errors"]["ping"], j["sshd"]["running"], j["sshd"]["state"]), ("timed out", None, "none"))

    def test_jail_status_failing(self):
        doc, f, j = self.quiet({"f2b-status-sshd": fakesys.failing("ERROR  NOK: ('sshd',)", 255)})
        self.assertEqual((f["state"], f["incomplete"]), ("none", ["jails"]))
        self.assertEqual((j["sshd"]["running"], j["sshd"]["state"], j["sshd"]["error"], j["sshd"]["failed_total"]),
                         (True, "none", "ERROR  NOK: ('sshd',)", None))
        self.assertEqual(f["bans_total"], 3, "from the database")
        both = self.quiet({"f2b-status-sshd": fakesys.failing("ERROR", 255)}, meta={"db_error": "disk I/O error"})[1]
        self.assertIsNone(both["bans_total"], "neither every jail nor the database: not known")

    def test_only_the_history_missing(self):
        """The database is optional: without it the history is missing, the state stands."""
        doc, f, j = self.quiet(meta={"db_error": "unable to open database file"})
        self.assertEqual((f["state"], f["incomplete"], f["errors"]), ("ok", [], {"db": "unable to open database file"}))
        self.assertEqual((f["history_total"], f["bans_total"], j["sshd"]["state"]), (None, 1, "ok"), "the bans from status")
        self.assertEqual((doc["sources"]["fail2ban"]["state"], doc["sources"]["fail2ban"]["missing"]), ("partial", "db"))

    def test_configured_jail_not_running(self):
        """The review's case: sshd configured, fail2ban answers, its list of running jails is empty
        (and, as fail2ban removes the chain of a jail it stops, no f2b- chain is left)."""
        ipt = "\n".join(line for line in fixture("fail2ban", "commands", "iptables-save.txt").splitlines()
                        if "f2b-" not in line) + "\n"
        doc, f, j = self.quiet({"f2b-status": "Status\n|- Number of jail:\t0\n`- Jail list:\t\n", "iptables-save": ipt})
        self.assertEqual((j["sshd"]["running"], j["sshd"]["findings"], j["sshd"]["state"]),
                         (False, [{"code": "jail-not-running", "state": "warning"}], "warning"))
        self.assertEqual((f["state"], f["incomplete"], f["findings"]), ("warning", [], []))

    def test_more_jails_than_asked(self):
        """The review's case: 31 quiet jails, configured and running. Only the first 30 are asked
        (F2B_MAX_JAILS stays); the 31st was ok without an answer of its own, and the whole ok with
        nothing incomplete. Now it is not checked, and the whole is incomplete."""
        system = fakesys.FakeSystem("fail2ban", **fakesys.fail2ban_jails(31))
        doc = seccheck.scan(system)
        f, j = doc["fail2ban"], {x["name"]: x for x in doc["fail2ban"]["jails"]}
        self.assertEqual(len([c for c in system.calls if c.startswith("f2b-status-")]), seccheck.F2B_MAX_JAILS)
        self.assertEqual((f["state"], f["incomplete"], f["findings"]), ("none", ["skipped"], []))
        self.assertEqual((j["j31"]["running"], j["j31"]["state"], j["j31"]["skipped"], j["j31"]["failed_total"]),
                         (True, "none", True, None))
        self.assertNotIn("error", j["j31"])
        self.assertEqual({n for n, x in j.items() if x["state"] == "ok"}, {f"j{i:02d}" for i in range(1, 31)})
        self.assertEqual([n for n, x in j.items() if x.get("skipped")], ["j31"])
        self.assertEqual((doc["sources"]["fail2ban"]["state"], doc["sources"]["fail2ban"]["missing"]),
                         ("partial", "skipped"))
        self.assertEqual(f["bans_total"], 3, "not every jail answered: the bans from the database")
        # 30 jails: every one asked, nothing incomplete.
        doc = seccheck.scan(fakesys.FakeSystem("fail2ban", **fakesys.fail2ban_jails(30)))
        f = doc["fail2ban"]
        self.assertEqual((f["state"], f["incomplete"], doc["sources"]["fail2ban"]["state"]), ("ok", [], "ok"))
        self.assertFalse(any(x.get("skipped") for x in f["jails"]))

    def test_service_down_is_one_finding(self):
        """fail2ban not running: one finding for the whole, its jails simply do not run."""
        doc, f, j = self.quiet({"f2b-ping": fakesys.failing("ERROR   Failed to access socket path", 255),
                                "systemctl-show-fail2ban": "ActiveState=failed\nUnitFileState=enabled\n"})
        self.assertEqual(([x["code"] for x in f["findings"]], f["incomplete"], f["state"]),
                         (["not-running"], [], "warning"))
        self.assertEqual((j["sshd"]["running"], j["sshd"]["findings"], j["sshd"]["state"]), (False, [], "none"),
                         "no warning of its own, and not OK either")


class Marks(unittest.TestCase):
    def test_view(self):
        doc = scan("ufw-docker")
        marks = {"ports": {"8080/tcp": "test page", "22/tcp": "not public anyway"},
                 "containers": {("runner", "docker-socket"): "CI needs it"}}
        v = seccheck.view(doc, marks)
        p = ports(v)
        self.assertEqual((p["8080/tcp"]["state"], p["8080/tcp"]["base_state"], p["8080/tcp"]["expected"]),
                         ("info", "warning", "test page"))
        self.assertEqual((p["22/tcp"]["state"], p["22/tcp"]["expected"]), ("ok", "not public anyway"))
        runner = [c for c in v["containers"]["items"] if c["name"] == "runner"][0]
        self.assertEqual((runner["findings"][0]["state"], runner["state"]), ("ok", "info"))
        self.assertEqual(ports(doc)["8080/tcp"]["state"], "warning", "the state itself is unchanged")

    def test_marks_file(self):
        good = fakesys.FakeSystem("ufw-docker", files={seccheck.MARKS_FILE: "port 8080/tcp x\nnonsense\n"})
        self.assertEqual(seccheck.read_marks(good), ({"ports": {"8080/tcp": "x"}, "containers": {}}, "lines 2"))
        bad = fakesys.FakeSystem("ufw-docker", files={seccheck.MARKS_FILE: "port 8080/tcp x\n"},
                                 meta={"stat": {seccheck.MARKS_FILE: {"mode": "666", "uid": 0}}})
        self.assertEqual(seccheck.read_marks(bad), ({"ports": {}, "containers": {}}, "untrusted"))
        other = fakesys.FakeSystem("ufw-docker", files={seccheck.MARKS_FILE: "port 8080/tcp x\n"},
                                   meta={"stat": {seccheck.MARKS_FILE: {"mode": "644", "uid": 1000}}})
        self.assertEqual(seccheck.read_marks(other)[1], "untrusted")


class ScanScript(unittest.TestCase):
    """security-scan.py as the service runs it: both files written atomically, the state 0600,
    the status 0644 and readable by the status verb; the marks file counts."""

    def test_files(self):
        import importlib.util
        import stat as st
        import tempfile
        lib = os.path.join(HERE, "..", "lib")
        spec = importlib.util.spec_from_file_location("security_scan", os.path.join(lib, "security-scan.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        d = tempfile.mkdtemp()
        mod.LOCK = os.path.join(d, "scan.lock")
        out, status = os.path.join(d, "state.json"), os.path.join(d, "status.json")
        system = fakesys.FakeSystem("ufw-docker", files={seccheck.MARKS_FILE: "port 8080/tcp test page\n"})
        import io
        from contextlib import redirect_stdout
        with redirect_stdout(io.StringIO()) as buf:
            rc = mod.main(["--output", out, "--status", status], system=system)
        self.assertEqual(rc, 0)
        self.assertIn("13 ports", buf.getvalue())
        self.assertEqual(st.S_IMODE(os.stat(out).st_mode), 0o600)
        self.assertEqual(st.S_IMODE(os.stat(status).st_mode), 0o644)
        with open(status, encoding="utf-8") as f:
            doc = json.load(f)
        self.assertEqual(doc["items"][0]["state"], "info", "8080/tcp marked as expected")
        self.assertEqual(sorted(set(os.listdir(d)) - {"scan.lock"}), ["state.json", "status.json"],
                         "no temporary file left (the lock exists only as root)")

    def test_first_seen_over_two_runs(self):
        """The second run takes over when each port was first seen from the state the first wrote;
        the status names that time as `since`. A port gone in a complete check loses it."""
        import importlib.util
        import io
        import stat as st
        import tempfile
        from contextlib import redirect_stdout
        lib = os.path.join(HERE, "..", "lib")
        spec = importlib.util.spec_from_file_location("security_scan", os.path.join(lib, "security-scan.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        d = tempfile.mkdtemp()
        mod.LOCK = os.path.join(d, "scan.lock")
        out, status = os.path.join(d, "state.json"), os.path.join(d, "status.json")

        def run(now, **kw):
            with redirect_stdout(io.StringIO()):
                self.assertEqual(mod.main(["--output", out, "--status", status],
                                          system=fakesys.FakeSystem("ufw-docker", meta={"now": now}, **kw)), 0)
            with open(out, encoding="utf-8") as f, open(status, encoding="utf-8") as g:
                return json.load(f), json.load(g)
        state1, _ = run("2026-10-20T12:00:00Z")
        state2, status2 = run("2026-10-20T12:15:00Z")
        self.assertEqual(st.S_IMODE(os.stat(out).st_mode), 0o600)
        self.assertEqual(state2["generated"], "2026-10-20T12:15:00Z")
        self.assertEqual(state2["first_seen"], state1["first_seen"])
        self.assertEqual(set(state2["first_seen"].values()), {"2026-10-20T12:00:00Z"})
        since = {f["fid"]: f["since"] for f in status2["items"][0]["findings"]["list"]}
        self.assertEqual(since["port.8080-tcp"], "2026-10-20T12:00:00Z")
        vpn_only = fixture("ufw-docker", "commands", "iptables-save.txt").replace(
            "-A DOCKER -d 172.17.0.2/32",
            "-A DOCKER-USER -o docker0 -m conntrack --ctstate NEW ! -s 10.8.0.0/24 -j DROP\n-A DOCKER -d 172.17.0.2/32", 1)
        state3, status3 = run("2026-10-20T12:30:00Z", results={"iptables-save": vpn_only})
        self.assertNotIn("port.8080-tcp", state3["first_seen"])
        self.assertNotIn("port.8080-tcp", [f["fid"] for f in status3["items"][0]["findings"]["list"]])
        self.assertEqual(state3["first_seen"]["port.80-tcp"], "2026-10-20T12:00:00Z")


class Fixtures(unittest.TestCase):
    def test_state_and_status_files_current(self):
        for s in make_states.SCENARIOS:
            doc, system = make_states.state(s)
            want = json.loads(json.dumps(doc))
            self.assertEqual(json.loads(fixture(f"state-{s}.json")), want,
                             f"state-{s}.json is old: python3 test/fixtures/make_states.py")
            self.assertEqual(json.loads(fixture(f"status-{s}.json")),
                             json.loads(json.dumps(make_states.status(doc, system))), s)

    def test_no_real_hosts(self):
        """Only documentation and private addresses in the fixtures."""
        import re
        pat = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}\b")
        allowed = ("10.", "127.", "172.1", "172.2", "172.3", "192.168.", "192.0.2.", "198.51.100.", "203.0.113.",
                   "0.0.0.0", "224.", "239.", "255.", "100.64.", "169.254.", "1.8.", "1.1.", "6.8.", "4.0.")
        for root, _, files in os.walk(FIX):
            for name in files:
                text = open(os.path.join(root, name), encoding="utf-8", errors="replace").read()
                for m in pat.finditer(text):
                    self.assertTrue(m.group(0).startswith(allowed), f"{name}: {m.group(0)}")


if __name__ == "__main__":
    unittest.main(verbosity=1)
