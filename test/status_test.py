#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The status of the add-on (status contract of the Azentrius add-ons,
schema 1): secstatus.py against the scenarios, the marks, and
`security.py status`, the verb the Status Board calls. Offline, no root."""

import io
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.join(HERE, "..", "lib")
sys.dont_write_bytecode = True
sys.path.insert(0, HERE)
sys.path.insert(0, LIB)
sys.path.insert(0, os.path.join(HERE, "fixtures"))
import importlib.util  # noqa: E402

import fakesys  # noqa: E402
import make_states  # noqa: E402
import seccheck  # noqa: E402
import secproc  # noqa: E402
import secstatus  # noqa: E402

spec = importlib.util.spec_from_file_location("security", os.path.join(LIB, "security.py"))
security = importlib.util.module_from_spec(spec)
spec.loader.exec_module(security)

FIX = os.path.join(HERE, "fixtures")
GERMAN = re.compile(r"[äöüÄÖÜß]|\b(und|nicht|Anmeldung|Schlüssel|Befunde|geprüft|Sperre|erreichbar)\b")
PRIVATE = re.compile(r"\b\d{1,3}(\.\d{1,3}){3}\b|[0-9a-f]{1,4}:[0-9a-f]{0,4}:[0-9a-f:]+|https?:|@|"
                     r"/(etc|var|home|opt|usr|root|run)/|\balex\b|\bdeploy\b|SHA256:")
NOW = datetime(2026, 10, 20, 12, 10, tzinfo=timezone.utc)
NO_MARKS = {"ports": {}, "containers": {}}


def status(scenario, marks=NO_MARKS):
    doc, _ = make_states.state(scenario)
    return secstatus.status_file(seccheck.view(doc, marks), "0.1.0")


def texts(doc):
    yield doc["summary"]
    for i in doc["items"]:
        for k in ("title", "detail", "value"):
            yield i.get(k) or ""
        for f in (i.get("findings") or {}).get("list") or []:
            yield f["title"]
    for c in doc.get("checks") or []:
        yield c["title"]
        yield c.get("reason") or ""


def call(argv, path, now=NOW):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = security.do_status(argv, path, now)
    return rc, out.getvalue(), err.getvalue()


class Contract(unittest.TestCase):
    def test_scenarios(self):
        for s in make_states.SCENARIOS:
            st = status(s)
            for lang in ("en", "de"):
                doc = secstatus.localize(st, lang, NOW)
                self.assertNotIn("i18n", doc)
                self.assertEqual(secstatus.problems(doc), [], (s, lang))
                self.assertEqual((doc["schema"], doc["addon"], doc["label"]), (1, "security", "Security Monitor"))
                self.assertTrue(len(json.dumps(doc).encode()) < 64 << 10)
                for t in texts(doc):
                    self.assertIsNone(PRIVATE.search(t), (s, lang, t))
                if lang == "en":
                    for t in texts(doc):
                        self.assertIsNone(GERMAN.search(t), (s, t))
                else:
                    self.assertEqual(doc["items"][0]["title"], "Aus dem Internet erreichbar")

    def test_items_of_the_scenarios(self):
        want = {
            "ufw-docker": ("danger", [("exposure", "warning", "5"), ("ssh", "warning", "3"), ("logins", "ok", "1"),
                                      ("containers", "danger", "1"), ("scan", "ok", None)]),
            "hetzner-open": ("warning", [("exposure", "info", "3"), ("ssh", "warning", "2"),
                                         ("logins", "warning", "1"), ("containers", "warning", "2"),
                                         ("crowdsec", "warning", "2"), ("scan", "ok", None)]),
            "nft-native": ("danger", [("exposure", "warning", "4"), ("ssh", "warning", "2"), ("logins", "ok", "0"),
                                      ("containers", "danger", "2"), ("scan", "ok", None)]),
            "derived-ci": ("danger", [("exposure", "info", "2"), ("ssh", "info", None), ("logins", "ok", "0"),
                                      ("containers", "danger", "3"), ("scan", "ok", None)]),
            "derived-edge": ("danger", [("exposure", "info", "2"), ("ssh", "info", None), ("logins", "ok", "0"),
                                        ("containers", "danger", "1"), ("scan", "ok", None)]),
            "derived-ipv6": ("danger", [("exposure", "ok", "0"), ("ssh", "info", None), ("logins", "ok", "0"),
                                        ("containers", "danger", "1"), ("scan", "ok", None)]),
            "derived-services": ("danger", [("exposure", "warning", "10"), ("ssh", "info", None),
                                            ("logins", "ok", "0"), ("containers", "danger", "1"),
                                            ("scan", "ok", None)]),
            "fail2ban": ("danger", [("exposure", "warning", "5"), ("ssh", "warning", "3"), ("logins", "ok", "1"),
                                    ("containers", "danger", "1"), ("fail2ban", "warning", "3"), ("scan", "ok", None)]),
        }
        for s, (state, items) in want.items():
            st = status(s)
            self.assertEqual(st["state"], state, s)
            self.assertEqual([(i["id"], i["state"], i.get("value")) for i in st["items"]], items, s)
            for i in st["items"]:
                self.assertEqual(i["stale_after"], 3600)
                self.assertEqual(i.get("link"), None if i["id"] == "scan" else "#/" + i["id"])
        ex = status("ufw-docker")["items"][0]["detail"]
        self.assertEqual(ex, "8080/tcp web, 80/tcp http, 443/tcp https, 443/udp http3, 51820/udp wireguard")
        fb = {lang: next(i for i in secstatus.localize(status("fail2ban"), lang, NOW)["items"]
                         if i["id"] == "fail2ban")["detail"] for lang in ("en", "de")}
        self.assertEqual(fb["en"], secstatus._clip(
            "1 address blocked that fail2ban does not manage; nginx-botsearch: TCP only, 443/udp stays open; "
            "nginx-botsearch: not one hit since 18 Oct; recidive: log unchanged for 5 days; web: does not protect "
            "container ports (8080/tcp); web: TCP only, 443/udp stays open"), "the warnings, cut as every detail")
        self.assertTrue(fb["en"].endswith(" …"))
        quiet = {"installed": True, "state": "ok", "bans_total": 1, "findings": [], "jails": [
            {"name": "sshd", "findings": []}, {"name": "recidive", "findings": [{"code": "allports-input", "state": "info"}]}]}
        item = secstatus.items_of({"ports": [], "ssh": {}, "logins": {}, "containers": {}, "fail2ban": quiet,
                                   "sources": {}}, "en")
        self.assertEqual([(i["id"], i["state"], i.get("value"), i.get("detail")) for i in item if i["id"] == "fail2ban"],
                         [("fail2ban", "ok", "1", "2 jails, 1 ban")], "without warnings: jails and bans")
        self.assertTrue(fb["de"].startswith("1 Adresse gesperrt, die fail2ban nicht verwaltet; nginx-botsearch: nur TCP"),
                        fb["de"])
        self.assertIn("kein einziger Treffer seit 18.10.", fb["de"])
        cr = status("hetzner-open")["items"][4]["detail"]
        self.assertEqual(cr, "outdated version 1.4.6; bouncer does not protect container ports; 2 active decisions")
        de = secstatus.localize(status("hetzner-open"), "de", NOW)
        self.assertEqual(de["items"][2]["detail"], "1 erfolgreiche Anmeldung von außerhalb von VPN und Privatnetz")

    def test_limited_ports_apart(self):
        """The figure counts what the whole internet reaches; a port only some addresses reach
        (here an allowed network) is named apart."""
        ex = status("nft-native")["items"][0]
        self.assertEqual((ex["value"], ex["detail"]),
                         ("4", "3000/tcp forgejo, 80/tcp http, 443/tcp https, 51820/udp wireguard; "
                               "only from some addresses: 60001/tcp syncthing"))
        doc, _ = make_states.state("nft-native")
        for p in doc["ports"]:
            for f in ("4", "6"):
                if p["reach"][f]["internet"]["result"] == "open":
                    p["reach"][f]["internet"]["result"] = "closed"
        ex = secstatus.status_file(doc, "0.1.0")["items"][0]
        self.assertEqual((ex["value"], ex["detail"]), ("0", "only from some addresses: 60001/tcp syncthing"))

    def test_locked_account(self):
        ssh = {i["id"]: i for i in status("ufw-docker")["items"]}["ssh"]
        self.assertIn("1 locked account can still log in with keys", ssh["detail"])
        de = {i["id"]: i for i in secstatus.localize(status("ufw-docker"), "de", NOW)["items"]}["ssh"]
        self.assertIn("1 gesperrtes Konto kann sich per Schlüssel anmelden", de["detail"])
        self.assertFalse(de["detail"].endswith("…"), "within the 200 characters of a detail")

    def test_journal_shorter_than_14_days(self):
        """The journal begins 9 days back: the counts name that day instead of "14 days"."""
        lg = {i["id"]: i for i in status("ufw-docker")["items"]}["logins"]
        self.assertEqual(lg["detail"], "1 failed attempt from 1 source since 11 Oct (the journal begins there)")
        de = {i["id"]: i for i in secstatus.localize(status("ufw-docker"), "de", NOW)["items"]}["logins"]
        self.assertEqual(de["detail"], "1 Fehlversuch von 1 Quelle seit 11.10. (dort beginnt das Journal)")
        doc, _ = make_states.state("ufw-docker")
        doc["logins"]["journal_start"] = "2026-10-06T20:00:00Z"      # 13 days 16 hours back: 14 days
        lg = {i["id"]: i for i in secstatus.status_file(doc, "0.1.0")["items"]}["logins"]
        self.assertEqual(lg["detail"], "1 failed attempt from 1 source in 14 days")
        doc["logins"]["journal_start"] = None
        doc["logins"]["failed_total"] = 0
        lg = {i["id"]: i for i in secstatus.status_file(doc, "0.1.0")["items"]}["logins"]
        self.assertEqual(lg["detail"], "no failed attempts in 14 days")

    def test_marks_change_the_status(self):
        st = status("ufw-docker", {"ports": {"8080/tcp": "test page"},
                                   "containers": {("runner", "docker-socket"): "CI"}})
        items = {i["id"]: i for i in st["items"]}
        self.assertEqual(items["exposure"]["state"], "info", "a marked port is public and expected")
        self.assertEqual(items["containers"]["state"], "info", "the marked finding no longer counts")
        self.assertEqual(st["state"], "warning", "SSH stays")

    def test_unknown_ports_are_never_ok(self):
        doc, _ = make_states.state("ufw-docker")
        for p in doc["ports"]:
            if p["state"] in ("ok", "info", "warning"):
                p["state"] = "ok" if p["state"] != "warning" else "none"
        st = secstatus.status_file(seccheck.view(doc, NO_MARKS), "0.1.0")
        ex = st["items"][0]
        self.assertEqual(ex["state"], "info")
        self.assertIn("1 port not assessable", ex["detail"])

    def test_rules_not_readable(self):
        doc, _ = make_states.state("ufw-docker")
        doc["sources"]["rules"] = {"state": "needs-root"}
        ex = secstatus.status_file(doc, "0.1.0")["items"][0]
        self.assertEqual((ex["state"], ex["detail"]), ("none", "the packet filter could not be read"))

    def test_addresses_or_sockets_not_readable(self):
        """Never OK and never "nothing reachable" without the addresses or the sockets; what is
        known (a port Docker publishes) still counts. A host really without a public address or a
        listening socket stays OK."""
        def item(scenario="ufw-docker", lang="en", iid="exposure", **kw):
            doc, system = make_states.state(scenario, **kw)
            st = secstatus.localize(make_states.status(doc, system), lang, NOW)
            self.assertEqual(secstatus.problems(st), [])
            return next((i["state"], i.get("value"), i.get("detail")) for i in st["items"] if i["id"] == iid)
        no_ip = {"results": {"ip-addr": fakesys.failing("Cannot open netlink socket")}}
        self.assertEqual(item(**no_ip), ("none", None, "the addresses could not be read; 9 ports not assessable"))
        self.assertEqual(item(lang="de", **no_ip), ("none", None, "die Adressen ließen sich nicht lesen; "
                                                                  "9 Ports nicht beurteilbar"))
        no_ss = {"results": {"ss": fakesys.failing("ss: failed")}}
        self.assertEqual(item(**no_ss), ("warning", "1", "the listening sockets could not be read; 8080/tcp web"))
        self.assertEqual(item(meta={"exists": []}, **no_ss), ("none", None, "the listening sockets could not be read"))
        self.assertEqual(item(lang="de", meta={"exists": []}, **no_ss),
                         ("none", None, "die lauschenden Sockets ließen sich nicht lesen"))
        lo_only = json.dumps([{"ifname": "lo", "flags": ["LOOPBACK", "UP"], "addr_info": [
            {"family": "inet", "local": "127.0.0.1", "prefixlen": 8, "scope": "host"}]}])
        self.assertEqual(item(results={"ip-addr": lo_only}), ("ok", "0", "no public address"))
        self.assertEqual(item(meta={"exists": []}, results={"ss": ""}), ("ok", "0", "no port reachable from the internet"))

    def test_docker_not_answering(self):
        """Docker does not answer: 8080, which it forwards past UFW, is not assessable (it was "no
        port" for it, as closed), and the detail says first that Docker could not be asked. Without a
        port at info or above that is "not checked", never OK: a port Docker publishes without
        docker-proxy has no socket and is not listed at all."""
        def exposure(st, lang="en"):
            st = secstatus.localize(st, lang, NOW)
            self.assertEqual(secstatus.problems(st), [])
            return next((i["state"], i.get("value"), i.get("detail")) for i in st["items"] if i["id"] == "exposure")
        doc, system = make_states.state("ufw-docker", docker_error=TimeoutError("timed out"))
        st = make_states.status(doc, system)
        self.assertEqual(exposure(st), ("info", "4", "Docker could not be asked; 80/tcp http, 443/tcp https, 443/udp "
                                                     "http3, 51820/udp wireguard; 1 port not assessable"))
        self.assertTrue(exposure(st, "de")[2].startswith("Docker ließ sich nicht abfragen; 80/tcp http"))
        self.assertTrue(exposure(st, "de")[2].endswith("; 1 Port nicht beurteilbar"))
        doc["ports"] = [p for p in doc["ports"] if p["state"] in ("ok", "none")]
        self.assertEqual(exposure(secstatus.status_file(doc, "0.1.0")),
                         ("none", None, "Docker could not be asked; 1 port not assessable"))
        doc, system = make_states.state("ufw-docker", meta={"exists": []})
        self.assertNotIn("Docker", exposure(make_states.status(doc, system))[2], "no Docker at all: nothing to ask")

    def test_hetzner_rules_not_known(self):
        """A firewall missing from the API's answer protects nothing: the ports count as open
        (UFW is off there); a known empty list of rules blocks all."""
        def exposure(change):
            doc, system = make_states.state("hetzner-open", **fakesys.hetzner_firewalls(change))
            return {i["id"]: i for i in make_states.status(doc, system)["items"]}["exposure"]
        ex = exposure(lambda h: h["firewalls"][0].update(rules=None))
        self.assertEqual((ex["state"], ex["value"]), ("warning", "9"), "as without a token: every public port")
        self.assertTrue(ex["detail"].startswith("22/tcp ssh, 80/tcp http, 443/tcp https, 443/udp http3, 5432/tcp "
                                                "postgresql (+4)"), ex["detail"])
        ex = exposure(lambda h: h["firewalls"][0].update(rules=[]))
        self.assertEqual((ex["state"], ex["value"], ex["detail"]), ("ok", "0", "no port reachable from the internet"))

    def test_fail2ban_not_read(self):
        """What fail2ban-client could not answer is "not checked" (none) first in the detail, a
        configured jail that does not run a warning, a missing database only a note."""
        def item(lang="en", results=None, meta=None):
            doc, system = make_states.state("fail2ban", meta=meta, **fakesys.fail2ban_quiet(results))
            st = secstatus.localize(make_states.status(doc, system), lang, NOW)
            self.assertEqual(secstatus.problems(st), [])
            for t in texts(st):
                self.assertIsNone(PRIVATE.search(t), t)
            return next((i["state"], i.get("value"), i.get("detail")) for i in st["items"] if i["id"] == "fail2ban")
        self.assertEqual(item(), ("ok", "3", "1 jail, 3 bans"))
        broken = {"f2b-dump": fakesys.failing("ERROR  /etc/fail2ban/jail.local: bad", 255),
                  "f2b-status": fakesys.failing("ERROR  NOK", 255)}
        self.assertEqual(item(results=broken), ("none", "3", "not checked completely: the configuration, the running "
                                                             "jails; 0 jails, 3 bans"))
        self.assertEqual(item("de", broken), ("none", "3", "nicht vollständig geprüft: die Konfiguration, die laufenden "
                                                           "Jails; 0 Jails, 3 Sperren"))
        self.assertEqual(item(results={"f2b-ping": secproc.Result(None, "", "", timeout=True)})[:2], ("none", "3"))
        self.assertTrue(item(results={"f2b-ping": secproc.Result(None, "", "", timeout=True)})[2].startswith(
            "not checked completely: no answer to ping"))
        jail = {"f2b-status-sshd": fakesys.failing("ERROR", 255)}
        self.assertEqual(item(results=jail), ("none", "3", "not checked completely: jail sshd; 1 jail, 3 bans"))
        self.assertEqual(item(results=jail, meta={"db_error": "locked"}),
                         ("none", None, "not checked completely: jail sshd; 1 jail; history of bans not readable"))
        self.assertEqual(item(meta={"db_error": "locked"}), ("ok", "1", "1 jail, 1 ban; history of bans not readable"))
        self.assertEqual(item("de", meta={"db_error": "locked"}),
                         ("ok", "1", "1 Jail, 1 Sperre; Verlauf der Sperren nicht lesbar"))
        stopped = {"f2b-status": "Status\n|- Number of jail:\t0\n`- Jail list:\t\n",
                   "iptables-save": "\n".join(x for x in fakesys._fixture("fail2ban", "commands", "iptables-save.txt")
                                              .splitlines() if "f2b-" not in x) + "\n"}
        self.assertEqual(item(results=stopped), ("warning", "3", "sshd: configured, but not running"))
        self.assertEqual(item("de", stopped), ("warning", "3", "sshd: eingerichtet, läuft aber nicht"))
        # 31 quiet jails: the 31st is not asked, so fail2ban is not checked completely.
        doc, system = make_states.state("fail2ban", **fakesys.fail2ban_jails(31))
        st = make_states.status(doc, system)
        f2b = {lang: next(i for i in secstatus.localize(st, lang, NOW)["items"] if i["id"] == "fail2ban")
               for lang in ("en", "de")}
        self.assertEqual((f2b["en"]["state"], f2b["en"]["detail"]),
                         ("none", "not checked completely: 1 jail beyond the first 30; 31 jails, 3 bans"))
        self.assertEqual(f2b["de"]["detail"], "nicht vollständig geprüft: 1 Jail über die ersten 30 hinaus; 31 Jails, 3 Sperren")

    def test_old_state(self):
        st = status("ufw-docker")
        doc = secstatus.localize(st, "de", datetime(2026, 10, 20, 13, 30, tzinfo=timezone.utc))
        scan = doc["items"][-1]
        self.assertEqual((scan["state"], scan["detail"]), ("warning", "die letzte Prüfung ist älter als eine Stunde"))
        self.assertEqual(doc["state"], "danger")
        self.assertEqual(secstatus.problems(doc), [])

    def test_problems_catches_breakage(self):
        st = secstatus.localize(status("ufw-docker"), "en", NOW)
        bad = json.loads(json.dumps(st))
        bad["state"] = "ok"
        bad["items"].append(dict(bad["items"][0]))
        bad["items"][1]["link"] = "javascript:alert(1)"
        bad["items"][2]["detail"] = "x" * 201
        p = secstatus.problems(bad)
        self.assertIn("state does not follow the items", p)
        self.assertIn("an id twice", p)
        self.assertTrue(any(x.startswith("link") for x in p))
        self.assertTrue(any(x.startswith("length") for x in p))


def checks(st, lang="en"):
    return {c["id"]: c for c in secstatus.localize(st, lang, NOW)["checks"]}


def exposure_findings(st):
    return next(i for i in st["items"] if i["id"] == "exposure")["findings"]


def fids(st):
    return [f["fid"] for f in exposure_findings(st)["list"]]


def make_danger(doc, port, proto="tcp"):
    """The port as a database port open to the whole internet (danger)."""
    p = next(x for x in doc["ports"] if x["port"] == port and x["proto"] == proto)
    p["reach"]["4"]["internet"]["result"] = "open"
    p["state"], p["why"] = "danger", "public-danger"
    return p


class Extension(unittest.TestCase):
    """The optional parts of the contract: `features`, a check per area, the findings of the
    item `exposure` with a `fid` per port, and when each was first seen."""

    def test_parts_of_every_scenario(self):
        for s in make_states.SCENARIOS:
            st = status(s)
            self.assertEqual(st["features"], ["checks", "findings"], s)
            self.assertEqual([c["id"] for c in st["checks"]], list(secstatus.AREAS), s)
            items = {i["id"] for i in st["items"]}
            for c in st["checks"]:
                self.assertIn(c["state"], secstatus.CHECK_STATES)
                self.assertEqual(c["title"], secstatus.t("en", c["id"] + ".title"), "the item's title")
                self.assertEqual(c.get("item"), c["id"] if c["id"] in items else None, (s, c))
                self.assertEqual((c["checked_at"], c["stale_after"]), (st["checked_at"], 3600))
                self.assertEqual("reason" in c, c["state"] != "checked", (s, c))
            fx = exposure_findings(st)
            self.assertEqual((fx["complete"], fx["total"]), (True, len(fx["list"])), s)
            for f in fx["list"]:
                port, proto = f["fid"][len("port."):].split("-")
                self.assertRegex(f["fid"], r"^port\.\d{1,5}-(tcp|udp)$")
                self.assertTrue(f["title"].startswith(f"{port}/{proto}"), f)
                self.assertEqual(f["link"], f"#/exposure/{port}-{proto}")
                self.assertIn(f["exposure"], ("internet", "restricted"))
                self.assertIn(f["state"], ("info", "warning", "danger"))
                self.assertEqual(f["since"], st["checked_at"], "first seen in this scan")
        self.assertEqual({c["id"]: c["state"] for c in status("nft-native")["checks"]},
                         {"exposure": "checked", "ssh": "partial", "logins": "checked", "containers": "checked",
                          "crowdsec": "notapplicable", "fail2ban": "notapplicable"})
        self.assertEqual(checks(status("nft-native"))["ssh"]["reason"],
                         "sshd -T without its privilege separation directory: not checkable")
        self.assertEqual(fids(status("derived-services"))[:3], ["port.22-tcp", "port.68-udp", "port.80-tcp"])
        self.assertEqual([(f["fid"], f["exposure"]) for f in exposure_findings(status("nft-native"))["list"]][-1],
                         ("port.60001-tcp", "restricted"), "only some addresses reach it")

    def test_fids_the_same_in_every_language_order_and_run(self):
        for s in ("ufw-docker", "nft-native", "derived-services", "hetzner-open"):
            doc, _ = make_states.state(s)
            st = secstatus.status_file(seccheck.view(doc, NO_MARKS), "0.1.0")
            want = fids(st)
            self.assertTrue(want, s)
            en, de = (secstatus.localize(st, lang, NOW) for lang in ("en", "de"))
            self.assertEqual((fids(en), fids(de)), (want, want), s)
            self.assertEqual(exposure_findings(en)["list"], exposure_findings(de)["list"], "titles too: ports, names")
            backwards = json.loads(json.dumps(doc))
            backwards["ports"].reverse()
            self.assertEqual(fids(secstatus.status_file(seccheck.view(backwards, NO_MARKS), "0.1.0")), want, s)
            again, _ = make_states.state(s)
            self.assertEqual(fids(secstatus.status_file(seccheck.view(again, NO_MARKS), "0.1.0")), want, s)
            de_doc = secstatus.document(seccheck.view(doc, NO_MARKS), "de", "0.1.0")
            self.assertEqual(fids(de_doc), want, "the German document itself")

    def test_second_dangerous_port_is_a_second_finding(self):
        doc, _ = make_states.state("ufw-docker")
        make_danger(doc, 8080)
        one = secstatus.status_file(doc, "0.1.0")
        ex = one["items"][0]
        self.assertEqual((ex["state"], [(f["fid"], f["state"]) for f in ex["findings"]["list"] if f["state"] == "danger"]),
                         ("danger", [("port.8080-tcp", "danger")]))
        make_danger(doc, 5432)
        two = secstatus.status_file(doc, "0.1.0")
        ex = two["items"][0]
        self.assertEqual(ex["state"], "danger", "the item stays danger")
        self.assertEqual([(f["fid"], f["state"]) for f in ex["findings"]["list"] if f["state"] == "danger"],
                         [("port.5432-tcp", "danger"), ("port.8080-tcp", "danger")], "one finding per port")
        self.assertEqual((ex["findings"]["total"], ex["findings"]["complete"]), (6, True))
        self.assertEqual([f for f in ex["findings"]["list"] if f["fid"] == "port.8080-tcp"],
                         [f for f in one["items"][0]["findings"]["list"] if f["fid"] == "port.8080-tcp"],
                         "the first finding unchanged")

    def test_expected_port_is_no_finding(self):
        marked = status("ufw-docker", {"ports": {"8080/tcp": "test page"}, "containers": {}})
        self.assertNotIn("port.8080-tcp", fids(marked))
        self.assertEqual(fids(marked), ["port.80-tcp", "port.443-tcp", "port.443-udp", "port.51820-udp"])
        fx = exposure_findings(marked)
        self.assertEqual((fx["total"], fx["complete"]), (4, True))
        self.assertEqual(checks(marked)["exposure"]["state"], "checked")
        self.assertIn("port.8080-tcp", fids(status("ufw-docker")), "without the mark it is one")

    def test_unread_sources_make_exposure_partial(self):
        """What the exposure rests on could not be read: the check is partial, the list is not
        complete, and the reason says why; never "checked"."""
        def run(scenario="ufw-docker", lang="en", **kw):
            doc, system = make_states.state(scenario, **kw)
            st = make_states.status(doc, system)
            loc = secstatus.localize(st, lang, NOW)
            self.assertEqual(secstatus.problems(loc), [])
            return loc["checks"][0], exposure_findings(loc)
        fail = fakesys.failing
        cases = [
            ({"results": {"iptables-save": fail("x"), "ip6tables-save": fail("x"), "nft": fail("x")}},
             "the packet filter could not be read; 8 ports not assessable"),
            ({"results": {"nft": fail("netlink: Error: cache initialization failed")}},
             "part of the packet filter could not be read"),
            ({"results": {"ip-addr": fail("Cannot open netlink socket")}},
             "the addresses could not be read; 9 ports not assessable"),
            ({"results": {"ss": fail("ss: failed")}}, "the listening sockets could not be read"),
            ({"docker_error": TimeoutError("timed out")}, "Docker could not be asked; 1 port not assessable"),
            ({"uid": 1000, "results": {"iptables-save": fakesys.failing("Permission denied (you must be root)"),
                                       "ip6tables-save": fakesys.failing("Permission denied (you must be root)"),
                                       "nft": fakesys.failing("Operation not permitted")},
              "docker_error": PermissionError(13, "Permission denied")}, None),
        ]
        for kw, reason in cases:
            check, fx = run(**kw)
            self.assertEqual((check["id"], check["state"], fx["complete"]), ("exposure", "partial", False), kw)
            if reason:
                self.assertEqual(check["reason"], reason, kw)
            self.assertEqual(fx["total"], len(fx["list"]))
        check, fx = run(lang="de", results={"ip-addr": fakesys.failing("Cannot open netlink socket")})
        self.assertEqual(check["reason"], "die Adressen ließen sich nicht lesen; 9 Ports nicht beurteilbar")
        check, fx = run(results={"ss": fakesys.failing("ss: failed")})
        self.assertEqual([f["fid"] for f in fx["list"]], ["port.8080-tcp"], "what Docker publishes still counts")
        check, fx = run("hetzner-open", **fakesys.hetzner_firewalls(lambda h: h["firewalls"][0].update(rules=None)))
        self.assertEqual((check["state"], check["reason"], fx["complete"]),
                         ("partial", "the Hetzner Cloud Firewall could not be read", False))
        # A port the evaluator cannot judge (an unreadable rule) makes it partial too, also when marked.
        text = fakesys._fixture("ufw-docker", "commands", "iptables-save.txt").replace(
            "-A ufw-user-input -i wg0 -j ACCEPT", "-A ufw-user-input -m mark --mark 0x1 -j ACCEPT\n"
                                                  "-A ufw-user-input -i wg0 -j ACCEPT")
        check, fx = run(results={"iptables-save": text})
        self.assertEqual((check["state"], check["reason"], fx["complete"]), ("partial", "3 ports not assessable", False))
        self.assertNotIn("port.9090-tcp", [f["fid"] for f in fx["list"]], "not assessable is no finding")
        check, fx = run(results={"iptables-save": text}, files={seccheck.MARKS_FILE: "port 9090/tcp Cockpit\n"})
        self.assertEqual((check["state"], fx["complete"]), ("partial", False), "a mark does not assess it")
        check, fx = run()
        self.assertEqual((check["state"], fx["complete"]), ("checked", True), "everything read")
        self.assertNotIn("reason", check)

    def test_checks_of_what_is_not_installed(self):
        c = {k: v["state"] for k, v in checks(status("ufw-docker")).items()}
        self.assertEqual(c, {"exposure": "checked", "ssh": "checked", "logins": "checked", "containers": "checked",
                             "crowdsec": "notapplicable", "fail2ban": "notapplicable"})
        de = checks(status("ufw-docker"), "de")
        self.assertEqual((de["crowdsec"]["reason"], de["fail2ban"]["reason"], de["containers"]["title"]),
                         ("CrowdSec ist nicht installiert", "fail2ban ist nicht installiert", "Container-Härtung"))
        self.assertNotIn("item", de["crowdsec"], "no item for what is not installed")

        def run(scenario="ufw-docker", **kw):
            doc, system = make_states.state(scenario, **kw)
            return checks(make_states.status(doc, system))
        no_docker = run(meta={"exists": []})["containers"]
        self.assertEqual((no_docker["state"], no_docker["reason"], no_docker.get("item")),
                         ("notapplicable", "Docker is not installed", None))
        failed = run(docker_error=ConnectionRefusedError(111, "Connection refused"))["containers"]
        self.assertEqual((failed["state"], failed["reason"], failed["item"]),
                         ("failed", "Docker could not be asked", "containers"))
        self.assertEqual(run("hetzner-open")["crowdsec"]["state"], "checked")
        cs = run("hetzner-open", results={"cscli-decisions": fakesys.failing("cannot connect to the API")})["crowdsec"]
        self.assertEqual((cs["state"], cs["reason"]), ("partial", "cscli did not answer completely"))
        self.assertEqual(run("fail2ban")["fail2ban"]["state"], "checked")
        broken = {"f2b-dump": fakesys.failing("ERROR  bad", 255), "f2b-status": fakesys.failing("ERROR  NOK", 255)}
        f2b = run("fail2ban", **fakesys.fail2ban_quiet(broken))["fail2ban"]
        self.assertEqual((f2b["state"], f2b["reason"]),
                         ("partial", "not checked completely: the configuration, the running jails"))
        f2b = run("fail2ban", meta={"db_error": "locked"}, **fakesys.fail2ban_quiet())["fail2ban"]
        self.assertEqual((f2b["state"], f2b["reason"]), ("partial", "history of bans not readable"))
        f2b = run("fail2ban", **fakesys.fail2ban_jails(31))["fail2ban"]
        self.assertEqual((f2b["state"], f2b["reason"]), ("partial", "not checked completely: 1 jail beyond the first 30"))
        lg = run(results={"journal": secproc.Result(None, "", "", timeout=True)})["logins"]
        self.assertEqual((lg["state"], lg["reason"]), ("failed", "the journal did not answer in time"))
        lg = run(gone=("journal", "journal-start"))["logins"]
        self.assertEqual((lg["state"], lg["reason"], lg.get("item")), ("unsupported", "journalctl is not installed", None))
        ssh = run(files={"/usr/sbin/sshd": None})["ssh"]
        self.assertEqual((ssh["state"], ssh["reason"]), ("notapplicable", "no SSH server installed"))
        ssh = run(results={"sshd-T": fakesys.failing("/etc/ssh/sshd_config line 3: Bad configuration option")},
                  files={"/etc/passwd": None})["ssh"]
        self.assertEqual(ssh["state"], "failed", "neither the configuration nor the keys read")

    def test_never_checked_or_broken(self):
        for why, state, reason in (("missing", "unconfigured", "not checked yet"),
                                   ("unreadable", "failed", "the last result could not be read")):
            doc = secstatus.none_document("en", "0.1.0", why)
            self.assertEqual(secstatus.problems(doc), [])
            self.assertEqual(doc["features"], ["checks", "findings"])
            self.assertEqual([(c["id"], c["state"], c["reason"]) for c in doc["checks"]],
                             [(a, state, reason) for a in secstatus.AREAS])
            self.assertFalse(any("item" in c or "checked_at" in c for c in doc["checks"]), "never checked: no time")
        de = secstatus.none_document("de", "0.1.0", "missing")
        self.assertEqual((de["checks"][0]["title"], de["checks"][0]["reason"]),
                         ("Aus dem Internet erreichbar", "noch nicht geprüft"))

    def test_more_findings_than_an_answer_holds(self):
        doc, _ = make_states.state("ufw-docker")
        base = next(p for p in doc["ports"] if p["port"] == 8080)
        doc["ports"] = []
        for n in range(120):
            p = json.loads(json.dumps(base))
            p["port"], p["id"] = 10000 + n, f"tcp-{10000 + n}"
            p["state"] = "danger" if n >= 115 else "warning"
            doc["ports"].append(p)
        st = secstatus.status_file(doc, "0.1.0")
        fx = exposure_findings(st)
        self.assertEqual((len(fx["list"]), fx["total"], fx["complete"]), (100, 120, False))
        self.assertEqual([f["fid"] for f in fx["list"][:5]], [f"port.{10115 + n}-tcp" for n in range(5)],
                         "the most severe first")
        self.assertEqual(checks(st)["exposure"]["state"], "checked", "read fully, only not all listed")
        self.assertEqual(secstatus.problems(secstatus.localize(st, "en", NOW)), [])
        self.assertTrue(len(json.dumps(secstatus.localize(st, "de", NOW)).encode()) < 64 << 10)

    def test_since_comes_from_first_seen(self):
        doc, _ = make_states.state("ufw-docker")
        doc["first_seen"]["port.8080-tcp"] = "2026-10-01T08:00:00Z"
        fx = exposure_findings(secstatus.status_file(doc, "0.1.0"))
        self.assertEqual({f["fid"]: f["since"] for f in fx["list"]}["port.8080-tcp"], "2026-10-01T08:00:00Z")
        del doc["first_seen"]
        fx = exposure_findings(secstatus.status_file(doc, "0.1.0"))
        self.assertFalse(any("since" in f for f in fx["list"]), "a state of an older version: no since")

    def test_problems_catches_a_broken_extension(self):
        st = secstatus.localize(status("ufw-docker"), "en", NOW)

        def broken(change):
            bad = json.loads(json.dumps(st))
            change(bad)
            return secstatus.problems(bad)
        self.assertEqual(broken(lambda d: None), [])
        self.assertTrue(broken(lambda d: d["checks"][0].update(state="fine")))
        self.assertTrue(broken(lambda d: d["checks"][0].update(item="nothing")))
        self.assertTrue(broken(lambda d: d["checks"].append(dict(d["checks"][0]))))
        self.assertTrue(broken(lambda d: d["checks"][1].update(reason="x" * 201)))
        self.assertTrue(broken(lambda d: d.update(checks="all")))
        self.assertTrue(broken(lambda d: d.update(features="checks")))
        def fx(d):
            return d["items"][0]["findings"]
        self.assertTrue(broken(lambda d: fx(d)["list"][0].update(fid="Port 8080")))
        self.assertTrue(broken(lambda d: fx(d)["list"].append(dict(fx(d)["list"][0]))))
        self.assertTrue(broken(lambda d: fx(d)["list"][0].update(link="javascript:alert(1)")))
        self.assertTrue(broken(lambda d: fx(d)["list"][0].update(exposure="everywhere")))
        self.assertTrue(broken(lambda d: fx(d)["list"][0].update(since="yesterday")))
        self.assertTrue(broken(lambda d: fx(d).update(total=1)))
        self.assertTrue(broken(lambda d: fx(d).update(complete="yes")))
        self.assertTrue(broken(lambda d: fx(d)["list"].extend(
            [dict(fx(d)["list"][0], fid=f"port.{n}-tcp") for n in range(20000, 20100)])))


class FirstSeen(unittest.TestCase):
    """state.json keeps when each port the internet reaches was first seen (`first_seen`): over
    scans for a port still there, dropped for one that is gone, but only after a check that
    read everything."""

    T1, T2, T3, T4 = "2026-10-20T12:00:00Z", "2026-10-20T12:15:00Z", "2026-10-20T12:30:00Z", "2026-10-20T12:45:00Z"
    VPN_ONLY = fakesys._fixture("ufw-docker", "commands", "iptables-save.txt").replace(
        "-A DOCKER -d 172.17.0.2/32",
        "-A DOCKER-USER -o docker0 -m conntrack --ctstate NEW ! -s 10.8.0.0/24 -j DROP\n-A DOCKER -d 172.17.0.2/32", 1)

    def scan(self, now, previous=None, **kw):
        meta = dict(kw.pop("meta", {}), now=now)
        return seccheck.scan(fakesys.FakeSystem("ufw-docker", meta=meta, **kw), previous)

    def test_kept_over_scans_and_dropped_when_gone(self):
        first = self.scan(self.T1)
        want = {f: self.T1 for f in ("port.443-tcp", "port.443-udp", "port.51820-udp", "port.80-tcp", "port.8080-tcp")}
        self.assertEqual(first["first_seen"], want)
        second = self.scan(self.T2, first)
        self.assertEqual(second["first_seen"], want, "a second scan keeps the times")
        st = secstatus.status_file(seccheck.view(second, NO_MARKS), "0.1.0")
        self.assertEqual({f["since"] for f in exposure_findings(st)["list"]}, {self.T1})
        gone = self.scan(self.T3, second, results={"iptables-save": self.VPN_ONLY})
        self.assertEqual(secstatus.check_exposure(gone, "en")[0], "checked")
        self.assertEqual(gone["first_seen"], {k: v for k, v in want.items() if k != "port.8080-tcp"},
                         "8080 is VPN only now: gone")
        back = self.scan(self.T4, gone)
        self.assertEqual(back["first_seen"]["port.8080-tcp"], self.T4, "back again: seen anew")
        self.assertEqual(back["first_seen"]["port.80-tcp"], self.T1)

    def test_kept_when_the_check_could_not_read_everything(self):
        second = self.scan(self.T2, self.scan(self.T1))
        partial = self.scan(self.T3, second, docker_error=TimeoutError("timed out"))
        self.assertEqual(secstatus.check_exposure(partial, "en")[0], "partial")
        self.assertEqual(partial["first_seen"]["port.8080-tcp"], self.T1, "not assessable: not known to be gone")
        no_ss = self.scan(self.T3, second, results={"ss": fakesys.failing("ss: failed")})
        self.assertEqual(no_ss["first_seen"], second["first_seen"], "sockets not read: every time kept")

    def test_marks_do_not_change_it(self):
        marked = self.scan(self.T1, files={seccheck.MARKS_FILE: "port 8080/tcp test page\n"})
        self.assertIn("port.8080-tcp", marked["first_seen"], "kept for when the mark is taken back")
        v = seccheck.view(marked, {"ports": {"8080/tcp": "x"}, "containers": {}})
        self.assertEqual(secstatus.first_seen(v, marked["first_seen"]), marked["first_seen"])

    def test_garbage_in_the_previous_state(self):
        prev = {"first_seen": {"port.8080-tcp": "2026-10-01T00:00:00Z", "port.80-tcp": "2099-01-01T00:00:00Z",
                               "__proto__": "2026-10-01T00:00:00Z", "port.443-tcp": 5, "port.x-tcp": self.T1}}
        doc = self.scan(self.T2, prev)
        self.assertEqual(doc["first_seen"]["port.8080-tcp"], "2026-10-01T00:00:00Z")
        self.assertEqual((doc["first_seen"]["port.80-tcp"], doc["first_seen"]["port.443-tcp"]), (self.T2, self.T2),
                         "a time after the scan or no time: this scan")
        self.assertEqual(sorted(doc["first_seen"]), sorted({"port.443-tcp", "port.443-udp", "port.51820-udp",
                                                            "port.80-tcp", "port.8080-tcp"}))
        for junk in (None, [], "x", {"first_seen": "x"}, {"first_seen": None}):
            self.assertEqual(len(self.scan(self.T1, junk)["first_seen"]), 5)


class Verb(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "status.json")
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(status("hetzner-open"), f, ensure_ascii=False)

    def test_languages(self):
        for argv, lang in ((["--lang", "de"], "de"), (["--lang=de-AT"], "de"), (["--lang", "de_CH"], "de"),
                           (["--lang", "fr"], "en"), ([], "en")):
            rc, out, _ = call(argv, self.path)
            self.assertEqual(rc, 0, argv)
            doc = json.loads(out)
            self.assertEqual(doc["items"][0]["title"],
                             "Aus dem Internet erreichbar" if lang == "de" else "Reachable from the internet", argv)
            self.assertNotEqual(doc["version"], "unknown", "from security.js next to lib/")
            self.assertEqual(doc["checks"][0]["title"], doc["items"][0]["title"], "the check in the same language")
            self.assertEqual(doc["checks"][5]["reason"],
                             "fail2ban ist nicht installiert" if lang == "de" else "fail2ban is not installed", argv)
            self.assertEqual([f["fid"] for f in doc["items"][0]["findings"]["list"]],
                             ["port.80-tcp", "port.443-tcp", "port.443-udp", "port.8443-tcp"], argv)

    def test_wrong_calls(self):
        for argv in (["--lang"], ["--lang", "x"], ["--lang", "de", "extra"], ["--lang", "../etc"], ["-l", "de"]):
            self.assertEqual(call(argv, self.path)[0], 64, argv)

    def test_missing_broken_unreadable(self):
        rc, out, _ = call([], os.path.join(self.dir, "none.json"))
        doc = json.loads(out)
        self.assertEqual((rc, doc["state"], doc["summary"]), (0, "none", "Not checked yet."))
        self.assertEqual({c["state"] for c in doc["checks"]}, {"unconfigured"}, "never checked")
        with open(self.path, "w", encoding="utf-8") as f:
            st = status("hetzner-open")
            st["checks"][0]["state"] = "fine"
            json.dump(st, f)
        doc = json.loads(call([], self.path)[1])
        self.assertEqual((doc["summary"], {c["state"] for c in doc["checks"]}),
                         ("The state of Security Monitor could not be read.", {"failed"}), "a broken check: unreadable")
        with open(self.path, "w") as f:
            f.write("{not json")
        rc, out, _ = call(["--lang", "de"], self.path)
        self.assertEqual((rc, json.loads(out)["summary"]), (0, "Der Stand von Security Monitor ließ sich nicht lesen."))
        with open(self.path, "w") as f:
            json.dump({"schema": 2}, f)
        self.assertEqual(json.loads(call([], self.path)[1])["state"], "none")
        rc, _, err = call([], self.dir)
        self.assertEqual(rc, 77, "a directory cannot be read")

    def test_as_a_process(self):
        """The verb as the board runs it: a process of its own, well within 2 seconds."""
        t0 = time.monotonic()
        p = subprocess.run([sys.executable, "-IB", os.path.join(LIB, "security.py"), "status", "--lang", "de"],
                           capture_output=True, text=True, timeout=10)
        self.assertLess(time.monotonic() - t0, 2)
        self.assertEqual(p.returncode, 0, p.stderr)
        doc = json.loads(p.stdout)
        self.assertEqual(doc["schema"], 1)
        p = subprocess.run([sys.executable, "-IB", os.path.join(LIB, "security.py"), "nonsense"], capture_output=True,
                           text=True, timeout=10)
        self.assertEqual(p.returncode, 64)


if __name__ == "__main__":
    unittest.main(verbosity=1)
