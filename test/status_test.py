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

import make_states  # noqa: E402
import seccheck  # noqa: E402
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
            "recorded-ci": ("danger", [("exposure", "info", "2"), ("ssh", "info", None), ("logins", "ok", "0"),
                                       ("containers", "danger", "5"), ("scan", "ok", None)]),
            "recorded-edge": ("danger", [("exposure", "info", "2"), ("ssh", "info", None), ("logins", "ok", "0"),
                                         ("containers", "danger", "1"), ("scan", "ok", None)]),
            "recorded-ipv6": ("danger", [("exposure", "ok", "0"), ("ssh", "info", None), ("logins", "ok", "0"),
                                         ("containers", "danger", "1"), ("scan", "ok", None)]),
            "recorded-services": ("danger", [("exposure", "warning", "10"), ("ssh", "info", None),
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

    def test_wrong_calls(self):
        for argv in (["--lang"], ["--lang", "x"], ["--lang", "de", "extra"], ["--lang", "../etc"], ["-l", "de"]):
            self.assertEqual(call(argv, self.path)[0], 64, argv)

    def test_missing_broken_unreadable(self):
        rc, out, _ = call([], os.path.join(self.dir, "none.json"))
        doc = json.loads(out)
        self.assertEqual((rc, doc["state"], doc["summary"]), (0, "none", "Not checked yet."))
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
