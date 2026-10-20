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
            "ufw-docker": ("danger", [("exposure", "warning", "5"), ("ssh", "warning", "2"), ("logins", "ok", "1"),
                                      ("containers", "danger", "1"), ("scan", "ok", None)]),
            "hetzner-open": ("warning", [("exposure", "info", "4"), ("ssh", "warning", "2"),
                                         ("logins", "warning", "1"), ("containers", "warning", "2"),
                                         ("crowdsec", "warning", "2"), ("scan", "ok", None)]),
            "nft-native": ("danger", [("exposure", "warning", "5"), ("ssh", "warning", "2"), ("logins", "ok", "0"),
                                      ("containers", "danger", "2"), ("scan", "ok", None)]),
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
        cr = status("hetzner-open")["items"][4]["detail"]
        self.assertEqual(cr, "outdated version 1.4.6; bouncer does not protect container ports; 2 active decisions")
        de = secstatus.localize(status("hetzner-open"), "de", NOW)
        self.assertEqual(de["items"][2]["detail"], "1 erfolgreiche Anmeldung von außerhalb von VPN und Privatnetz")

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
