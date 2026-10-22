#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""security-hetzner.py against recorded answers of Hetzner's API (formats as
the API and hcloud-python document them): the server found by its IPv4
address or its IPv6 network, pages, the firewalls applied to it; a failing
API keeps the last good answer; the token never leaves the token file. And
how the scan reads the firewall (seccheck.hetzner_reach). Offline: no request
leaves the test."""

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.join(HERE, "..", "lib")
sys.dont_write_bytecode = True
sys.path.insert(0, LIB)
import importlib.util  # noqa: E402

import seccheck  # noqa: E402

spec = importlib.util.spec_from_file_location("security_hetzner", os.path.join(LIB, "security-hetzner.py"))
hz = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hz)

API = os.path.join(HERE, "fixtures", "hetzner-open", "hetzner-api")
TOKEN = "fixture-token-0123456789"


def answer(name):
    with open(os.path.join(API, name + ".json"), encoding="utf-8") as f:
        return json.load(f)


class Api:
    def __init__(self, pages=None, fail=None):
        self.pages = pages
        self.fail = fail
        self.calls = []

    def __call__(self, path, token):
        self.calls.append(path)
        assert token == TOKEN
        if self.fail:
            raise hz.ApiError(self.fail)
        kind = path.split("?")[0].strip("/")
        if self.pages and kind in self.pages:
            page = int(path.split("page=")[1].split("&")[0])
            return self.pages[kind][page - 1]
        return answer(kind)


class Fetch(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.out = os.path.join(self.dir, "hetzner.json")
        self.token = os.path.join(self.dir, "hetzner.token")
        with open(self.token, "w") as f:
            f.write(TOKEN + "\n")

    def run_main(self, api, addrs, minute=0):
        err = io.StringIO()
        with redirect_stderr(err):
            rc = hz.main(["--output", self.out, "--token-file", self.token], get=api, addrs=addrs,
                         now=datetime(2026, 10, 20, 12, minute, tzinfo=timezone.utc))
        with open(self.out, encoding="utf-8") as f:
            text = f.read()
        self.assertNotIn(TOKEN, text + err.getvalue(), "the token is never written or printed")
        return rc, json.loads(text), err.getvalue()

    def test_matched_by_ipv4(self):
        api = Api()
        rc, doc, _ = self.run_main(api, ["203.0.113.20"])
        self.assertEqual(rc, 0)
        self.assertEqual(api.calls, ["/servers?page=1&per_page=50", "/firewalls?page=1&per_page=50"])
        self.assertEqual((doc["server"], doc["matched_by"], doc["error"]), ({"id": 4711, "name": "web-1"}, "ipv4",
                                                                             None))
        self.assertEqual([f["name"] for f in doc["firewalls"]], ["web"])
        self.assertEqual(len(doc["firewalls"][0]["rules"]), 5, "outgoing rules are left out")

    def test_matched_by_ipv6_network(self):
        rc, doc, _ = self.run_main(Api(), ["2001:db8:20::abcd"])
        self.assertEqual((doc["server"]["id"], doc["matched_by"]), (4711, "ipv6"))

    def test_not_matched(self):
        rc, doc, _ = self.run_main(Api(), ["198.51.100.99"])
        self.assertEqual((doc["server"], doc["firewalls"], doc["error"]), (None, [], None))

    def test_pages(self):
        s = answer("servers")
        first = {"servers": s["servers"][1:], "meta": {"pagination": {"page": 1, "next_page": 2}}}
        second = {"servers": s["servers"][:1], "meta": {"pagination": {"page": 2, "next_page": None}}}
        api = Api(pages={"servers": [first, second]})
        rc, doc, _ = self.run_main(api, ["203.0.113.20"])
        self.assertEqual(doc["server"]["id"], 4711)
        self.assertIn("/servers?page=2&per_page=50", api.calls)

    def test_failure_keeps_the_last_good_answer(self):
        self.run_main(Api(), ["203.0.113.20"], minute=0)
        rc, doc, err = self.run_main(Api(fail="HTTP 401 unauthorized"), ["203.0.113.20"], minute=15)
        self.assertEqual(rc, 0)
        self.assertEqual((doc["ok_at"], doc["tried_at"], doc["error"]), ("2026-10-20T12:00:00Z", "2026-10-20T12:15:00Z",
                                                                         "HTTP 401 unauthorized"))
        self.assertEqual(doc["server"]["id"], 4711)
        self.assertIn("HTTP 401", err)

    def test_first_failure_and_bad_token_file(self):
        rc, doc, _ = self.run_main(Api(fail="network: timed out"), ["203.0.113.20"])
        self.assertEqual((doc["ok_at"], doc["server"], doc["error"]), (None, None, "network: timed out"))
        with open(self.token, "w") as f:
            f.write("two tokens\n")
        rc, doc, _ = self.run_main(Api(), ["203.0.113.20"])
        self.assertEqual(doc["error"], "the token file is empty or not a single token")
        os.remove(self.token)
        rc, doc, _ = self.run_main(Api(), ["203.0.113.20"])
        self.assertEqual(doc["error"], "the token could not be read")

    def test_unexpected_answer(self):
        api = Api(pages={"servers": [{"error": {"code": "x"}}]})
        rc, doc, _ = self.run_main(api, ["203.0.113.20"])
        self.assertEqual(doc["error"], "unexpected answer for /servers")

    def test_firewall_missing_from_the_answer(self):
        """The server names a firewall /v1/firewalls does not list: its rules are not known (null,
        not []), and the scan never counts it as protection."""
        fws = answer("firewalls")
        fws["firewalls"] = [f for f in fws["firewalls"] if f["id"] != 38]
        rc, doc, _ = self.run_main(Api(pages={"firewalls": [fws]}), ["203.0.113.20"])
        self.assertEqual(doc["firewalls"], [{"id": 38, "name": None, "status": "applied", "rules": None}])
        known = dict(doc, configured=True)
        self.assertEqual(seccheck.hetzner_reach(known, 4, "tcp", 5432), ("unknown", [{"firewall": "", "id": 38}], []))


class Reach(unittest.TestCase):
    def fw(self, rules, status="applied"):
        return {"configured": True, "server": {"id": 1}, "ok_at": "x",
                "firewalls": [{"id": 1, "name": "fw", "status": status, "rules": rules}]}

    def test_cases(self):
        r = seccheck.hetzner_reach
        web = self.fw([{"direction": "in", "protocol": "tcp", "port": "80-85", "source_ips": ["0.0.0.0/0", "::/0"]},
                       {"direction": "in", "protocol": "tcp", "port": "22", "source_ips": ["198.51.100.7/32",
                                                                                           "10.8.0.0/24"]},
                       {"direction": "in", "protocol": "udp", "port": "any", "source_ips": ["::/0"]}])
        self.assertEqual(r(web, 4, "tcp", 82)[0], "allows")
        self.assertEqual(r(web, 6, "tcp", 80)[0], "allows")
        self.assertEqual(r(web, 4, "tcp", 22)[::2], ("restricted", ["198.51.100.7/32"]))
        self.assertEqual(r(web, 6, "tcp", 22)[0], "blocks")
        self.assertEqual(r(web, 6, "udp", 5000)[0], "allows")
        self.assertEqual(r(web, 4, "udp", 5000)[0], "blocks")
        self.assertEqual(r(web, 4, "tcp", 8080)[0], "blocks")
        self.assertEqual(r(self.fw([], status="pending"), 4, "tcp", 22)[0], "none", "not applied yet")
        self.assertEqual(r({"firewalls": []}, 4, "tcp", 22)[0], "none", "no firewall: nothing filtered")

    def test_rules_not_known(self):
        """null (the firewall missing from the API's answer) is not [] (no incoming rule: all
        blocked): it never claims protection, alone or next to others."""
        r = seccheck.hetzner_reach
        self.assertEqual(r(self.fw([]), 4, "tcp", 5432)[0], "blocks")
        self.assertEqual(r(self.fw(None), 4, "tcp", 5432), ("unknown", [{"firewall": "fw", "id": 1}], []))
        self.assertEqual(r(self.fw("garbage"), 6, "udp", 53)[0], "unknown")
        self.assertEqual(r(self.fw(None, status="pending"), 4, "tcp", 22)[0], "none", "not applied: not counted")
        everyone = {"direction": "in", "protocol": "tcp", "port": "443", "source_ips": ["0.0.0.0/0", "::/0"]}
        office = {"direction": "in", "protocol": "tcp", "port": "8443", "source_ips": ["198.51.100.0/24"]}

        def two(first, second):
            return {"firewalls": [{"id": 1, "name": "a", "status": "applied", "rules": first},
                                  {"id": 2, "name": "b", "status": "applied", "rules": second}]}
        for rules in (two([everyone, office], None), two(None, [everyone, office])):
            self.assertEqual(r(rules, 4, "tcp", 443)[0], "allows", "a known rule lets everyone in: safe to say")
            self.assertEqual(r(rules, 4, "tcp", 8443)[0], "unknown", "the other one may let everyone in")
            self.assertEqual(r(rules, 4, "tcp", 22)[0], "unknown")
        self.assertEqual(r(two([office, "not a rule"], [everyone]), 4, "tcp", 8443)[::2],
                         ("restricted", ["198.51.100.0/24"]))
        self.assertEqual(r(two([office], [dict(office, port="8443", source_ips=["0.0.0.0/0"])]), 4, "tcp", 8443)[0],
                         "allows", "the union of the rules of both")
        self.assertEqual(r(two([], []), 4, "tcp", 443)[0], "blocks")


if __name__ == "__main__":
    unittest.main(verbosity=1)
