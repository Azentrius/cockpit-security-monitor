#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Writes test/fixtures/state-<scenario>.json (what security-scan.py writes
for that scenario, with the times it took set to 0) and status-<scenario>.json
(the status file) for the page tests and the preview. scan_test.py checks
that they are current.

    python3 test/fixtures/make_states.py
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, os.path.join(HERE, "..", "..", "lib"))
import fakesys  # noqa: E402
import seccheck  # noqa: E402
import secstatus  # noqa: E402

SCENARIOS = ("ufw-docker", "hetzner-open", "nft-native", "fail2ban",
             "derived-ci", "derived-edge", "derived-ipv6", "derived-services")
VERSION = "0.1.0"


def state(scenario, **kw):
    system = fakesys.FakeSystem(scenario, **kw)
    doc = seccheck.scan(system)
    doc["took_ms"] = 0
    for s in doc["sources"].values():
        if "took_ms" in s:
            s["took_ms"] = 0
    return doc, system


def status(doc, system):
    marks, _ = seccheck.read_marks(system)
    return secstatus.status_file(seccheck.view(doc, marks), VERSION)


def dump(path, doc):
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(doc, f, indent=1, ensure_ascii=False)
        f.write("\n")


if __name__ == "__main__":
    for s in SCENARIOS:
        doc, system = state(s)
        dump(os.path.join(HERE, f"state-{s}.json"), doc)
        dump(os.path.join(HERE, f"status-{s}.json"), status(doc, system))
    print("written")
