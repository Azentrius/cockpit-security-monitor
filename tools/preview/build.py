#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Builds a static preview of the page with the test fixtures.

    python3 tools/preview/build.py      -> tools/preview/out/security/index.html
    open tools/preview/out/security/index.html?scenario=ufw-docker&lang=de

More query parameters: admin=0 (no administrative access: the summary only),
marks=1 (8080/tcp and the runner's Docker socket marked as expected),
tab=ssh (opens that tab, as a link #/ssh would). Cockpit's base1/cockpit.js
is replaced by cockpit-stub.js, which answers the page's calls from
test/fixtures/state-*.json and status-*.json. Nothing touches a real server.
The output directory is generated and git-ignored.
"""
import json
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
FIX = os.path.join(REPO, "test", "fixtures")
OUT = os.path.join(HERE, "out")
NOW = "2026-10-20T12:05:00Z"
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.join(REPO, "lib"))
import seccheck  # noqa: E402
import secstatus  # noqa: E402

PO_STUB = """// Stand-in for Cockpit's base1/po.js: ?lang=de switches the session language.
const _l = new URLSearchParams(location.search).get("lang");
if (_l && _l !== "en") cockpit.locale({"": {"language": _l, "language-direction": "ltr"}});
"""
MARKS = {"ports": {"8080/tcp": "test page for the office"}, "containers": {("runner", "docker-socket"): "CI needs it"}}


def main():
    data = {}
    for name in sorted(os.listdir(FIX)):
        if not (name.startswith("state-") and name.endswith(".json")):
            continue
        s = name[len("state-"):-len(".json")]
        with open(os.path.join(FIX, name), encoding="utf-8") as f:
            state = json.load(f)
        with open(os.path.join(FIX, f"status-{s}.json"), encoding="utf-8") as f:
            status = json.load(f)
        data[s] = {"state": state, "marked": seccheck.view(state, MARKS),
                   "status": {lang: secstatus.localize(status, lang) for lang in ("en", "de")}}
    shutil.rmtree(OUT, ignore_errors=True)
    os.makedirs(os.path.join(OUT, "base1"))
    shutil.copytree(os.path.join(REPO, "plugin"), os.path.join(OUT, "security"))
    with open(os.path.join(HERE, "cockpit-stub.js"), encoding="utf-8") as f:
        stub = f.read()
    stub = stub.replace("__FIXTURES__", json.dumps(data, ensure_ascii=False)).replace("__NOW__", json.dumps(NOW))
    with open(os.path.join(OUT, "base1", "cockpit.js"), "w", encoding="utf-8") as f:
        f.write(stub)
    with open(os.path.join(OUT, "base1", "po.js"), "w", encoding="utf-8") as f:
        f.write(PO_STUB)
    print("Preview:", os.path.join(OUT, "security", "index.html") + "?scenario=ufw-docker")


if __name__ == "__main__":
    main()
