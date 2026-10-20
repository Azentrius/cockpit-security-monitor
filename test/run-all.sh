#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Runs every offline test: no root, no network, no command on this machine's packet filter (the
# helpers read the scenarios in test/fixtures/ through test/fakesys.py).
#   cd test && npm ci && ./run-all.sh
# The end-to-end test with a real Cockpit, UFW and Docker is separate: CI, job e2e.
set -u
cd "$(dirname "$0")" || exit 2

if [ ! -d node_modules/jsdom ] && [ -z "${NODE_PATH:-}" ]; then
    echo "jsdom missing – run first: (cd test && npm ci)" >&2
    exit 2
fi

fail=0
run() {
    local name=$1; shift
    local log
    log=$(mktemp)
    if "$@" >"$log" 2>&1; then
        echo "PASS  $name"
    else
        echo "FAIL  $name"
        sed 's/^/      | /' "$log"
        fail=1
    fi
    rm -f "$log"
}

run "python: parsers, keys, journal, marks"              python3 -B lib_test.py
run "python: packet filter model and evaluator"          python3 -B fw_test.py
run "python: scan against the scenarios"                 python3 -B scan_test.py
run "python: status for the Status Board, its verb"      python3 -B status_test.py
run "python: verbs of the page (marks, root, calls)"     python3 -B verbs_test.py
run "python: Hetzner Cloud Firewall"                     python3 -B hetzner_test.py
run "python: syntax lib/*.py"                            python3 -B -c 'import ast, glob; [ast.parse(open(f).read(), f) for f in glob.glob("../lib/*.py")]'
run "shell:  syntax of the shell scripts"                bash -c 'for f in ../tools/*.sh ../packaging/scripts/* *.sh e2e/*.sh fixtures/*.sh; do [ -e "$f" ] || continue; sh -n "$f" || exit 1; done'
run "page:   tabs, ports, marks, dialogs, escaping"      node page.test.js
run "page:   texts in English and German"                node i18n.test.js
run "page:   files, calls, manifest"                     node files.test.js
run "design: contrast (light + dark)"                    python3 -B contrast_test.py
run "design: fonts ship with the add-on"                 python3 -B fonts_test.py
run "repo:   version + changelog"                        sh ../tools/check-version.sh
run "repo:   shared design files"                        sh ../tools/check-design-files.sh

echo
if [ $fail = 0 ]; then echo "ALL TESTS PASSED"; else echo "THERE ARE FAILURES"; fi
exit $fail
