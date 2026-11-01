// SPDX-License-Identifier: Apache-2.0
/* A status answer judged by Status Board's own rules (test/e2e/upgrade.sh, CI only): the board's
   src/lib/status.js, from a checkout of the board at the release the workflow names, reads the
   answer as the board does (validateStatus). Prints what the board takes; exits 1 when the answer
   is not readable or the board leaves out any part of it: an item, a check or a finding.

     node test/e2e/board-rules.js BOARD/src/lib/status.js PACKAGE ANSWER.json */
"use strict";
const fs = require("fs");
const path = require("path");

const [statusJs, pkg, file] = process.argv.slice(2);
if (!statusJs || !pkg || !file) {
    console.error("usage: node board-rules.js BOARD/src/lib/status.js PACKAGE ANSWER.json");
    process.exit(64);
}
const board = require(path.resolve(statusJs));
const text = fs.readFileSync(file, "utf8");
const raw = JSON.parse(text);
const result = board.validateStatus(text, pkg);
if (!result.ok) {
    console.log(JSON.stringify(result));
    console.error("the board cannot read the answer");
    process.exit(1);
}
const s = result.status;
const count = (items) => items.reduce((n, it) => n + (it.findings && Array.isArray(it.findings.list) ? it.findings.list.length : 0), 0);
const taken = {
    addon: s.addon,
    state: s.state,
    items: s.items.length,
    dropped: s.dropped,
    features: s.features,
    checks: (s.checks || []).map(c => c.id + ":" + c.state),
    findings: Object.fromEntries(s.items.filter(it => it.findings).map(it => [it.id, {
        complete: it.findings.complete, total: it.findings.total, listed: it.findings.list.length,
    }])),
    extDropped: s.extDropped,
};
console.log(JSON.stringify(taken));
const problems = [];
if (s.dropped !== 0 || s.items.length !== raw.items.length) problems.push(`items left out: ${raw.items.length - s.items.length}`);
if (s.extDropped !== 0) problems.push(`optional parts left out: ${s.extDropped}`);
if ((s.checks || []).length !== (Array.isArray(raw.checks) ? raw.checks.length : 0)) problems.push("checks left out");
if (count(s.items) !== count(raw.items)) problems.push(`findings left out: ${count(raw.items) - count(s.items)}`);
if (!s.features.includes("checks") || !s.features.includes("findings")) problems.push(`features taken: ${s.features.join(", ")}`);
if (problems.length) {
    console.error(problems.join("\n"));
    process.exit(1);
}
