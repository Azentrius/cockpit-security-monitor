// SPDX-License-Identifier: Apache-2.0
/* The texts of the page (plugin/i18n.js), without a browser:
 *   - every key in English and German, with the same placeholders and plural shape,
 *   - every key security.js and menu-status.js ask for exists (t("…"), and the families
 *     security.js builds: why., ck., …),
 *   - no German in English, German with "Sie", no long dash (U+2014) anywhere.
 * Run with: node test/i18n.test.js */
"use strict";
const assert = require("assert");
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const PLUGIN = path.join(__dirname, "..", "plugin");
const box = { window: {} };
vm.runInNewContext(fs.readFileSync(path.join(PLUGIN, "i18n.js"), "utf8"), box);
const { en, de } = box.window.SecurityMonitorI18n;
const js = ["security.js", "menu-status.js"].map((f) => fs.readFileSync(path.join(PLUGIN, f), "utf8")).join("\n");
const html = fs.readFileSync(path.join(PLUGIN, "index.html"), "utf8");

let passed = 0;
function t(name, fn) {
    try { fn(); passed++; } catch (e) { console.error("FAIL", name, "\n ", e.stack || e.message); process.exitCode = 1; }
}
const vars = (s) => (typeof s === "object" ? [s.one, s.other] : [s]).map((x) => (x.match(/\{\w+\}/g) || []).sort().join());
const texts = (o) => Object.values(o).flatMap((s) => (typeof s === "object" ? [s.one, s.other] : [s]));

t("the same keys in both languages", () => {
    assert.deepStrictEqual(Object.keys(de).sort(), Object.keys(en).sort());
});

t("the same placeholders and plural shape", () => {
    Object.keys(en).forEach((k) => {
        assert.strictEqual(typeof de[k], typeof en[k], k);
        assert.deepStrictEqual(vars(de[k]), vars(en[k]), k);
        assert.strictEqual(((typeof en[k] === "object" ? en[k].other : en[k]).match(/`/g) || []).length % 2, 0, "backticks in pairs: " + k);
    });
});

t("every key the page asks for exists", () => {
    const used = new Set([...js.matchAll(/\bt\("([a-zA-Z0-9.-]+)"/g), ...js.matchAll(/\btr\("([a-zA-Z0-9.-]+)"/g),
                          ...html.matchAll(/data-i18n(?:-aria|-placeholder)?="([^"]+)"/g)].map((m) => m[1]));
    used.forEach((k) => assert.ok(k.endsWith(".") || k in en, "missing: " + k));
    const families = {
        "why.": ["public-danger", "public-other", "public-expected", "outside-only", "restricted", "unknown", "hetzner",
                 "only-vpn", "only-private", "only-vpn-private", "local", "expected", "note"],
        "label.": ["none", "ok", "info", "warning", "danger"],
        "reach.": ["open", "restricted", "closed", "unknown", "absent"],
        "det.res.": ["open", "restricted", "closed", "unknown"],
        "det.class.": ["internet", "vpn", "private", "local"],
        "det.owner.": ["ufw", "docker", "fail2ban", "crowdsec"],
        "det.hz.": ["blocks", "allows", "restricted"],
        "ov.filter.": ["on", "off", "unknown", "noaddr"],
        "ck.": ["docker-socket", "privileged", "pid-host", "cap-add", "host-mount", "network-host", "root-user",
                "no-new-privileges", "apparmor-unconfined"],
        "kind.": ["docker-socket", "privileged", "pid-host", "cap-add", "host-mount", "network-host", "root-user",
                  "no-new-privileges", "apparmor-unconfined"],
        "sshd.": ["password-on", "password-off", "kbd-pam", "kbd-off", "kbd-no-pam", "empty-passwords", "root-yes", "root-key",
                  "root-forced", "root-no", "pubkey-on", "pubkey-off", "tries-many", "tries-ok", "allow-list", "no-allow-list",
                  "x11-on", "x11-off", "agent-on", "agent-off"],
        "key.": ["dsa", "rsa-short", "no-from", "unreadable"],
        "file.": ["file-writable", "dir-writable", "file-owner", "dir-owner", "link"],
        "src.class.": ["internet", "vpn", "private", "local", "cgnat", "link", "other"],
        "src.": ["ip", "ss", "rules", "docker", "ufw", "hetzner", "sshd", "keys", "journal", "crowdsec"],
        "reason.": ["missing", "needs-root", "error", "timeout", "partial"],
        "cs.": ["old-engine", "not-running", "bouncer-input-only", "bouncer-no-docker-user", "no-bouncer"],
        "svc.": ["ssh", "cockpit"],
        "tab.": ["exposure", "ssh", "logins", "containers", "crowdsec"],
    };
    Object.entries(families).forEach(([prefix, keys]) => keys.forEach((k) => assert.ok(prefix + k in en, "missing: " + prefix + k)));
});

t("no German in English, Sie in German", () => {
    const german = /[äöüßÄÖÜ„“]|\b(und|nicht|oder|der|die|das|Sie|Ihre?)\b/;
    texts(en).forEach((s) => assert.ok(!german.test(s.replace(/„|“/g, "")) || /“Refresh”|“Not checked”|“Marked as expected”|“Not assessable”|“OK”/.test(s), "German in English: " + s));
    texts(de).forEach((s) => assert.ok(!/\b(du|dein|deine|dich|dir)\b/i.test(s), "du in German: " + s));
});

t("no long dash", () => {
    const dash = String.fromCharCode(0x2014);
    texts(en).concat(texts(de)).forEach((s) => assert.ok(!s.includes(dash), s));
    [js, html].forEach((f) => assert.ok(!f.includes(dash)));
});

console.log(process.exitCode ? "THERE ARE FAILURES" : `all ${passed} passed`);
