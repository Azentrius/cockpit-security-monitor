// SPDX-License-Identifier: Apache-2.0
/* What the page's files may and may not contain, checked without a browser:
 *   - values from the system only ever reach the page as text: no innerHTML and its relatives,
 *   - nothing Cockpit's CSP blocks: no inline scripts, no event handler or style attributes,
 *   - every stylesheet url() names a file of the page,
 *   - the page calls only the fixed verbs of security.py, with administrative access only
 *     where it acts (scan, the timer, the marks),
 *   - the manifest names the status verb as the status contract wants it.
 * Run with: node test/files.test.js */
"use strict";
const assert = require("assert");
const fs = require("fs");
const path = require("path");

const PLUGIN = path.join(__dirname, "..", "plugin");
const read = (f) => fs.readFileSync(path.join(PLUGIN, f), "utf8");
const html = read("index.html");
const strip = (s) => s.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
const js = strip(read("security.js"));

let passed = 0;
function t(name, fn) {
    try { fn(); passed++; } catch (e) { console.error("FAIL", name, "\n ", e.stack || e.message); process.exitCode = 1; }
}

t("no HTML from strings", () => ["security.js", "i18n.js"].forEach((f) => {
    const code = strip(read(f));
    ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "DOMParser", "createContextualFragment", "eval(",
     "new Function", "setTimeout(\"", "javascript:"].forEach((bad) => assert.ok(!code.includes(bad), f + " uses " + bad));
}));

t("index.html: only external scripts, no handlers, no style attributes", () => {
    const scripts = html.match(/<script\b[^>]*>[\s\S]*?<\/script>/g) || [];
    assert.ok(scripts.length > 0);
    scripts.forEach((s) => assert.ok(/^<script src="[^"]+"><\/script>$/.test(s), "external only: " + s));
    assert.ok(!/\son[a-z]+=/i.test(html), "no event handler attributes");
    assert.ok(!/\sstyle=/i.test(html), "no style attributes");
    assert.ok(!/<style\b/i.test(html), "no style elements");
});

t("index.html: the page frame", () => {
    assert.ok(html.includes('<h1 class="az-page-title">Security <span class="az-page-title__suffix">Monitor</span></h1>'));
    assert.ok(html.includes("<title>Security Monitor</title>"));
    assert.strictEqual((html.match(/az-btn--primary/g) || []).length, 1, "Refresh is the only filled button");
    assert.ok(html.indexOf("azentrius-theme.js") < html.indexOf("azentrius.css"), "the theme script before the stylesheet");
    assert.ok(html.includes('<script src="../base1/cockpit.js"></script>') && html.includes('<script src="../base1/po.js"></script>'));
    assert.ok(!/https?:\/\/(?!azentrius\.com|github\.com\/Azentrius)/.test(html), "no other external address");
});

t("stylesheets take every file from the page", () => fs.readdirSync(PLUGIN).filter((f) => f.endsWith(".css")).forEach((sheet) => {
    const css = read(sheet).replace(/\/\*[\s\S]*?\*\//g, "");
    [...css.matchAll(/url\(\s*(["']?)([^"')]*)\1\s*\)/g)].map((m) => m[2]).forEach((u) => {
        if (u.startsWith("data:")) return;
        assert.ok(!/^[a-z][a-z0-9+.-]*:/i.test(u) && !u.startsWith("/"), sheet + ": a relative path, not " + u);
        const file = path.resolve(PLUGIN, u);
        assert.ok(file.startsWith(PLUGIN + path.sep) && fs.statSync(file).isFile(), sheet + ": " + u + " exists");
    });
}));

t("only the fixed verbs, and require only where the page acts", () => {
    const spawns = [...js.matchAll(/spawn\(\s*\[HELPER, ([^\]]*)\]\s*,\s*"(try|require)"\)/g)].map((m) => [m[1], m[2]]);
    const verbs = spawns.map(([a, su]) => a.split(",")[0].trim() + " " + su);
    assert.deepStrictEqual(verbs.sort(), ['"scan" require', '"show" try', '"status" try'].sort());
    const dialog = [...js.matchAll(/\[HELPER, "(install|remove|expect|unexpect)"/g)].map((m) => m[1]);
    assert.deepStrictEqual([...new Set(dialog)].sort(), ["expect", "install", "remove", "unexpect"]);
    assert.ok(/proc = spawn\(argv, "require"\)/.test(js), "the dialog runs as administrator");
    assert.ok(!/cockpit\.spawn\(\[/.test(js), "every call goes through spawn()");
    assert.ok(!/superuser: "require"/.test(js.replace(/err: superuser === "require"/, "")), "no other require");
    assert.ok(/const PORT_KEY = \/\^\[0-9\]\{1,5\}\\\/\(tcp\|udp\)\$\//.test(js), "a port key is checked before it is passed");
    assert.ok(js.includes('cockpit.file(STATUS_PATH, { syntax: JSON })'), "only status.json is watched");
    assert.ok(!/\.watch\(/.test(js.replace("file.watch((content, tag)", "")), "no other watch");
});

t("the manifest names the status verb as the contract wants it", () => {
    const m = JSON.parse(read("manifest.json"));
    assert.strictEqual(m.menu.index.label, "Security Monitor");
    const cmd = m.azentrius.status;
    assert.deepStrictEqual(cmd, ["/usr/lib/cockpit-security-monitor/security.py", "status"]);
    assert.ok(/^\/usr\/lib\/cockpit-[a-z0-9][a-z0-9-]{0,40}(\/[A-Za-z0-9_][A-Za-z0-9._-]{0,80}){1,3}$/.test(cmd[0]));
    assert.strictEqual(m.requires.cockpit, "264");
    assert.ok(fs.existsSync(path.join(__dirname, "..", "lib", path.basename(cmd[0]))), "the verb ships in lib/");
});

t("the status module names the package folder", () => {
    const py = fs.readFileSync(path.join(__dirname, "..", "lib", "secstatus.py"), "utf8");
    assert.ok(/^ADDON = "security"$/m.test(py), "addon = the page's folder /usr/share/cockpit/security");
    assert.ok(py.includes('"/usr/share/cockpit/security/security.js"'));
});

t("the label classes exist in azentrius.css", () => {
    const css = read("azentrius.css");
    [...js.matchAll(/"az-label(?: az-label--([a-z]+))?"/g)].forEach((m) => {
        if (m[1]) assert.ok(css.includes(".az-label--" + m[1]), "az-label--" + m[1]);
    });
});

console.log(process.exitCode ? "THERE ARE FAILURES" : `all ${passed} passed`);
