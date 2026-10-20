// SPDX-License-Identifier: Apache-2.0
// Stand-in for Cockpit's base1/cockpit.js in the preview (tools/preview/build.py): answers the
// page's calls from the test fixtures. ?scenario=…&lang=de&admin=0&marks=1&tab=ssh
(function () {
    "use strict";
    const DATA = __FIXTURES__;
    const NOW = Date.parse(__NOW__);
    const q = new URLSearchParams(location.search);
    const scenario = DATA[q.get("scenario")] ? q.get("scenario") : Object.keys(DATA)[0];
    const admin = q.get("admin") !== "0";
    const d = DATA[scenario];
    Date.now = () => NOW;

    function proc(fn) {
        let cb = null;
        const p = new Promise((resolve, reject) => setTimeout(() => {
            try {
                const out = fn((text) => cb && cb(text));
                resolve(out);
            } catch (e) {
                reject(e);
            }
        }, 200));
        p.stream = (f) => { cb = f; return p; };
        return p;
    }
    const listeners = {};
    window.cockpit = {
        language: "en",
        locale(po) { if (po && po[""] && po[""].language) this.language = po[""].language; },
        location: {
            path: q.get("tab") ? [q.get("tab")] : [],
            go(path) { this.path = path; (listeners.locationchanged || []).forEach((f) => f()); },
        },
        addEventListener(ev, f) { (listeners[ev] = listeners[ev] || []).push(f); },
        file(path) {
            return {
                read() { return Promise.resolve(path === "/etc/hostname" ? "preview-host\n" : null); },
                watch(cb) { cb(null, "tag-1"); },
            };
        },
        spawn(argv) {
            const verb = argv.slice(1).join(" ");
            if (verb === "show") {
                return proc(() => {
                    if (!admin) {
                        const e = new Error("access denied");
                        e.exit_status = 77;
                        throw e;
                    }
                    return JSON.stringify({ root: true, state: q.get("marks") === "1" ? d.marked : d.state, marks_problem: null,
                                            marks_file: "/etc/cockpit-security-monitor/exposure.conf", timer: "inactive",
                                            next: null, running: false, hetzner_token: !!d.state.firewall.hetzner.configured });
                });
            }
            if (verb.startsWith("status")) return proc(() => JSON.stringify(d.status[argv[3] === "de" ? "de" : "en"]));
            return proc((stream) => { stream("+ " + argv.join(" ") + "\n"); return ""; });
        },
        jump() {},
        transport: { wait() {} },
    };
})();
