# SPDX-License-Identifier: Apache-2.0
"""The status contract of the Azentrius add-ons (schema 1) for Security
Monitor: a short summary of state.json with the marks applied, which the
Status Board reads through `security.py status --lang en|de`.

Lives in /usr/lib/cockpit-security-monitor (root-owned). Standard library
only, no side effects on import, nothing here runs a command.

The scan writes status.json (0644) next to state.json (0600): the English
document plus the German texts under "i18n" (a field readers of schema 1
ignore). Only numbers, states, ports, and names of services and containers:
no addresses, no user names, no paths.
"""

import os
import re
from datetime import datetime, timezone

SCHEMA = 1
ADDON = "security"
LABEL = "Security Monitor"
STALE_AFTER = 3600      # seconds: the scan runs every 15 minutes; older than 1 hour is out of date
ORDER = {"none": 0, "ok": 1, "info": 2, "warning": 3, "danger": 4}
ID_RE = re.compile(r"^[a-z0-9-]{1,40}$")
LINK_RE = re.compile(r"^#/[A-Za-z0-9/_-]{0,80}$")
MAX_NAMES = 5
MAX_DETAIL = 200
PAGE_JS = (os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "plugin", "security.js"),
           "/usr/share/cockpit/security/security.js")

T = {
    "en": {
        "summary.missing": "Not checked yet.",
        "summary.unreadable": "The state of Security Monitor could not be read.",
        "summary.ok": "Nothing found in the areas checked.",
        "summary.found": {"one": "Findings in {n} area: {list}.", "other": "Findings in {n} areas: {list}."},
        "summary.unchecked": "Some areas could not be checked.",
        "missing.title": "Not checked yet",
        "missing.detail": "Open Security Monitor with administrative access, or set up its regular check.",
        "unreadable.title": "State not readable",
        "unreadable.detail": "Run the check again in Security Monitor.",
        "exposure.title": "Reachable from the internet",
        "exposure.none": "no port reachable from the internet",
        "exposure.public": "{list}",
        "exposure.unknown": {"one": "{n} port not assessable", "other": "{n} ports not assessable"},
        "exposure.nopublic": "no public address",
        "exposure.norules": "the packet filter could not be read",
        "ssh.title": "SSH",
        "ssh.password-on": "password login on",
        "ssh.kbd-pam": "passwords through PAM (keyboard-interactive)",
        "ssh.empty-passwords": "empty passwords allowed",
        "ssh.root-yes": "root may log in with a password",
        "ssh.root-key": "root may log in with a key",
        "ssh.rsa-short": {"one": "{n} RSA key under 3072 bits", "other": "{n} RSA keys under 3072 bits"},
        "ssh.dsa": {"one": "{n} DSA key", "other": "{n} DSA keys"},
        "ssh.files": {"one": "{n} key file others can change", "other": "{n} key files others can change"},
        "ssh.no-from": {"one": "{n} key without from=", "other": "{n} keys without from="},
        "ssh.notes": {"one": "{n} note", "other": "{n} notes"},
        "ssh.unchecked": "sshd -T failed: not checkable",
        "ssh.privsep": "sshd -T without its privilege separation directory: not checkable",
        "logins.title": "Logins",
        "logins.outside": {"one": "{n} successful login from outside VPN and private networks",
                           "other": "{n} successful logins from outside VPN and private networks"},
        "logins.failed": {"one": "{n} failed attempt from {m} sources in 14 days",
                          "other": "{n} failed attempts from {m} sources in 14 days"},
        "logins.failed1": {"one": "{n} failed attempt from 1 source in 14 days",
                           "other": "{n} failed attempts from 1 source in 14 days"},
        "logins.none": "no failed attempts in 14 days",
        "containers.title": "Container hardening",
        "containers.ok": "no finding in {n} containers",
        "containers.kind.docker-socket": "Docker socket",
        "containers.kind.privileged": "privileged",
        "containers.kind.pid-host": "host PIDs",
        "containers.kind.cap-add": "extra capabilities",
        "containers.kind.host-mount": "host folders writable",
        "containers.kind.network-host": "host network",
        "containers.kind.root-user": "runs as root",
        "containers.kind.no-new-privileges": "without no-new-privileges",
        "containers.kind.apparmor-unconfined": "AppArmor unconfined",
        "crowdsec.title": "CrowdSec",
        "crowdsec.old-engine": "outdated version {value}",
        "crowdsec.not-running": "not running",
        "crowdsec.bouncer-input-only": "bouncer does not protect container ports",
        "crowdsec.bouncer-no-docker-user": "bouncer does not protect container ports",
        "crowdsec.no-bouncer": "no bouncer",
        "crowdsec.decisions": {"one": "{n} active decision", "other": "{n} active decisions"},
        "scan.title": "Check",
        "scan.ok": "checked every 15 minutes when set up",
        "scan.old": "the last check is older than an hour",
        "unchecked": "not checked",
    },
    "de": {
        "summary.missing": "Noch nicht geprüft.",
        "summary.unreadable": "Der Stand von Security Monitor ließ sich nicht lesen.",
        "summary.ok": "In den geprüften Bereichen nichts gefunden.",
        "summary.found": {"one": "Befunde in {n} Bereich: {list}.", "other": "Befunde in {n} Bereichen: {list}."},
        "summary.unchecked": "Einige Bereiche ließen sich nicht prüfen.",
        "missing.title": "Noch nicht geprüft",
        "missing.detail": "Öffnen Sie Security Monitor mit administrativem Zugriff, oder richten Sie die "
                          "regelmäßige Prüfung ein.",
        "unreadable.title": "Stand nicht lesbar",
        "unreadable.detail": "Prüfen Sie in Security Monitor erneut.",
        "exposure.title": "Aus dem Internet erreichbar",
        "exposure.none": "kein Port aus dem Internet erreichbar",
        "exposure.public": "{list}",
        "exposure.unknown": {"one": "{n} Port nicht beurteilbar", "other": "{n} Ports nicht beurteilbar"},
        "exposure.nopublic": "keine öffentliche Adresse",
        "exposure.norules": "der Paketfilter ließ sich nicht lesen",
        "ssh.title": "SSH",
        "ssh.password-on": "Anmeldung mit Passwort an",
        "ssh.kbd-pam": "Passwörter über PAM (keyboard-interactive)",
        "ssh.empty-passwords": "leere Passwörter erlaubt",
        "ssh.root-yes": "root darf sich mit Passwort anmelden",
        "ssh.root-key": "root darf sich mit Schlüssel anmelden",
        "ssh.rsa-short": {"one": "{n} RSA-Schlüssel unter 3072 Bit", "other": "{n} RSA-Schlüssel unter 3072 Bit"},
        "ssh.dsa": {"one": "{n} DSA-Schlüssel", "other": "{n} DSA-Schlüssel"},
        "ssh.files": {"one": "{n} Schlüsseldatei, die andere ändern können",
                      "other": "{n} Schlüsseldateien, die andere ändern können"},
        "ssh.no-from": {"one": "{n} Schlüssel ohne from=", "other": "{n} Schlüssel ohne from="},
        "ssh.notes": {"one": "{n} Hinweis", "other": "{n} Hinweise"},
        "ssh.unchecked": "sshd -T schlug fehl: nicht prüfbar",
        "ssh.privsep": "sshd -T ohne Verzeichnis für die Rechtetrennung: nicht prüfbar",
        "logins.title": "Anmeldungen",
        "logins.outside": {"one": "{n} erfolgreiche Anmeldung von außerhalb von VPN und Privatnetz",
                           "other": "{n} erfolgreiche Anmeldungen von außerhalb von VPN und Privatnetz"},
        "logins.failed": {"one": "{n} Fehlversuch von {m} Quellen in 14 Tagen",
                          "other": "{n} Fehlversuche von {m} Quellen in 14 Tagen"},
        "logins.failed1": {"one": "{n} Fehlversuch von 1 Quelle in 14 Tagen",
                           "other": "{n} Fehlversuche von 1 Quelle in 14 Tagen"},
        "logins.none": "keine Fehlversuche in 14 Tagen",
        "containers.title": "Container-Härtung",
        "containers.ok": "kein Befund in {n} Containern",
        "containers.kind.docker-socket": "Docker-Socket",
        "containers.kind.privileged": "privilegiert",
        "containers.kind.pid-host": "Host-PIDs",
        "containers.kind.cap-add": "zusätzliche Capabilities",
        "containers.kind.host-mount": "Host-Ordner schreibbar",
        "containers.kind.network-host": "Host-Netz",
        "containers.kind.root-user": "läuft als root",
        "containers.kind.no-new-privileges": "ohne no-new-privileges",
        "containers.kind.apparmor-unconfined": "AppArmor unconfined",
        "crowdsec.title": "CrowdSec",
        "crowdsec.old-engine": "veraltete Version {value}",
        "crowdsec.not-running": "läuft nicht",
        "crowdsec.bouncer-input-only": "Bouncer schützt keine Container-Ports",
        "crowdsec.bouncer-no-docker-user": "Bouncer schützt keine Container-Ports",
        "crowdsec.no-bouncer": "kein Bouncer",
        "crowdsec.decisions": {"one": "{n} aktive Sperre", "other": "{n} aktive Sperren"},
        "scan.title": "Prüfung",
        "scan.ok": "alle 15 Minuten, wenn eingerichtet",
        "scan.old": "die letzte Prüfung ist älter als eine Stunde",
        "unchecked": "nicht geprüft",
    },
}


def t(lang, key, **kw):
    s = T[lang][key]
    if isinstance(s, dict):
        s = s["one"] if kw.get("n") == 1 else s["other"]
    return s.format(**kw)


def version():
    """The add-on's version, from const VERSION in the page's security.js."""
    for p in PAGE_JS:
        try:
            with open(p, encoding="utf-8") as f:
                m = re.search(r'^\s*const VERSION = "([0-9A-Za-z.+~-]{1,40})";', f.read(1 << 20), re.M)
        except OSError:
            continue
        if m:
            return m.group(1)
    return "unknown"


def overall(items):
    worst = max((ORDER.get(i.get("state"), 0) for i in items), default=0)
    if worst >= ORDER["info"]:
        return next(k for k, v in ORDER.items() if v == worst)
    return "ok" if any(i.get("state") == "ok" for i in items) else "none"


def worst(states, default="ok"):
    return max(states, key=lambda s: ORDER.get(s, 0), default=default)


def _names(names, n=MAX_NAMES):
    names = [str(x) for x in names]
    more = len(names) - n
    return ", ".join(names[:n]) + (f" (+{more})" if more > 0 else "")


def _clip(text):
    if len(text) <= MAX_DETAIL:
        return text
    cut = text[:MAX_DETAIL - 2]
    at = max(cut.rfind(", "), cut.rfind("; "), cut.rfind(" "))
    return (cut[:at] if at > 0 else cut).rstrip(",; ") + " …"


def _port_label(p):
    what = (p.get("service") or {}).get("containers") or (p.get("service") or {}).get("processes") or []
    name = p.get("name") or (what[0] if what else "")
    return f"{p['port']}/{p['proto']}" + (f" {name}" if name else "")


def items_of(doc, lang):
    at = doc.get("generated")
    src = doc.get("sources") or {}
    out = []

    def item(iid, state, value=None, detail=None, link=True):
        i = {"id": iid, "state": state, "title": t(lang, iid + ".title")}
        if value is not None:
            i["value"] = str(value)
        if detail:
            i["detail"] = _clip(detail)
        if link:
            i["link"] = "#/" + iid
        i["checked_at"] = at
        i["stale_after"] = STALE_AFTER
        return i

    # exposure
    ports = doc.get("ports") or []
    if (src.get("rules") or {}).get("state") != "ok":
        out.append(item("exposure", "none", detail=t(lang, "exposure.norules")))
    else:
        public = [p for p in ports if any(p["reach"][f]["internet"]["result"] in ("open", "restricted")
                                          for f in ("4", "6"))]
        unknown = [p for p in ports if p["state"] == "none"]
        state = worst([p["state"] for p in ports if p["state"] != "none"], "ok")
        if unknown and ORDER[state] < ORDER["info"]:
            state = "info"
        public.sort(key=lambda p: (-ORDER.get(p["state"], 0), p["port"]))
        parts = []
        if public:
            parts.append(t(lang, "exposure.public", list=_names([_port_label(p) for p in public])))
        elif not any((doc.get("network") or {}).get("public", {}).values()):
            parts.append(t(lang, "exposure.nopublic"))
        else:
            parts.append(t(lang, "exposure.none"))
        if unknown:
            parts.append(t(lang, "exposure.unknown", n=len(unknown)))
        out.append(item("exposure", state, len(public), "; ".join(parts)))

    # ssh
    ssh = doc.get("ssh") or {}
    sshd = ssh.get("sshd") or {}
    if sshd.get("state") in ("ok",) or ssh.get("keys") is not None:
        parts = []
        codes = {f["code"]: f["state"] for f in ssh.get("findings") or []}
        for code in ("password-on", "kbd-pam", "empty-passwords", "root-yes", "root-key"):
            if code in codes:
                parts.append(t(lang, "ssh." + code))
        keys = [k for f in ssh.get("keys") or [] for k in f["keys"]]
        for code in ("rsa-short", "dsa"):
            n = sum(1 for k in keys if any(x["code"] == code for x in k["findings"]))
            if n:
                parts.append(t(lang, "ssh." + code, n=n))
        n = sum(1 for f in ssh.get("keys") or [] if f["problems"])
        if n:
            parts.append(t(lang, "ssh.files", n=n))
        n = sum(1 for k in keys if any(x["code"] == "no-from" for x in k["findings"]))
        if n:
            parts.append(t(lang, "ssh.no-from", n=n))
        if sshd.get("state") == "error":
            parts.append(t(lang, "ssh.privsep" if sshd.get("reason") == "privsep-dir-missing" else "ssh.unchecked"))
        state = ssh.get("state") or "none"
        warn = sum(1 for f in ssh.get("findings") or [] if ORDER[f["state"]] >= ORDER["warning"]) + \
            sum(1 for k in keys if ORDER[k.get("state", "ok")] >= ORDER["warning"]) + \
            sum(1 for f in ssh.get("keys") or [] if f["problems"])
        out.append(item("ssh", state, warn or None, "; ".join(parts)))
    elif sshd.get("state") == "error":
        out.append(item("ssh", "none", detail=t(lang, "ssh.privsep" if sshd.get("reason") == "privsep-dir-missing"
                                                 else "ssh.unchecked")))

    # logins
    lg = doc.get("logins") or {}
    if lg.get("state") == "ok":
        if lg.get("outside"):
            out.append(item("logins", "warning", lg["outside"], t(lang, "logins.outside", n=lg["outside"])))
        else:
            n, m = lg.get("failed_total", 0), lg.get("failed_sources", 0)
            detail = t(lang, "logins.none") if not n else t(lang, "logins.failed1" if m == 1 else "logins.failed",
                                                             n=n, m=m)
            out.append(item("logins", "ok", n, detail))
    elif lg.get("state") in ("error", "timeout"):
        out.append(item("logins", "none", detail=t(lang, "unchecked")))

    # containers
    cs = doc.get("containers") or {}
    if cs.get("state") == "ok":
        items = cs.get("items") or []
        found = [f for c in items for f in c["findings"] if f["state"] not in ("ok", "none")]
        state = worst([f["state"] for f in found], "ok")
        if found:
            parts = []
            top = [k for k in ("docker-socket", "privileged", "pid-host", "cap-add", "host-mount")
                   if any(f["kind"] == k and f["state"] not in ("ok",) for c in items for f in c["findings"])]
            for k in top:
                names = [c["name"] for c in items if any(f["kind"] == k and f["state"] != "ok" for f in c["findings"])]
                parts.append(t(lang, "containers.kind." + k) + ": " + _names(names, 3))
            if not top:
                kinds = sorted({f["kind"] for f in found}, key=lambda k: list(T["en"]).index("containers.kind." + k))
                parts.append(", ".join(t(lang, "containers.kind." + k) for k in kinds))
            n = sum(1 for c in items if any(ORDER.get(f["state"], 0) >= ORDER["warning"] for f in c["findings"]))
            out.append(item("containers", state, n or None, "; ".join(parts)))
        else:
            out.append(item("containers", "ok", detail=t(lang, "containers.ok", n=len(items))))
    elif doc.get("sources", {}).get("docker", {}).get("state") in ("error", "needs-root"):
        out.append(item("containers", "none", detail=t(lang, "unchecked")))

    # crowdsec (only when installed)
    cr = doc.get("crowdsec") or {}
    if cr.get("installed"):
        parts = [t(lang, "crowdsec." + f["code"], value=f.get("value", "")) for f in cr.get("findings") or []]
        parts = list(dict.fromkeys(parts))
        parts.append(t(lang, "crowdsec.decisions", n=cr.get("decisions_total", 0)))
        out.append(item("crowdsec", cr.get("state") or "ok", cr.get("decisions_total", 0), "; ".join(parts)))

    out.append(item("scan", "ok", detail=t(lang, "scan.ok"), link=False))
    return out


def document(doc, lang, ver):
    items = items_of(doc, lang)
    state = overall(items)
    found = [i for i in items if ORDER[i["state"]] >= ORDER["info"]]
    if found:
        summary = t(lang, "summary.found", n=len(found), list=", ".join(i["title"] for i in found))
    elif any(i["state"] == "none" for i in items):
        summary = t(lang, "summary.unchecked")
    else:
        summary = t(lang, "summary.ok")
    return {"schema": SCHEMA, "addon": ADDON, "label": LABEL, "version": ver, "checked_at": doc.get("generated"),
            "state": state, "summary": summary, "items": items}


def none_document(lang, ver, why, checked_at=None):
    at = checked_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    item = {"id": "scan", "state": "none", "title": t(lang, why + ".title"), "detail": t(lang, why + ".detail"),
            "checked_at": at, "stale_after": STALE_AFTER}
    return {"schema": SCHEMA, "addon": ADDON, "label": LABEL, "version": ver, "checked_at": at,
            "state": "none", "summary": t(lang, "summary." + why), "items": [item]}


def status_file(doc, ver):
    """What status.json holds: the English document, the German texts under
    "i18n". `doc` is the view (marks applied)."""
    en = document(doc, "en", ver)
    de = document(doc, "de", ver)
    en["i18n"] = {"de": {"summary": de["summary"],
                         "items": {i["id"]: {k: i[k] for k in ("title", "detail") if k in i} for i in de["items"]},
                         "scan_old": t("de", "scan.old")},
                  "en": {"scan_old": t("en", "scan.old")}}
    return en


def localize(status, lang, now=None):
    """A status.json in the language asked for, without "i18n". A state
    older than an hour turns the item `scan` into a warning (spec 4.6)."""
    out = {k: v for k, v in status.items() if k != "i18n"}
    tr = (status.get("i18n") or {}).get(lang) or {}
    if lang != "en" and isinstance(tr.get("summary"), str):
        out["summary"] = tr["summary"]
    texts = tr.get("items") if isinstance(tr.get("items"), dict) and lang != "en" else {}
    items = []
    for i in status.get("items") or []:
        i = dict(i)
        for k, v in (texts.get(i.get("id")) or {}).items():
            if k in ("title", "detail") and isinstance(v, str):
                i[k] = v
        items.append(i)
    now = now or datetime.now(timezone.utc)
    try:
        at = datetime.strptime(str(status.get("checked_at")), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        old = (now - at).total_seconds() > STALE_AFTER
    except ValueError:
        old = False
    if old:
        for i in items:
            if i.get("id") == "scan":
                i["state"] = "warning"
                i["detail"] = tr.get("scan_old") if isinstance(tr.get("scan_old"), str) else T[lang]["scan.old"]
        out["state"] = overall(items)
    out["items"] = items
    return out


def problems(status):
    """What breaks the contract in a status document (empty when nothing)."""
    out = []
    for key in ("schema", "addon", "label", "version", "checked_at", "state", "summary", "items"):
        if key not in status:
            out.append("missing " + key)
    if status.get("schema") != SCHEMA:
        out.append("schema " + repr(status.get("schema")))
    if status.get("state") not in ORDER:
        out.append("state " + repr(status.get("state")))
    items = status.get("items")
    if not isinstance(items, list):
        return out + ["items is not a list"]
    ids = [i.get("id") for i in items if isinstance(i, dict)]
    if len(ids) != len(set(ids)):
        out.append("an id twice")
    for i in items:
        if not isinstance(i, dict):
            out.append("an item is not an object")
            continue
        if not ID_RE.match(str(i.get("id", ""))):
            out.append("id " + repr(i.get("id")))
        if i.get("state") not in ORDER:
            out.append("state of " + repr(i.get("id")))
        if "link" in i and not LINK_RE.match(str(i["link"])):
            out.append("link " + repr(i["link"]))
        if not isinstance(i.get("stale_after"), int) or not isinstance(i.get("checked_at"), str):
            out.append("time of " + repr(i.get("id")))
        for k in ("title", "value", "detail"):
            if k in i and not isinstance(i[k], str):
                out.append(k + " of " + repr(i.get("id")))
        if len(i.get("detail", "")) > MAX_DETAIL or len(i.get("title", "")) > 80 or len(i.get("value", "")) > 40:
            out.append("length of " + repr(i.get("id")))
    if status.get("state") in ORDER and status.get("state") != overall(items):
        out.append("state does not follow the items")
    return out
