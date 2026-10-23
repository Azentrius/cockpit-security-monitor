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

Besides the items it sends the optional parts of the contract (`features`):
`checks`, how each area went (read fully, in part, not at all, not there),
and `findings` for the item `exposure`, one per port the internet reaches,
whose `fid` (`port.<port>-<proto>`) stays the same in every language and on
every run. When the scan first saw each of them is kept in state.json
(`first_seen`, see first_seen()).
"""

import os
import re
from datetime import datetime, timedelta, timezone

SCHEMA = 1
ADDON = "security"
LABEL = "Security Monitor"
STALE_AFTER = 3600      # seconds: the scan runs every 15 minutes; older than 1 hour is out of date
ORDER = {"none": 0, "ok": 1, "info": 2, "warning": 3, "danger": 4}
ID_RE = re.compile(r"^[a-z0-9-]{1,40}$")
LINK_RE = re.compile(r"^#/[A-Za-z0-9/_-]{0,80}$")
MAX_NAMES = 5
MAX_DETAIL = 200
MAX_TITLE = 80
# The optional parts of the contract ("Optional: checks, findings and a host's profile").
FEATURES = ("checks", "findings")
AREAS = ("exposure", "ssh", "logins", "containers", "crowdsec", "fail2ban")
CHECK_STATES = ("checked", "partial", "failed", "unconfigured", "noaccess", "unsupported", "notapplicable")
FID_RE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,63}$")
EXPOSURES = ("internet", "restricted", "internal", "local")
MAX_CHECKS = 50
MAX_FINDINGS = 100      # per answer, over all items
TIME_RE = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
PORT_FID_RE = re.compile(r"^port\.\d{1,5}-(tcp|udp|sctp)$")
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
        "exposure.limited": "only from some addresses: {list}",
        "exposure.unknown": {"one": "{n} port not assessable", "other": "{n} ports not assessable"},
        "exposure.nopublic": "no public address",
        "exposure.norules": "the packet filter could not be read",
        "exposure.noaddrs": "the addresses could not be read",
        "exposure.nosockets": "the listening sockets could not be read",
        "exposure.nodocker": "Docker could not be asked",
        "ssh.title": "SSH",
        "ssh.locked-keys": {"one": "{n} locked account can still log in with keys",
                            "other": "{n} locked accounts can still log in with keys"},
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
        "logins.failed": {"one": "{n} failed attempt from {m} sources {period}",
                          "other": "{n} failed attempts from {m} sources {period}"},
        "logins.failed1": {"one": "{n} failed attempt from 1 source {period}",
                           "other": "{n} failed attempts from 1 source {period}"},
        "logins.none": "no failed attempts {period}",
        "period.days": "in 14 days",
        "period.since": "since {date} (the journal begins there)",
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
        "fail2ban.title": "fail2ban",
        "fail2ban.not-running": "not running",
        "fail2ban.unmanaged-bans": {"one": "{n} address blocked that fail2ban does not manage",
                                    "other": "{n} addresses blocked that fail2ban does not manage"},
        "fail2ban.input-only": "{jail}: does not protect container ports ({value})",
        "fail2ban.udp-open": "{jail}: TCP only, {value} stays open",
        "fail2ban.log-missing": "{jail}: log missing",
        "fail2ban.log-idle": "{jail}: log unchanged for {days} days",
        "fail2ban.no-match": "{jail}: not one hit since {date}",
        "fail2ban.jail-not-running": "{jail}: configured, but not running",
        "fail2ban.jails": {"one": "{n} jail", "other": "{n} jails"},
        "fail2ban.bans": {"one": "{n} ban", "other": "{n} bans"},
        "fail2ban.incomplete": "not checked completely: {list}",
        "fail2ban.part.ping": "no answer to ping",
        "fail2ban.part.config": "the configuration",
        "fail2ban.part.status": "the running jails",
        "fail2ban.part.jails": {"one": "jail {names}", "other": "jails {names}"},
        "fail2ban.part.skipped": {"one": "{n} jail beyond the first 30", "other": "{n} jails beyond the first 30"},
        "fail2ban.nohistory": "history of bans not readable",
        "scan.title": "Check",
        "scan.ok": "checked every 15 minutes when set up",
        "scan.old": "the last check is older than an hour",
        "unchecked": "not checked",
        # why a check is not "checked" (its reason)
        "check.missing": "not checked yet",
        "check.unreadable": "the last result could not be read",
        "check.needsroot": "needs administrative access",
        "check.incomplete": "not read completely",
        "check.exposure.notool": "neither iptables-save nor nft is installed",
        "check.exposure.somerules": "part of the packet filter could not be read",
        "check.exposure.noprocs": "the processes behind the sockets could not be read",
        "check.exposure.nohetzner": "the Hetzner Cloud Firewall could not be read",
        "check.ssh.noserver": "no SSH server installed",
        "check.ssh.noaccounts": "the accounts could not be read",
        "check.ssh.otherkeys": "the keys of other accounts could not be read",
        "check.logins.nojournal": "journalctl is not installed",
        "check.logins.timeout": "the journal did not answer in time",
        "check.logins.error": "the journal could not be read",
        "check.logins.partial": "only part of the journal could be read",
        "check.logins.truncated": "more than 100000 entries in the journal: not all read",
        "check.containers.nodocker": "Docker is not installed",
        "check.crowdsec.missing": "CrowdSec is not installed",
        "check.crowdsec.partial": "cscli did not answer completely",
        "check.fail2ban.missing": "fail2ban is not installed",
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
        "exposure.limited": "nur von manchen Adressen: {list}",
        "exposure.unknown": {"one": "{n} Port nicht beurteilbar", "other": "{n} Ports nicht beurteilbar"},
        "exposure.nopublic": "keine öffentliche Adresse",
        "exposure.norules": "der Paketfilter ließ sich nicht lesen",
        "exposure.noaddrs": "die Adressen ließen sich nicht lesen",
        "exposure.nosockets": "die lauschenden Sockets ließen sich nicht lesen",
        "exposure.nodocker": "Docker ließ sich nicht abfragen",
        "ssh.title": "SSH",
        "ssh.locked-keys": {"one": "{n} gesperrtes Konto kann sich per Schlüssel anmelden",
                            "other": "{n} gesperrte Konten können sich per Schlüssel anmelden"},
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
        "logins.failed": {"one": "{n} Fehlversuch von {m} Quellen {period}",
                          "other": "{n} Fehlversuche von {m} Quellen {period}"},
        "logins.failed1": {"one": "{n} Fehlversuch von 1 Quelle {period}",
                           "other": "{n} Fehlversuche von 1 Quelle {period}"},
        "logins.none": "keine Fehlversuche {period}",
        "period.days": "in 14 Tagen",
        "period.since": "seit {date} (dort beginnt das Journal)",
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
        "fail2ban.title": "fail2ban",
        "fail2ban.not-running": "läuft nicht",
        "fail2ban.unmanaged-bans": {"one": "{n} Adresse gesperrt, die fail2ban nicht verwaltet",
                                    "other": "{n} Adressen gesperrt, die fail2ban nicht verwaltet"},
        "fail2ban.input-only": "{jail}: schützt keine Container-Ports ({value})",
        "fail2ban.udp-open": "{jail}: nur TCP, {value} bleibt offen",
        "fail2ban.log-missing": "{jail}: Log fehlt",
        "fail2ban.log-idle": "{jail}: Log seit {days} Tagen unverändert",
        "fail2ban.no-match": "{jail}: kein einziger Treffer seit {date}",
        "fail2ban.jail-not-running": "{jail}: eingerichtet, läuft aber nicht",
        "fail2ban.jails": {"one": "{n} Jail", "other": "{n} Jails"},
        "fail2ban.bans": {"one": "{n} Sperre", "other": "{n} Sperren"},
        "fail2ban.incomplete": "nicht vollständig geprüft: {list}",
        "fail2ban.part.ping": "keine Antwort auf ping",
        "fail2ban.part.config": "die Konfiguration",
        "fail2ban.part.status": "die laufenden Jails",
        "fail2ban.part.jails": {"one": "Jail {names}", "other": "Jails {names}"},
        "fail2ban.part.skipped": {"one": "{n} Jail über die ersten 30 hinaus",
                                  "other": "{n} Jails über die ersten 30 hinaus"},
        "fail2ban.nohistory": "Verlauf der Sperren nicht lesbar",
        "scan.title": "Prüfung",
        "scan.ok": "alle 15 Minuten, wenn eingerichtet",
        "scan.old": "die letzte Prüfung ist älter als eine Stunde",
        "unchecked": "nicht geprüft",
        "check.missing": "noch nicht geprüft",
        "check.unreadable": "das letzte Ergebnis ließ sich nicht lesen",
        "check.needsroot": "braucht administrativen Zugriff",
        "check.incomplete": "nicht vollständig gelesen",
        "check.exposure.notool": "weder iptables-save noch nft ist installiert",
        "check.exposure.somerules": "ein Teil des Paketfilters ließ sich nicht lesen",
        "check.exposure.noprocs": "die Prozesse hinter den Sockets ließen sich nicht lesen",
        "check.exposure.nohetzner": "die Hetzner Cloud Firewall ließ sich nicht lesen",
        "check.ssh.noserver": "kein SSH-Server installiert",
        "check.ssh.noaccounts": "die Konten ließen sich nicht lesen",
        "check.ssh.otherkeys": "die Schlüssel anderer Konten ließen sich nicht lesen",
        "check.logins.nojournal": "journalctl ist nicht installiert",
        "check.logins.timeout": "das Journal antwortete nicht rechtzeitig",
        "check.logins.error": "das Journal ließ sich nicht lesen",
        "check.logins.partial": "nur ein Teil des Journals ließ sich lesen",
        "check.logins.truncated": "mehr als 100000 Einträge im Journal: nicht alle gelesen",
        "check.containers.nodocker": "Docker ist nicht installiert",
        "check.crowdsec.missing": "CrowdSec ist nicht installiert",
        "check.crowdsec.partial": "cscli antwortete nicht vollständig",
        "check.fail2ban.missing": "fail2ban ist nicht installiert",
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


MONTHS_EN = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def _parse_iso(text):
    try:
        return datetime.strptime(text or "", "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def journal_short(lg, generated):
    """The day the journal begins when it covers clearly less than the 14 days
    the logins are read for (more than a day missing), else None."""
    start, now = _parse_iso(lg.get("journal_start")), _parse_iso(generated)
    if not start or not now or start - (now - timedelta(days=14)) <= timedelta(days=1):
        return None
    return start


def period(lang, lg, generated):
    start = journal_short(lg, generated)
    if not start:
        return t(lang, "period.days")
    day = f"{start.day} {MONTHS_EN[start.month - 1]}" if lang == "en" else f"{start.day}.{start.month}."
    return t(lang, "period.since", date=day)


def _port_label(p):
    what = (p.get("service") or {}).get("containers") or (p.get("service") or {}).get("processes") or []
    name = p.get("name") or (what[0] if what else "")
    return f"{p['port']}/{p['proto']}" + (f" {name}" if name else "")


def _f2b_unread(fb, lang):
    """What fail2ban could not answer (its `incomplete`), as texts: no addresses, no paths."""
    unread = []
    for k in fb.get("incomplete") or []:
        if k == "jails":
            bad = [str(j.get("name")) for j in fb.get("jails") or [] if j.get("error")]
            unread.append(t(lang, "fail2ban.part.jails", n=len(bad), names=_names(bad, 3)))
        elif k == "skipped":
            unread.append(t(lang, "fail2ban.part.skipped", n=sum(1 for j in fb.get("jails") or [] if j.get("skipped"))))
        elif "fail2ban.part." + str(k) in T[lang]:
            unread.append(t(lang, "fail2ban.part." + k))
    return unread


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
        def reached(p, result):
            return any(p["reach"][f]["internet"]["result"] == result for f in ("4", "6"))

        # Without the addresses (which classes a socket receives from), the sockets (which ports
        # there are) or Docker's answer (which ports it publishes, also without a socket) the
        # exposure is not assessable: never OK, and no "nothing reachable".
        missing = []
        if (src.get("ip") or {}).get("state") != "ok":
            missing.append(t(lang, "exposure.noaddrs"))
        if (src.get("ss") or {}).get("state") not in ("ok", "partial"):
            missing.append(t(lang, "exposure.nosockets"))
        if (src.get("docker") or {}).get("state") in ("error", "needs-root"):
            missing.append(t(lang, "exposure.nodocker"))
        # The figure counts what the whole internet reaches; ports only some addresses reach
        # (a country list, an allowed network) are named apart, so that they do not look as open.
        public = [p for p in ports if reached(p, "open")]
        limited = [p for p in ports if not reached(p, "open") and reached(p, "restricted")]
        unknown = [p for p in ports if p["state"] == "none"]
        state = worst([p["state"] for p in ports if p["state"] != "none"], "ok")
        if missing:
            # What was found still counts; nothing found is "not checked", not OK.
            state = state if ORDER[state] >= ORDER["info"] else "none"
        elif unknown and ORDER[state] < ORDER["info"]:
            state = "info"
        public.sort(key=lambda p: (-ORDER.get(p["state"], 0), p["port"]))
        limited.sort(key=lambda p: (-ORDER.get(p["state"], 0), p["port"]))
        parts = list(missing)
        if public:
            parts.append(t(lang, "exposure.public", list=_names([_port_label(p) for p in public])))
        if limited:
            parts.append(t(lang, "exposure.limited", list=_names([_port_label(p) for p in limited], 3)))
        if not public and not limited and not missing:
            if not any((doc.get("network") or {}).get("public", {}).values()):
                parts.append(t(lang, "exposure.nopublic"))
            else:
                parts.append(t(lang, "exposure.none"))
        if unknown:
            parts.append(t(lang, "exposure.unknown", n=len(unknown)))
        out.append(item("exposure", state, len(public) if public or not missing else None, "; ".join(parts)))

    # ssh
    ssh = doc.get("ssh") or {}
    sshd = ssh.get("sshd") or {}
    if sshd.get("state") in ("ok",) or ssh.get("keys") is not None:
        parts = []
        codes = {f["code"]: f["state"] for f in ssh.get("findings") or []}
        for code in ("password-on", "kbd-pam", "empty-passwords", "root-yes", "root-key"):
            if code in codes:
                parts.append(t(lang, "ssh." + code))
        locked = sum(1 for f in ssh.get("keys") or [] if (f.get("account") or {}).get("finding") == "locked-with-keys")
        if locked:
            parts.append(t(lang, "ssh.locked-keys", n=locked))
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
            sum(1 for f in ssh.get("keys") or [] if f["problems"]) + locked
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
            when = period(lang, lg, at)
            detail = t(lang, "logins.none", period=when) if not n else \
                t(lang, "logins.failed1" if m == 1 else "logins.failed", n=n, m=m, period=when)
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

    # fail2ban (only when installed): what could not be read, the warnings, then jails and bans;
    # no addresses, no paths, no error messages
    fb = doc.get("fail2ban") or {}
    if fb.get("installed"):
        unread = _f2b_unread(fb, lang)
        parts = []
        for jail, f in [(None, f) for f in fb.get("findings") or []] + [
                (j.get("name"), f) for j in fb.get("jails") or [] for f in j.get("findings") or []]:
            if ORDER.get(f.get("state"), 0) < ORDER["warning"] or "fail2ban." + str(f.get("code")) not in T[lang]:
                continue
            when = _parse_iso(f.get("value")) if f.get("code") == "no-match" else None
            date = (f"{when.day} {MONTHS_EN[when.month - 1]}" if lang == "en" else f"{when.day}.{when.month}.") \
                if when else ""
            parts.append(t(lang, "fail2ban." + f["code"], jail=jail or "", value=f.get("value", ""),
                           n=f.get("value") if isinstance(f.get("value"), int) else 0, days=f.get("days", ""),
                           date=date))
        # The warnings first; the number of bans is the value anyway (left out when not known).
        bans = fb.get("bans_total", 0)
        parts = list(dict.fromkeys(parts)) or [t(lang, "fail2ban.jails", n=len(fb.get("jails") or [])) + (
            ", " + t(lang, "fail2ban.bans", n=bans) if bans is not None else "")]
        if unread:
            parts.insert(0, t(lang, "fail2ban.incomplete", list=", ".join(unread)))
        # The database is optional: without it only the history is missing, the state stands.
        if (fb.get("errors") or {}).get("db"):
            parts.append(t(lang, "fail2ban.nohistory"))
        out.append(item("fail2ban", fb.get("state") or "ok", bans, "; ".join(parts)))

    out.append(item("scan", "ok", detail=t(lang, "scan.ok"), link=False))
    return out


# ---------------------------------------------------------------------------
# Checks: how each area went, from the scan's sources. "checked" only when
# everything it rests on was read; what could not be read makes it "partial"
# (or "failed" when nothing of it could), never "checked" (spec 4.4).

def _base(p):
    """A port's state before the marks (view() keeps it in base_state)."""
    return p.get("base_state", p.get("state"))


def _reached(p, result):
    return any((((p.get("reach") or {}).get(f) or {}).get("internet") or {}).get("result") == result
               for f in ("4", "6"))


def check_exposure(doc, lang):
    """(state, reasons) of the check `exposure`: the packet filter, the
    addresses, the sockets and their processes, Docker's answer (its socket
    there), the Hetzner Cloud Firewall (a token set), and every port assessed.
    The marks change nothing here: a marked port that could not be assessed is
    still not assessed."""
    src = doc.get("sources") or {}
    rules = src.get("rules") or {}
    if rules.get("state") == "missing":
        return "unsupported", [t(lang, "check.exposure.notool")]
    why = []
    if rules.get("state") != "ok":
        why.append(t(lang, "exposure.norules"))
    elif set(str(rules.get("partial") or "").split(",")) - {"", "missing"}:
        # one of iptables-save, ip6tables-save, nft failed (a tool not installed is no gap)
        why.append(t(lang, "check.exposure.somerules"))
    if (src.get("ip") or {}).get("state") != "ok":
        why.append(t(lang, "exposure.noaddrs"))
    ss = src.get("ss") or {}
    if ss.get("state") not in ("ok", "partial"):
        why.append(t(lang, "exposure.nosockets"))
    elif ss.get("state") == "partial" or ss.get("partial"):
        why.append(t(lang, "check.exposure.noprocs"))
    if (src.get("docker") or {}).get("state") in ("error", "needs-root", "timeout"):
        why.append(t(lang, "exposure.nodocker"))
    if (src.get("hetzner") or {}).get("state") in ("error", "partial", "timeout", "needs-root"):
        why.append(t(lang, "check.exposure.nohetzner"))
    unknown = sum(1 for p in doc.get("ports") or [] if _base(p) == "none")
    if unknown:
        why.append(t(lang, "exposure.unknown", n=unknown))
    return ("partial" if why else "checked"), why


def check_ssh(doc, lang):
    src = doc.get("sources") or {}
    sshd = (src.get("sshd") or {}).get("state")
    keys = (src.get("keys") or {}).get("state")
    if sshd == "missing":
        return "notapplicable", [t(lang, "check.ssh.noserver")]
    if sshd == "needs-root":
        return "noaccess", [t(lang, "check.needsroot")]
    why = []
    if sshd != "ok":
        reason = ((doc.get("ssh") or {}).get("sshd") or {}).get("reason")
        why.append(t(lang, "ssh.privsep" if reason == "privsep-dir-missing" else "ssh.unchecked"))
        if keys not in ("ok", "partial"):
            return "failed", why + [t(lang, "check.ssh.noaccounts")]
    if keys not in ("ok", "partial"):
        why.append(t(lang, "check.ssh.noaccounts"))
    elif keys == "partial":
        why.append(t(lang, "check.ssh.otherkeys"))
    return ("partial" if why else "checked"), why


def check_logins(doc, lang):
    journal = ((doc.get("sources") or {}).get("journal") or {}).get("state")
    lg = doc.get("logins") or {}
    if journal == "missing":
        return "unsupported", [t(lang, "check.logins.nojournal")]
    if journal == "needs-root":
        return "noaccess", [t(lang, "check.needsroot")]
    if journal == "timeout":
        return "failed", [t(lang, "check.logins.timeout")]
    if journal not in ("ok", "partial") or lg.get("state") != "ok":
        return "failed", [t(lang, "check.logins.error")]
    why = []
    if journal == "partial":
        why.append(t(lang, "check.logins.partial"))
    if lg.get("truncated"):
        why.append(t(lang, "check.logins.truncated"))
    return ("partial" if why else "checked"), why


def check_containers(doc, lang):
    docker = ((doc.get("sources") or {}).get("docker") or {}).get("state")
    if docker == "missing":
        return "notapplicable", [t(lang, "check.containers.nodocker")]
    if docker == "needs-root":
        return "noaccess", [t(lang, "check.needsroot")]
    if docker != "ok" or (doc.get("containers") or {}).get("state") != "ok":
        return "failed", [t(lang, "exposure.nodocker")]
    return "checked", []


def check_crowdsec(doc, lang):
    if not (doc.get("crowdsec") or {}).get("installed"):
        return "notapplicable", [t(lang, "check.crowdsec.missing")]
    state = ((doc.get("sources") or {}).get("crowdsec") or {}).get("state")
    if state == "needs-root":
        return "noaccess", [t(lang, "check.needsroot")]
    if state != "ok":
        return "partial", [t(lang, "check.crowdsec.partial")]
    return "checked", []


def check_fail2ban(doc, lang):
    fb = doc.get("fail2ban") or {}
    if not fb.get("installed"):
        return "notapplicable", [t(lang, "check.fail2ban.missing")]
    state = ((doc.get("sources") or {}).get("fail2ban") or {}).get("state")
    if state == "needs-root":
        return "noaccess", [t(lang, "check.needsroot")]
    why = []
    unread = _f2b_unread(fb, lang)
    if unread:
        why.append(t(lang, "fail2ban.incomplete", list=", ".join(unread)))
    if (fb.get("errors") or {}).get("db"):
        why.append(t(lang, "fail2ban.nohistory"))
    if not why and state != "ok":
        why.append(t(lang, "check.incomplete"))
    return ("partial" if why else "checked"), why


CHECKS = {"exposure": check_exposure, "ssh": check_ssh, "logins": check_logins, "containers": check_containers,
          "crowdsec": check_crowdsec, "fail2ban": check_fail2ban}


def checks_of(doc, lang, items):
    """One check per area, in the order of AREAS: id and title as the item's,
    `item` when the answer has that item, the time of the scan, and why it is
    not "checked" (`reason`, cut to 200 characters)."""
    at = doc.get("generated")
    ids = {i["id"] for i in items}
    out = []
    for area in AREAS:
        state, why = CHECKS[area](doc, lang)
        c = {"id": area, "state": state, "title": t(lang, area + ".title")}
        if area in ids:
            c["item"] = area
        if why and state != "checked":
            c["reason"] = _clip("; ".join(why))
        c["checked_at"] = at
        c["stale_after"] = STALE_AFTER
        out.append(c)
    return out


# ---------------------------------------------------------------------------
# Findings of the item `exposure`: one per port the internet reaches.

def port_fid(p):
    """The finding's id: the rule and the port, never a text, a count, the
    families or the addresses, so it is the same in every language and order."""
    return f"port.{int(p['port'])}-{p['proto']}"


def _title(text):
    return text if len(text) <= MAX_TITLE else text[:MAX_TITLE - 2].rstrip() + " …"


def findings_of(doc, complete):
    """{complete, total, list} for the item `exposure`: every port at `info`
    or above (the whole internet reaches it, or only some addresses), not
    marked as expected; a port that could not be assessed is no finding (it
    makes the check partial). The most severe first, at most MAX_FINDINGS;
    `complete` only when the check is "checked" and every finding is listed."""
    seen = doc.get("first_seen") if isinstance(doc.get("first_seen"), dict) else {}
    found = [p for p in doc.get("ports") or [] if ORDER.get(p.get("state"), 0) >= ORDER["info"] and "expected" not in p]
    found.sort(key=lambda p: (-ORDER[p["state"]], p["port"], p["proto"]))
    out = []
    for p in found[:MAX_FINDINGS]:
        fid = port_fid(p)
        f = {"fid": fid, "state": p["state"], "title": _title(_port_label(p))}
        since = seen.get(fid)
        if isinstance(since, str) and TIME_RE.match(since):
            f["since"] = since
        f["exposure"] = "internet" if _reached(p, "open") else "restricted"
        f["link"] = f"#/exposure/{int(p['port'])}-{p['proto']}"
        out.append(f)
    return {"complete": bool(complete) and len(found) <= MAX_FINDINGS, "total": len(found), "list": out}


def first_seen(doc, previous=None):
    """When the scan first saw each port at `info` or above (before the marks,
    so a mark taken back keeps its time): {fid: time}, for state.json. A port
    still there keeps its time from `previous` (the map of the last state),
    a new one gets the time of this scan. One that is gone is dropped, but
    only when the check `exposure` is "checked": after a scan that could not
    read everything, a port missing from it is not known to be gone, and its
    time stays."""
    at = doc.get("generated")
    prev = {}
    for k, v in (previous.items() if isinstance(previous, dict) else ()):
        if isinstance(k, str) and PORT_FID_RE.match(k) and isinstance(v, str) and TIME_RE.match(v) \
                and (not at or v <= at):
            prev[k] = v
    now = {port_fid(p) for p in doc.get("ports") or [] if ORDER.get(_base(p), 0) >= ORDER["info"]}
    out = {fid: prev.get(fid, at) for fid in now}
    if check_exposure(doc, "en")[0] != "checked":
        for fid, v in prev.items():
            out.setdefault(fid, v)
    return dict(sorted(out.items()))


def document(doc, lang, ver):
    items = items_of(doc, lang)
    checks = checks_of(doc, lang, items)
    exposure = next(c for c in checks if c["id"] == "exposure")
    for i in items:
        if i["id"] == "exposure":
            i["findings"] = findings_of(doc, exposure["state"] == "checked")
    state = overall(items)
    found = [i for i in items if ORDER[i["state"]] >= ORDER["info"]]
    if found:
        summary = t(lang, "summary.found", n=len(found), list=", ".join(i["title"] for i in found))
    elif any(i["state"] == "none" for i in items):
        summary = t(lang, "summary.unchecked")
    else:
        summary = t(lang, "summary.ok")
    return {"schema": SCHEMA, "addon": ADDON, "label": LABEL, "version": ver, "checked_at": doc.get("generated"),
            "state": state, "summary": summary, "features": list(FEATURES), "checks": checks, "items": items}


def none_document(lang, ver, why, checked_at=None):
    """Nothing to show: never checked (`missing`: every check "unconfigured")
    or status.json broken (`unreadable`: every check "failed")."""
    at = checked_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    item = {"id": "scan", "state": "none", "title": t(lang, why + ".title"), "detail": t(lang, why + ".detail"),
            "checked_at": at, "stale_after": STALE_AFTER}
    state = "unconfigured" if why == "missing" else "failed"
    checks = [{"id": a, "state": state, "title": t(lang, a + ".title"), "reason": t(lang, "check." + why)}
              for a in AREAS]
    return {"schema": SCHEMA, "addon": ADDON, "label": LABEL, "version": ver, "checked_at": at,
            "state": "none", "summary": t(lang, "summary." + why), "features": list(FEATURES), "checks": checks,
            "items": [item]}


def status_file(doc, ver):
    """What status.json holds: the English document, the German texts under
    "i18n" (summary, the titles and details of the items, the titles and
    reasons of the checks; the titles of the findings are the same in both).
    `doc` is the view (marks applied)."""
    en = document(doc, "en", ver)
    de = document(doc, "de", ver)
    en["i18n"] = {"de": {"summary": de["summary"],
                         "items": {i["id"]: {k: i[k] for k in ("title", "detail") if k in i} for i in de["items"]},
                         "checks": {c["id"]: {k: c[k] for k in ("title", "reason") if k in c} for c in de["checks"]},
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
    if isinstance(status.get("checks"), list):
        texts = tr.get("checks") if isinstance(tr.get("checks"), dict) and lang != "en" else {}
        checks = []
        for c in status["checks"]:
            c = dict(c)
            for k, v in (texts.get(c.get("id")) or {}).items():
                if k in ("title", "reason") and isinstance(v, str):
                    c[k] = v
            checks.append(c)
        out["checks"] = checks
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
    return out + _problems_optional(status, [i for i in items if isinstance(i, dict)])


def _text(v, n):
    return isinstance(v, str) and 0 < len(v) <= n


def _problems_optional(status, items):
    """What breaks the optional parts (features, checks, findings)."""
    out = []
    feats = status.get("features")
    if feats is not None and (not isinstance(feats, list) or not all(isinstance(f, str) for f in feats)):
        out.append("features")
    ids = {i.get("id") for i in items if isinstance(i.get("id"), str)}
    checks = status.get("checks")
    if checks is not None:
        if not isinstance(checks, list) or len(checks) > MAX_CHECKS or not all(isinstance(c, dict) for c in checks):
            return out + ["checks"]
        cids = [c.get("id") for c in checks]
        if len(cids) != len(set(map(str, cids))):
            out.append("a check twice")
        for c in checks:
            if not ID_RE.match(str(c.get("id", ""))) or c.get("state") not in CHECK_STATES or \
                    not _text(c.get("title"), MAX_TITLE):
                out.append("check " + repr(c.get("id")))
            stale = c.get("stale_after", 1)
            if ("reason" in c and not _text(c["reason"], MAX_DETAIL)) or ("item" in c and str(c["item"]) not in ids) or \
                    ("link" in c and not LINK_RE.match(str(c["link"]))) or \
                    ("checked_at" in c and not isinstance(c["checked_at"], str)) or \
                    not isinstance(stale, int) or isinstance(stale, bool):
                out.append("fields of check " + repr(c.get("id")))
    fids = []
    for i in items:
        if "findings" not in i:
            continue
        f = i["findings"]
        lst = f.get("list") if isinstance(f, dict) else None
        total = f.get("total") if isinstance(f, dict) else None
        if not isinstance(f, dict) or not isinstance(f.get("complete"), bool) or not isinstance(lst, list) or \
                not isinstance(total, int) or isinstance(total, bool) or total < len(lst):
            out.append("findings of " + repr(i.get("id")))
            continue
        for x in lst:
            if not isinstance(x, dict) or not FID_RE.match(str(x.get("fid", ""))) or x.get("state") not in ORDER or \
                    not _text(x.get("title"), MAX_TITLE) or \
                    ("since" in x and not (isinstance(x["since"], str) and TIME_RE.match(x["since"]))) or \
                    ("exposure" in x and x["exposure"] not in EXPOSURES) or \
                    ("link" in x and not LINK_RE.match(str(x["link"]))):
                out.append("a finding of " + repr(i.get("id")))
                continue
            fids.append(x["fid"])
    if len(fids) != len(set(fids)):
        out.append("a fid twice")
    if len(fids) > MAX_FINDINGS:
        out.append("more than %d findings" % MAX_FINDINGS)
    return out
