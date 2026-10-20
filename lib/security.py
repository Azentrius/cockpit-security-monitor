#!/usr/bin/python3 -IB
# SPDX-License-Identifier: Apache-2.0
"""Security Monitor, the Cockpit add-on: the fixed verbs of the page and of
the Status Board.

  security.py status [--lang en|de]       the status contract (schema 1), no root
  security.py show                        the state with the marks, for the page (root)
  security.py scan                        run cockpit-security-scan.service now, wait (root)
  security.py install timer               the regular check: every 15 minutes (root)
  security.py remove timer                switch it off (root)
  security.py expect port PORT/PROTO [--note TEXT]
  security.py expect container NAME FINDING [--note TEXT]
  security.py unexpect port PORT/PROTO
  security.py unexpect container NAME FINDING

Everything else is a wrong call (exit 64). Every argument is checked here.
"expect" is the only change stage 1 makes to the system besides the timer:
it writes /etc/cockpit-security-monitor/exposure.conf (root, 0644, a copy of
the previous version as exposure.conf.bak) and never touches a firewall rule.

Exit codes: 0 ok (findings are no error), 1 failed, 2 unit missing, 5 the
marks file is not trusted (owned by someone else or writable by others), 64
wrong call, 75 busy, 77 needs root. SECURITY_LANG=de|en selects the language
of the messages.
"""

import fcntl
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
import seccheck  # noqa: E402
import seclib  # noqa: E402
import secstatus  # noqa: E402

STATE = "/var/lib/cockpit-security-monitor/state.json"
STATUS = "/var/lib/cockpit-security-monitor/status.json"
MARKS = seccheck.MARKS_FILE
MARKS_LOCK = "/run/cockpit-security-monitor-marks.lock"
SERVICE = "cockpit-security-scan.service"
TIMER = "cockpit-security-scan.timer"
LANG_RE = re.compile(r"^[A-Za-z]{2,3}([_-][A-Za-z0-9]{2,8})?$")
USAGE = ("usage: security.py status [--lang en|de] | show | scan | install timer | remove timer | "
         "expect port PORT/PROTO [--note TEXT] | expect container NAME FINDING [--note TEXT] | "
         "unexpect port PORT/PROTO | unexpect container NAME FINDING")
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "TZ": "UTC"}


class Fail(Exception):
    def __init__(self, code, de, en):
        super().__init__(en)
        self.code, self.de, self.en = code, de, en


def say(de, en, stream=None):
    print(de if os.environ.get("SECURITY_LANG") == "de" else en, file=stream or sys.stdout)


def need_root():
    if os.geteuid() != 0:
        raise Fail(77, "Dafür wird administrativer Zugriff benötigt.", "This needs administrative access.")


def systemctl(*args, check=False):
    p = subprocess.run(["systemctl", *args], capture_output=True, text=True, env=ENV)
    if check and p.returncode:
        raise Fail(1, f"systemctl {' '.join(args)} ist fehlgeschlagen: {p.stderr.strip()}",
                   f"systemctl {' '.join(args)} failed: {p.stderr.strip()}")
    return p


def unit_exists(unit):
    return systemctl("cat", unit).returncode == 0


# ---------------------------------------------------------------------------
# status (no root, no command, no lock)

def language(rest):
    if rest and len(rest) == 1 and rest[0].startswith("--lang="):
        rest = ["--lang", rest[0][len("--lang="):]]
    if not rest:
        return "en"
    if len(rest) != 2 or rest[0] != "--lang" or not LANG_RE.match(rest[1]):
        return None
    return "de" if rest[1].lower()[:2] == "de" else "en"


def do_status(rest, path=STATUS, now=None):
    lang = language(rest)
    if lang is None:
        print(USAGE, file=sys.stderr)
        return 64
    ver = secstatus.version()
    try:
        with open(path, "rb") as f:
            data = f.read(1 << 20)
    except FileNotFoundError:
        doc = secstatus.none_document(lang, ver, "missing")
    except OSError as e:
        print(f"cannot read {path}: {e.strerror}", file=sys.stderr)
        return 77
    else:
        try:
            status = json.loads(data.decode("utf-8"))
        except ValueError:
            status = None
        if not isinstance(status, dict) or secstatus.problems({k: v for k, v in status.items() if k != "i18n"}):
            doc = secstatus.none_document(lang, ver, "unreadable")
        else:
            doc = secstatus.localize(status, lang, now)
            doc["version"] = ver
    json.dump(doc, sys.stdout, ensure_ascii=False)
    sys.stdout.write("\n")
    return 0


# ---------------------------------------------------------------------------
# show (root): the state with the marks, the timer, whether a token is set

def timer_state():
    if not os.path.isdir("/run/systemd/system") or not unit_exists(TIMER):
        return "missing", None
    active = systemctl("is-active", "--quiet", TIMER).returncode == 0
    nxt = None
    if active:
        v = systemctl("show", TIMER, "-p", "NextElapseUSecRealtime", "--value").stdout.strip()
        m = re.match(r"^\w{3} (\d{4}-\d\d-\d\d) (\d\d:\d\d:\d\d) UTC$", v)
        nxt = f"{m.group(1)}T{m.group(2)}Z" if m else None
    return ("active" if active else "inactive"), nxt


def do_show(rest, system=None, state=STATE):
    if rest:
        raise Fail(64, USAGE, USAGE)
    need_root()
    system = system or seccheck.System()
    try:
        with open(state, "rb") as f:
            doc = json.loads(f.read(64 << 20).decode("utf-8"))
    except FileNotFoundError:
        doc = None
    except (OSError, ValueError) as e:
        raise Fail(1, f"Der Stand ist nicht lesbar: {e}", f"The state is not readable: {e}")
    marks, problem = seccheck.read_marks(system)
    timer, nxt = timer_state()
    running = systemctl("is-active", SERVICE).stdout.strip() == "activating"
    out = {"root": True, "state": seccheck.view(doc, marks) if isinstance(doc, dict) else None,
           "marks_problem": problem, "marks_file": MARKS, "timer": timer, "next": nxt, "running": running,
           "hetzner_token": system.lstat(seccheck.HETZNER_TOKEN) is not None}
    json.dump(out, sys.stdout, ensure_ascii=False)
    sys.stdout.write("\n")
    return 0


# ---------------------------------------------------------------------------
# scan and the timer (root)

def do_scan(rest):
    if rest:
        raise Fail(64, USAGE, USAGE)
    need_root()
    if not unit_exists(SERVICE):
        raise Fail(2, f"Der Dienst {SERVICE} fehlt (Paket cockpit-security-monitor).",
                   f"The service {SERVICE} is missing (package cockpit-security-monitor).")
    say("Prüfe diesen Server …", "Checking this server …")
    p = systemctl("start", SERVICE)
    if p.returncode:
        j = subprocess.run(["journalctl", "-u", SERVICE, "-n", "10", "--no-pager", "-o", "cat"], capture_output=True,
                           text=True, env=ENV)
        sys.stdout.write(j.stdout)
        raise Fail(1, f"Die Prüfung ist fehlgeschlagen: journalctl -u {SERVICE}",
                   f"The check failed: journalctl -u {SERVICE}")
    say("Fertig.", "Done.")
    return 0


def do_timer(verb, rest):
    if rest != ["timer"]:
        raise Fail(64, USAGE, USAGE)
    need_root()
    if not unit_exists(TIMER):
        raise Fail(2, f"Der Timer {TIMER} fehlt (Paket cockpit-security-monitor).",
                   f"The timer {TIMER} is missing (package cockpit-security-monitor).")
    if verb == "install":
        print(f"+ systemctl enable --now {TIMER}")
        systemctl("enable", "--now", TIMER, check=True)
        print(f"+ systemctl start {SERVICE}")
        systemctl("start", SERVICE, check=True)
        say("Regelmäßige Prüfung eingerichtet: alle 15 Minuten.", "Regular check set up: every 15 minutes.")
    else:
        print(f"+ systemctl disable --now {TIMER}")
        systemctl("disable", "--now", TIMER, check=True)
        say("Regelmäßige Prüfung ausgeschaltet. Der letzte Stand bleibt.",
            "Regular check switched off. The last state stays.")
    return 0


# ---------------------------------------------------------------------------
# expect / unexpect (root): the marks file

def parse_mark_args(verb, rest):
    """(kind, key, note) of a valid call, else a Fail(64)."""
    bad = Fail(64, USAGE, USAGE)
    note = ""
    if "--note" in rest:
        i = rest.index("--note")
        if verb != "expect" or i + 2 != len(rest):
            raise bad
        note = rest[i + 1].strip()
        rest = rest[:i]
        if not seclib.valid_note(note):
            raise Fail(64, f"Die Notiz ist zu lang (höchstens {seclib.NOTE_MAX} Zeichen) oder enthält Steuerzeichen.",
                       f"The note is too long (at most {seclib.NOTE_MAX} characters) or has control characters.")
    if len(rest) == 2 and rest[0] == "port" and seclib.valid_port_key(rest[1]):
        return "port", rest[1], note
    if len(rest) == 3 and rest[0] == "container" and seclib.CONTAINER_RE.match(rest[1]) and \
            rest[2] in seclib.CONTAINER_KINDS:
        return "container", (rest[1], rest[2]), note
    raise bad


def write_text_atomic(path, text, mode):
    d = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(dir=d, prefix="." + os.path.basename(path) + "-", suffix=".tmp")
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def do_mark(verb, rest, system=None, marks_file=None, state=STATE, status=STATUS, lock_file=MARKS_LOCK):
    kind, key, note = parse_mark_args(verb, rest)
    need_root()
    system = system or seccheck.System()
    marks_file = marks_file or MARKS
    os.makedirs(os.path.dirname(marks_file), mode=0o755, exist_ok=True)
    fd = os.open(lock_file, os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0), 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Fail(75, "Die Markierungen werden gerade geändert.", "The marks are being changed right now.")
        st = system.lstat(marks_file)
        if st is not None and not seclib.trusted_file(st):
            raise Fail(5, f"{marks_file} gehört nicht root oder ist für andere schreibbar; nichts geändert.",
                       f"{marks_file} is not root's or writable by others; nothing changed.")
        text = system.read(marks_file, 1 << 20) if st is not None else ""
        marks, _ = seclib.parse_marks(text or "")
        table = marks["ports" if kind == "port" else "containers"]
        if verb == "expect":
            table[key] = note
        elif key in table:
            del table[key]
        else:
            say("Nicht markiert; nichts geändert.", "Not marked; nothing changed.")
            return 0
        if st is not None:
            shutil.copyfile(marks_file, marks_file + ".bak")
            os.chmod(marks_file + ".bak", 0o644)
        write_text_atomic(marks_file, seclib.format_marks(marks), 0o644)
        refresh_status(system, state, status, marks)
    finally:
        os.close(fd)
    label = key if kind == "port" else f"{key[0]} {key[1]}"
    if verb == "expect":
        say(f"Als erwartet markiert: {label}.", f"Marked as expected: {label}.")
    else:
        say(f"Markierung entfernt: {label}.", f"Mark removed: {label}.")
    return 0


def refresh_status(system, state, status, marks):
    """status.json again from the last state with the new marks, so the Status
    Board shows the change before the next scan."""
    try:
        with open(state, "rb") as f:
            doc = json.loads(f.read(64 << 20).decode("utf-8"))
    except (OSError, ValueError):
        return
    if not isinstance(doc, dict):
        return
    text = json.dumps(secstatus.status_file(seccheck.view(doc, marks), secstatus.version()), ensure_ascii=False,
                      indent=1) + "\n"
    write_text_atomic(status, text, 0o644)


def main(argv):
    verb, rest = (argv[0], argv[1:]) if argv else ("", [])
    try:
        if verb == "status":
            return do_status(rest)
        if verb == "show":
            return do_show(rest)
        if verb == "scan":
            return do_scan(rest)
        if verb in ("install", "remove"):
            return do_timer(verb, rest)
        if verb in ("expect", "unexpect"):
            return do_mark(verb, rest)
        raise Fail(64, USAGE, USAGE)
    except Fail as f:
        say(f.de, f.en, sys.stderr)
        return f.code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
