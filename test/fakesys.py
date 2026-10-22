# SPDX-License-Identifier: Apache-2.0
"""A stand-in for seccheck.System that answers from a scenario in
test/fixtures/<scenario>/:

  commands/<key>.txt|.json|.jsonl   the output of a command (keys below); a command without a
                                    file is missing (journal-start: an older systemd)
  files/<absolute path>             files, also what exists and what a directory lists
  docker/*.json                     Docker's API (info, version, containers, networks, inspect-<id>)
  meta.json                         now, uid, exit codes and stderr of commands, stat data,
                                    paths that exist without a file (sockets)

Nothing touches the machine the tests run on. Unknown commands fail the test.
Variants of the scenarios (a failing command, another answer of the Hetzner
service, fail2ban cut down to one jail) are at the end, as keyword arguments."""

import json
import os
import stat
import sys
from datetime import datetime, timezone
from types import SimpleNamespace

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "lib"))
import secproc  # noqa: E402

FIXTURES = os.path.join(HERE, "fixtures")


def key(argv):
    a = list(argv)
    if a == ["ip", "-j", "addr"]:
        return "ip-addr"
    if a == ["ss", "-H", "-tulpn"]:
        return "ss"
    if a in (["iptables-save"], ["ip6tables-save"], ["iptables-legacy-save"], ["ip6tables-legacy-save"]):
        return a[0]
    if a == ["nft", "-j", "list", "ruleset"]:
        return "nft"
    if a == ["/usr/sbin/sshd", "-T"]:
        return "sshd-T"
    if a[:1] == ["journalctl"] and "--lines=+1" in a:
        return "journal-start"
    if a[:1] == ["journalctl"]:
        return "journal"
    if a == ["systemctl", "is-active", "crowdsec.service"]:
        return "systemctl-is-active-crowdsec"
    if a[:2] == ["cscli", "version"]:
        return "cscli-version"
    if a[:3] == ["cscli", "decisions", "list"]:
        return "cscli-decisions"
    if a[:3] == ["cscli", "alerts", "list"]:
        return "cscli-alerts"
    if a[:3] == ["cscli", "bouncers", "list"]:
        return "cscli-bouncers"
    if a[:3] == ["systemctl", "show", "fail2ban.service"]:
        return "systemctl-show-fail2ban"
    if a[:1] == ["/usr/bin/fail2ban-client"]:
        rest = a[1:]
        if rest in (["--version"], ["ping"], ["-d"], ["status"]):
            return "f2b-" + {"--version": "version", "ping": "ping", "-d": "dump", "status": "status"}[rest[0]]
        if len(rest) == 2 and rest[0] == "status":
            return "f2b-status-" + rest[1]
    raise AssertionError(f"unexpected command {argv}")


class FakeSystem:
    def __init__(self, scenario, uid=None, results=None, files=None, gone=(), meta=None, docker_error=None):
        self.dir = os.path.join(FIXTURES, scenario)
        with open(os.path.join(self.dir, "meta.json"), encoding="utf-8") as f:
            self.meta = json.load(f)
        self.meta.update(meta or {})
        self._uid = self.meta.get("uid", 0) if uid is None else uid
        self.results = dict(results or {})     # key -> secproc.Result or text
        self.files = dict(files or {})         # path -> text (None: gone)
        self.gone = set(gone)
        self.docker_error = docker_error
        self.calls = []

    def run(self, argv, limit=60):
        k = key(argv)
        self.calls.append(k)
        if k in self.results:
            r = self.results[k]
            return r if isinstance(r, secproc.Result) else secproc.Result(0, r, "")
        if k in self.gone:
            return secproc.Result(None, missing=True)
        for ext in (".txt", ".json", ".jsonl"):
            p = os.path.join(self.dir, "commands", k + ext)
            if os.path.exists(p):
                with open(p, encoding="utf-8") as f:
                    text = f.read()
                rc = (self.meta.get("rc") or {}).get(k, 0)
                return secproc.Result(rc, text, (self.meta.get("stderr") or {}).get(k, ""))
        return secproc.Result(None, missing=True)

    def _path(self, path):
        return os.path.join(self.dir, "files", path.lstrip("/"))

    def read(self, path, limit=4 << 20):
        if path in self.files:
            v = self.files[path]
            return None if v is None else v[:limit]
        p = self._path(path)
        if not os.path.isfile(p):
            return None
        with open(p, encoding="utf-8") as f:
            return f.read(limit)

    def read_user_file(self, path, limit=1 << 20):
        st = self.lstat(path)
        if st is None or not stat.S_ISREG(st.st_mode):
            return None, st
        return self.read(path, limit), st

    def lstat(self, path):
        if path in self.files:
            if self.files[path] is None:
                return None
            info = (self.meta.get("stat") or {}).get(path) or {}
            return self._st(info.get("type", "file"), info)
        info = (self.meta.get("stat") or {}).get(path)
        p = self._path(path)
        if info is None:
            if os.path.isfile(p):
                return self._st("file", {})
            if os.path.isdir(p):
                return self._st("dir", {"mode": "755"})
            if path in self.meta.get("exists", []):
                return self._st("socket", {"mode": "660"})
            return None
        if not os.path.exists(p) and info.get("type", "file") == "file" and path not in self.files:
            return None
        return self._st(info.get("type", "file"), info)

    def stat(self, path):
        return self.lstat(path)

    @staticmethod
    def _st(kind, info):
        mode = {"file": stat.S_IFREG, "dir": stat.S_IFDIR, "link": stat.S_IFLNK, "socket": stat.S_IFSOCK}[kind]
        mtime = 1792400000.0
        if info.get("mtime"):
            mtime = datetime.strptime(info["mtime"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
        return SimpleNamespace(st_mode=mode | int(info.get("mode", "644"), 8), st_uid=info.get("uid", 0),
                               st_mtime=mtime, st_size=info.get("size", 0))

    def sqlite_ro(self, path, queries, limit=1000):
        """fail2ban's database as fail2ban-db.json ({query name: rows}); meta "db_error" fails it."""
        if self.meta.get("db_error"):
            return None, self.meta["db_error"]
        p = os.path.join(self.dir, "fail2ban-db.json")
        if not os.path.exists(p):
            return None, "unable to open database file"
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
        return {name: data.get(name, [])[:limit] for name, _, _ in queries}, None

    def exists(self, path):
        return self.lstat(path) is not None

    def listdir(self, path):
        p = self._path(path)
        return sorted(os.listdir(p)) if os.path.isdir(p) else None

    def docker(self, path):
        if self.docker_error:
            raise self.docker_error
        if path.startswith("/containers/") and path.endswith("/json") and path != "/containers/json":
            name = "inspect-" + path.split("/")[2][:12]
        else:
            name = {"/info": "info", "/version": "version", "/containers/json": "containers",
                    "/networks": "networks"}[path]
        with open(os.path.join(self.dir, "docker", name + ".json"), encoding="utf-8") as f:
            return json.load(f)

    def now(self):
        return datetime.strptime(self.meta["now"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)

    def uid(self):
        return self._uid


# ---------------------------------------------------------------------------
# Variants of the scenarios, as keyword arguments for FakeSystem

def failing(msg, rc=1):
    """A command that fails with `msg` on stderr."""
    return secproc.Result(rc, "", msg + "\n")


def _fixture(*parts):
    with open(os.path.join(FIXTURES, *parts), encoding="utf-8") as f:
        return f.read()


HETZNER_FILE = "/var/lib/cockpit-security-hetzner/hetzner.json"


def hetzner_firewalls(change):
    """hetzner-open with the answer of the Hetzner service changed: `change(answer)` edits the
    parsed hetzner.json in place. Keyword arguments for FakeSystem("hetzner-open", ...)."""
    answer = json.loads(_fixture("hetzner-open", "files", HETZNER_FILE.lstrip("/")))
    change(answer)
    return {"files": {HETZNER_FILE: json.dumps(answer)}}


F2B_OTHER_JAILS = ("nginx-botsearch", "recidive", "web")


def fail2ban_quiet(results=None, files=None):
    """The scenario fail2ban cut down to the jail sshd (on the journal, banning port 22, no
    finding), without the bans fail2ban does not manage and without a saved ruleset: every
    finding gone, what is left to judge is whether fail2ban could be read. `results` and `files`
    change or add to it. Keyword arguments for FakeSystem("fail2ban", ...)."""
    dump = "\n".join(line for line in _fixture("fail2ban", "commands", "f2b-dump.txt").splitlines()
                     if not any(f"'{j}'" in line for j in F2B_OTHER_JAILS)) + "\n"
    ipt = "\n".join(line for line in _fixture("fail2ban", "commands", "iptables-save.txt").splitlines()
                    if "f2b-recidive" not in line and "198.51.100.7/" not in line) + "\n"
    nft = json.loads(_fixture("fail2ban", "commands", "nft.json"))
    nft["nftables"] = [e for e in nft["nftables"] if "f2b-table" not in json.dumps(e)]
    base = {"f2b-dump": dump, "iptables-save": ipt, "nft": json.dumps(nft),
            "f2b-status": "Status\n|- Number of jail:\t1\n`- Jail list:\tsshd\n"}
    base.update(results or {})
    return {"results": base, "files": dict({"/etc/iptables/rules.v4": None}, **(files or {}))}
