#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The verbs of security.py the page calls: every argument checked, "expect"
and "unexpect" writing only the marks file (with a copy of the previous
version) and the status again, refusing a marks file others could change,
and root required for everything but "status". The files live in a
temporary folder; root is pretended where the verb asks for it. Offline."""

import io
import json
import os
import stat
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.join(HERE, "..", "lib")
sys.dont_write_bytecode = True
sys.path.insert(0, HERE)
sys.path.insert(0, LIB)
sys.path.insert(0, os.path.join(HERE, "fixtures"))
import importlib.util  # noqa: E402

import make_states  # noqa: E402
import seccheck  # noqa: E402
import seclib  # noqa: E402

spec = importlib.util.spec_from_file_location("security", os.path.join(LIB, "security.py"))
security = importlib.util.module_from_spec(spec)
spec.loader.exec_module(security)


class Root:
    """Pretends root for need_root(); the files are in a temporary folder anyway. Pretending
    root, the files this test writes count as root's: without real root they belong to the user
    running the test. Write permission for group or others still makes a file untrusted."""

    def __init__(self, uid=0):
        self.uid = uid

    def __enter__(self):
        self.real = os.geteuid
        self.trusted = seclib.trusted_file
        real_uid, trusted = self.real(), self.trusted
        os.geteuid = lambda: self.uid
        if self.uid == 0:
            seclib.trusted_file = lambda st: st is not None and trusted(
                os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink,
                                0 if st.st_uid == real_uid else st.st_uid) + tuple(st)[5:]))
        return self

    def __exit__(self, *a):
        os.geteuid = self.real
        seclib.trusted_file = self.trusted


class Arguments(unittest.TestCase):
    def test_good(self):
        p = security.parse_mark_args
        self.assertEqual(p("expect", ["port", "8080/tcp", "--note", " Rustdesk relay "]), ("port", "8080/tcp",
                                                                                            "Rustdesk relay"))
        self.assertEqual(p("expect", ["port", "51820/udp"]), ("port", "51820/udp", ""))
        self.assertEqual(p("expect", ["container", "forgejo-runner", "docker-socket", "--note", "CI"]),
                         ("container", ("forgejo-runner", "docker-socket"), "CI"))
        self.assertEqual(p("unexpect", ["container", "a.b_c", "privileged"]), ("container", ("a.b_c", "privileged"),
                                                                              ""))

    def test_bad(self):
        p = security.parse_mark_args
        for verb, rest in (("expect", ["port", "8080"]), ("expect", ["port", "0/tcp"]),
                           ("expect", ["port", "65536/tcp"]), ("expect", ["port", "80/icmp"]),
                           ("expect", ["port", "80/tcp", "extra"]), ("expect", ["port", "80/tcp", "--note"]),
                           ("expect", ["port", "80/tcp", "--note", "a", "b"]),
                           ("expect", ["port", "80/tcp", "--note", "line\nbreak"]),
                           ("expect", ["port", "80/tcp", "--note", "x" * 201]),
                           ("unexpect", ["port", "80/tcp", "--note", "x"]),
                           ("expect", ["container", "-rf", "privileged"]), ("expect", ["container", "a/b", "privileged"]),
                           ("expect", ["container", "a", "everything"]), ("expect", ["file", "/etc/passwd"]),
                           ("expect", [])):
            with self.assertRaises(security.Fail, msg=(verb, rest)) as ctx:
                p(verb, rest)
            self.assertEqual(ctx.exception.code, 64)


class Marks(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.marks = os.path.join(self.dir, "etc", "exposure.conf")
        self.state = os.path.join(self.dir, "state.json")
        self.status = os.path.join(self.dir, "status.json")
        self.lock = os.path.join(self.dir, "marks.lock")
        doc, _ = make_states.state("ufw-docker")
        with open(self.state, "w", encoding="utf-8") as f:
            json.dump(doc, f)
        self.system = seccheck.System()

    def mark(self, verb, rest):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            try:
                rc = security.do_mark(verb, rest, self.system, self.marks, self.state, self.status, self.lock)
            except security.Fail as f:
                print(f.en, file=sys.stderr)
                rc = f.code
        return rc, out.getvalue(), err.getvalue()

    def read(self):
        with open(self.marks, encoding="utf-8") as f:
            return seclib.parse_marks(f.read())

    def test_expect_and_unexpect(self):
        with Root():
            rc, out, _ = self.mark("expect", ["port", "8080/tcp", "--note", "test page"])
            self.assertEqual((rc, out.strip()), (0, "Marked as expected: 8080/tcp."))
            self.assertEqual(self.read(), ({"ports": {"8080/tcp": "test page"}, "containers": {}}, []))
            self.assertEqual(stat.S_IMODE(os.stat(self.marks).st_mode), 0o644)
            self.assertFalse(os.path.exists(self.marks + ".bak"), "nothing to keep the first time")
            with open(self.status, encoding="utf-8") as f:
                st = json.load(f)
            self.assertEqual(st["items"][0]["state"], "info", "the status follows the mark at once")
            self.assertEqual(stat.S_IMODE(os.stat(self.status).st_mode), 0o644)

            rc, _, _ = self.mark("expect", ["container", "runner", "docker-socket", "--note", "CI needs it"])
            self.assertEqual(rc, 0)
            with open(self.marks + ".bak", encoding="utf-8") as f:
                self.assertEqual(seclib.parse_marks(f.read())[0]["ports"], {"8080/tcp": "test page"})
            self.assertEqual(self.read()[0]["containers"], {("runner", "docker-socket"): "CI needs it"})

            rc, out, _ = self.mark("unexpect", ["port", "8080/tcp"])
            self.assertEqual((rc, out.strip()), (0, "Mark removed: 8080/tcp."))
            self.assertEqual(self.read()[0]["ports"], {})
            rc, out, _ = self.mark("unexpect", ["port", "8080/tcp"])
            self.assertEqual((rc, out.strip()), (0, "Not marked; nothing changed."))

    def test_lines_by_hand_survive(self):
        os.makedirs(os.path.dirname(self.marks))
        with open(self.marks, "w") as f:
            f.write("port 22/tcp public on purpose\n")
        os.chmod(self.marks, 0o644)
        with Root():
            self.assertEqual(self.mark("expect", ["port", "443/udp"])[0], 0)
        self.assertEqual(self.read()[0]["ports"], {"22/tcp": "public on purpose", "443/udp": ""})

    def test_refuses_a_file_others_can_change(self):
        os.makedirs(os.path.dirname(self.marks))
        with open(self.marks, "w") as f:
            f.write("port 22/tcp x\n")
        os.chmod(self.marks, 0o666)
        with Root():
            rc, _, err = self.mark("expect", ["port", "443/udp"])
        if os.geteuid() == 0 or os.stat(self.marks).st_uid == 0:
            self.assertEqual(rc, 5, err)
        else:
            self.assertEqual(rc, 5, "owned by someone other than root, and writable by others")
        with open(self.marks) as f:
            self.assertEqual(f.read(), "port 22/tcp x\n")

    def test_needs_root(self):
        with Root(1000):
            rc, _, err = self.mark("expect", ["port", "8080/tcp"])
        self.assertEqual(rc, 77)
        self.assertFalse(os.path.exists(self.marks))

    def test_messages_in_german(self):
        os.environ["SECURITY_LANG"] = "de"
        try:
            with Root():
                rc, out, _ = self.mark("expect", ["port", "8080/tcp"])
        finally:
            del os.environ["SECURITY_LANG"]
        self.assertEqual(out.strip(), "Als erwartet markiert: 8080/tcp.")


class Root_(unittest.TestCase):
    def test_verbs_need_root(self):
        for argv in (["show"], ["scan"], ["install", "timer"], ["remove", "timer"]):
            out, err = io.StringIO(), io.StringIO()
            with Root(1000), redirect_stdout(out), redirect_stderr(err):
                rc = security.main(argv)
            self.assertEqual(rc, 77, argv)

    def test_wrong_calls(self):
        for argv in ([], ["show", "all"], ["scan", "now"], ["install", "radar"], ["remove"], ["rm", "-rf"],
                     ["status", "--lang", ";id"]):
            out, err = io.StringIO(), io.StringIO()
            with Root(), redirect_stdout(out), redirect_stderr(err):
                rc = security.main(argv)
            self.assertEqual(rc, 64, argv)


if __name__ == "__main__":
    unittest.main(verbosity=1)
