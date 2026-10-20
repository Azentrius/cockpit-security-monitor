# SPDX-License-Identifier: Apache-2.0
"""Commands with a time limit, for the helpers of Security Monitor.

Lives in /usr/lib/cockpit-security-monitor next to the scripts that import it
(root-owned). Standard library only, no side effects on import.

Every command runs in a process group of its own, with a fixed PATH that
leaves /usr/local out (a program there must never stand in for ss, nft or
sshd), LC_ALL=C (the parsers read English, untranslated output) and TZ=UTC.
The limit is a deadline for the whole command; when it passes, the group gets
SIGTERM, a moment later SIGKILL, and the process is always waited for. The
text handed to the parsers is cut at MAX_OUTPUT bytes per stream.
"""

import os
import signal
import subprocess
import time

PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
GRACE = 3              # seconds between SIGTERM and SIGKILL
MAX_OUTPUT = 32 << 20  # bytes kept of stdout and of stderr each


class Result:
    """What a command did: exit code (None when it could not start or was
    stopped), its output as text, and whether it ran out of time."""

    def __init__(self, rc, out="", err="", timeout=False, missing=False, cut=False):
        self.rc, self.out, self.err = rc, out, err
        self.timeout, self.missing, self.cut = timeout, missing, cut

    @property
    def ok(self):
        return self.rc == 0 and not self.timeout

    def __repr__(self):
        return f"Result(rc={self.rc!r}, timeout={self.timeout}, missing={self.missing})"


def env():
    return {"PATH": PATH, "LC_ALL": "C", "LANG": "C", "LANGUAGE": "C", "TZ": "UTC", "HOME": "/root",
            "SYSTEMD_PAGER": "", "SYSTEMD_COLORS": "0", "NO_COLOR": "1"}


def _stop(proc):
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        proc.wait(timeout=GRACE)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait()


def run(argv, limit=60):
    """Run argv (a list, never a shell string) with a deadline of `limit`
    seconds. Returns a Result; never raises for a command that is missing,
    fails or hangs."""
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=env(), start_new_session=True, close_fds=True)
    except FileNotFoundError:
        return Result(None, missing=True)
    except (OSError, subprocess.SubprocessError) as e:
        return Result(None, err=str(e))
    deadline = time.monotonic() + limit
    try:
        out, err = proc.communicate(timeout=limit)
    except subprocess.TimeoutExpired:
        _stop(proc)
        try:
            out, err = proc.communicate(timeout=GRACE)
        except (subprocess.TimeoutExpired, ValueError):
            out, err = b"", b""
        return Result(None, _text(out), _text(err), timeout=True)
    except BaseException:
        _stop(proc)
        raise
    if time.monotonic() > deadline:
        return Result(proc.returncode, _text(out), _text(err), timeout=True)
    return Result(proc.returncode, _text(out), _text(err), cut=len(out or b"") > MAX_OUTPUT)


def _text(data):
    if not data:
        return ""
    return data[:MAX_OUTPUT].decode("utf-8", "replace")
