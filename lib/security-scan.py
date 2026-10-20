#!/usr/bin/python3 -IB
# SPDX-License-Identifier: Apache-2.0
"""Security Monitor, the Cockpit add-on: every check of this host, as JSON.

  security-scan.py                  the document on stdout (diagnosis)
  security-scan.py --output FILE [--status FILE]
                                    written atomically: the state with mode
                                    0600, the status of the add-on (status
                                    contract, no addresses or user names)
                                    with mode 0644
                                    (cockpit-security-scan.service, as root)

Only reads: listings of the packet filter, the sockets and the addresses,
`sshd -T`, the journal, Docker's API with GET, cscli. No change to the
firewall, no network except the loopback (cscli). The checks are in
seccheck.py, the format in docs/INTERNALS.md. As root a lock in /run keeps
two scans apart (exit 75 while one runs). A scan that fails as a whole leaves
the previous files as they were (exit 1).
"""

import argparse
import fcntl
import json
import os
import sys
import tempfile

# -I leaves the script's directory out of sys.path; the modules come from this
# root-owned directory only, and no bytecode is written next to them.
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
import seccheck  # noqa: E402
import secstatus  # noqa: E402

LOCK = "/run/cockpit-security-monitor-scan.lock"


def write_atomic(path, doc, mode):
    d = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=d, prefix="." + os.path.basename(path) + "-", suffix=".tmp")
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w") as f:
            json.dump(doc, f, ensure_ascii=False, indent=1)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def lock():
    if os.geteuid() != 0:
        return None
    fd = os.open(LOCK, os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0), 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        print("another scan is running", file=sys.stderr)
        sys.exit(75)
    return fd


def main(argv, system=None):
    ap = argparse.ArgumentParser(description="Security Monitor: what is reachable from where on this host")
    ap.add_argument("--output", metavar="FILE", help="write the state atomically (mode 0600)")
    ap.add_argument("--status", metavar="FILE", help="with --output: write the status of the add-on (mode 0644)")
    args = ap.parse_args(argv)
    if args.status and not args.output:
        ap.error("--status needs --output")
    held = lock()
    system = system or seccheck.System()
    try:
        doc = seccheck.scan(system)
    except Exception as e:  # noqa: BLE001 - the previous state stays as it is
        print(f"scan failed: {type(e).__name__}: {e}", file=sys.stderr)
        return 1
    if args.output:
        write_atomic(args.output, doc, 0o600)
        if args.status:
            marks, _ = seccheck.read_marks(system)
            write_atomic(args.status, secstatus.status_file(seccheck.view(doc, marks), secstatus.version()), 0o644)
        bad = sorted(k for k, v in doc["sources"].items() if v["state"] not in ("ok", "missing", "skipped"))
        print(f"{len(doc['ports'])} ports, {len(doc['sources'])} sources in {doc['took_ms']} ms"
              + (f", not ok: {', '.join(bad)}" if bad else "") + f" -> {args.output}")
    else:
        json.dump(doc, sys.stdout, ensure_ascii=False, indent=1)
        sys.stdout.write("\n")
    if held is not None:
        os.close(held)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
