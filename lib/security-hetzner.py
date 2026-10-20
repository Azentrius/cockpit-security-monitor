#!/usr/bin/python3 -IB
# SPDX-License-Identifier: Apache-2.0
"""Security Monitor, the Cockpit add-on: which Hetzner Cloud Firewalls are
applied to this server, from Hetzner's API with a read-only token.

  security-hetzner.py --output FILE

Runs as cockpit-security-hetzner.service: without root (DynamicUser), with
network, and the only part of the add-on that sees the token. systemd hands
it over with LoadCredential= from /etc/cockpit-security-monitor/hetzner.token
(root, 0600); the browser never sees it, and nothing here writes it anywhere.
Only GET requests: /v1/servers and /v1/firewalls. The server is the one whose
public IPv4 address, or IPv6 network, is an address of this host.

The file keeps the last good answer: when the API fails, it stays and the
error and the time of the attempt are added, so the scan can say how old it
is. Exit 0 in both cases; 64 for a wrong call.
"""

import argparse
import ipaddress
import json
import os
import ssl
import sys
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
import seclib  # noqa: E402
import secproc  # noqa: E402

API = "https://api.hetzner.cloud/v1"
FORMAT = 1
MAX_PAGES = 20
TIMEOUT = 20


class ApiError(Exception):
    pass


def http_get(path, token):
    """GET API + path with the token; the decoded JSON. Raises ApiError with
    a short reason (never the token)."""
    req = urllib.request.Request(API + path, method="GET", headers={
        "Authorization": "Bearer " + token, "Accept": "application/json",
        "User-Agent": "cockpit-security-monitor"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=ssl.create_default_context()) as r:
            return json.loads(r.read(16 << 20).decode("utf-8"))
    except urllib.error.HTTPError as e:
        code = ""
        try:
            code = (json.loads(e.read(65536).decode("utf-8")).get("error") or {}).get("code") or ""
        except (ValueError, AttributeError, OSError):
            pass
        raise ApiError(f"HTTP {e.code} {seclib.clean(code, 40)}".strip()) from None
    except urllib.error.URLError as e:
        raise ApiError("network: " + seclib.clean(str(getattr(e, "reason", e)), 120)) from None
    except (OSError, ValueError) as e:
        raise ApiError(seclib.clean(f"{type(e).__name__}: {e}", 120)) from None


def all_pages(kind, token, get):
    out = []
    page = 1
    for _ in range(MAX_PAGES):
        data = get(f"/{kind}?page={page}&per_page=50", token)
        if not isinstance(data, dict) or not isinstance(data.get(kind), list):
            raise ApiError(f"unexpected answer for /{kind}")
        out.extend(data[kind])
        nxt = ((data.get("meta") or {}).get("pagination") or {}).get("next_page")
        if not nxt:
            return out
        page = int(nxt)
    raise ApiError(f"more than {MAX_PAGES} pages of /{kind}")


def local_addresses():
    res = secproc.run(["ip", "-j", "addr"], 20)
    if not res.ok:
        raise ApiError("ip -j addr failed")
    return [a["addr"] for i in seclib.parse_ip_addr(res.out) for a in i["addrs"] if a["class"] == "internet"]


def match_server(servers, addrs):
    """The server whose public IPv4 address or IPv6 network is ours: (server, how)."""
    mine = [ipaddress.ip_address(a) for a in addrs]
    for s in servers:
        pn = s.get("public_net") or {}
        v4 = (pn.get("ipv4") or {}).get("ip")
        if v4 and any(str(a) == v4 for a in mine):
            return s, "ipv4"
    for s in servers:
        v6 = ((s.get("public_net") or {}).get("ipv6") or {}).get("ip")
        if not v6:
            continue
        try:
            net = ipaddress.ip_network(v6, strict=False)
        except ValueError:
            continue
        if any(a.version == 6 and a in net for a in mine):
            return s, "ipv6"
    return None, None


def firewalls_of(server, firewalls):
    by_id = {f.get("id"): f for f in firewalls if isinstance(f, dict)}
    out = []
    for ref in ((server.get("public_net") or {}).get("firewalls") or []):
        f = by_id.get(ref.get("id"))
        if not f:
            out.append({"id": ref.get("id"), "name": None, "status": ref.get("status"), "rules": None})
            continue
        rules = [{"direction": r.get("direction"), "protocol": r.get("protocol"), "port": r.get("port"),
                  "source_ips": [str(x) for x in (r.get("source_ips") or [])][:200],
                  "description": seclib.clean(r.get("description"), 120) or None}
                 for r in f.get("rules") or [] if isinstance(r, dict) and r.get("direction") == "in"]
        out.append({"id": f.get("id"), "name": seclib.clean(f.get("name"), 80), "status": ref.get("status"),
                    "rules": rules})
    return out


def fetch(token, get=http_get, addrs=None):
    servers = all_pages("servers", token, get)
    firewalls = all_pages("firewalls", token, get)
    server, how = match_server(servers, addrs if addrs is not None else local_addresses())
    if not server:
        return {"server": None, "matched_by": None, "firewalls": []}
    return {"server": {"id": server.get("id"), "name": seclib.clean(server.get("name"), 80)}, "matched_by": how,
            "firewalls": firewalls_of(server, firewalls)}


def read_token(path):
    with open(path, encoding="utf-8") as f:
        token = f.read(4096).strip()
    if not token or any(c.isspace() for c in token):
        raise ApiError("the token file is empty or not a single token")
    return token


def write_atomic(path, doc):
    d = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=d, prefix="." + os.path.basename(path) + "-", suffix=".tmp")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(doc, f, ensure_ascii=False, indent=1)
            f.write("\n")
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def main(argv, get=http_get, addrs=None, now=None):
    ap = argparse.ArgumentParser(description="Security Monitor: the Hetzner Cloud Firewalls of this server")
    ap.add_argument("--output", metavar="FILE", required=True)
    ap.add_argument("--token-file", metavar="FILE",
                    default=os.path.join(os.environ.get("CREDENTIALS_DIRECTORY", "/nonexistent"), "hetzner.token"))
    args = ap.parse_args(argv)
    stamp = (now or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        with open(args.output, encoding="utf-8") as f:
            prev = json.load(f)
        if not isinstance(prev, dict):
            prev = {}
    except (OSError, ValueError):
        prev = {}
    try:
        token = read_token(args.token_file)
        doc = {"format": FORMAT, "tried_at": stamp, "ok_at": stamp, "error": None}
        doc.update(fetch(token, get, addrs))
    except (ApiError, OSError) as e:
        msg = str(e) if isinstance(e, ApiError) else "the token could not be read"
        doc = {"format": FORMAT, "tried_at": stamp, "ok_at": prev.get("ok_at"), "error": msg,
               "server": prev.get("server"), "matched_by": prev.get("matched_by"),
               "firewalls": prev.get("firewalls") or []}
        print(f"Hetzner API: {msg}", file=sys.stderr)
    write_atomic(args.output, doc)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
