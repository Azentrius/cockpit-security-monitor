#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Records what Security Monitor reads on a host, for a new scenario in test/fixtures/. Only
# reads: listings of the addresses, the sockets and the packet filter, sshd -T, Docker's API with
# GET, UFW's files, cscli's lists. Run as root on the host:
#
#   sudo sh capture.sh /tmp/capture          into a folder
#   sudo sh capture.sh - [PATTERN...]        to standard output, nothing kept on the host (for a
#                                            remote shell that returns only the output); each
#                                            file as "==> PATH BYTES SHA256 <==", its bytes and a
#                                            newline; PATTERNs (shell globs) pick files
#
# Then make it anonymous BY HAND before it goes into the repository: replace public addresses
# with documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32), host,
# user and container names with neutral ones, and drop key comments, tokens and anything else
# private (test/scan_test.py refuses other public addresses). No authorized_keys, no
# /etc/passwd and no journal are recorded: they hold names and addresses. Docker's answers keep
# only the fields the scan reads, so no environment and no labels leave the host.
set -u
if [ "${1:-}" = - ]; then
    shift
    dump=1
    out=$(mktemp -d /tmp/secmon-capture.XXXXXX) || exit 1
    trap 'rm -rf -- "$out"' EXIT
else
    dump=
    out="${1:?usage: capture.sh OUTDIR | capture.sh - [PATTERN...]}"
    shift
fi
mkdir -p "$out/commands" "$out/docker" "$out/files"
run() {
    name=$1
    shift
    "$@" > "$out/commands/$name" 2> "$out/commands/$name.err" || echo "$name: exit $?" >> "$out/errors.txt"
    [ -s "$out/commands/$name.err" ] || rm -f "$out/commands/$name.err"
}
keep() { [ -r "$1" ] && mkdir -p "$out/files$(dirname "$1")" && cat "$1" > "$out/files$1"; }

run ip-addr.json ip -j addr
run ss.txt ss -H -tulpn
run iptables-save.txt iptables-save
run ip6tables-save.txt ip6tables-save
command -v iptables-legacy-save > /dev/null && run iptables-legacy-save.txt iptables-legacy-save
command -v ip6tables-legacy-save > /dev/null && run ip6tables-legacy-save.txt ip6tables-legacy-save
run nft.json nft -j list ruleset
command -v sshd > /dev/null && run sshd-T.txt sshd -T

# What exists without being read (fakesys: meta.json "exists" or an empty file).
for f in /usr/sbin/sshd /usr/sbin/ufw /usr/bin/cscli /var/run/docker.sock /etc/cockpit-security-monitor/hetzner.token; do
    [ -e "$f" ] && echo "$f" >> "$out/exists.txt"
done

# The container of a host-network process comes from its cgroup.
for pid in $(grep -o 'pid=[0-9]*' "$out/commands/ss.txt" | cut -d= -f2 | sort -un); do
    keep "/proc/$pid/cgroup"
done
keep /proc/net/ip_tables_names
keep /proc/net/ip6_tables_names

if [ -S /var/run/docker.sock ]; then
    get() { curl -s --unix-socket /var/run/docker.sock "http://docker$1"; }
    get /info > "$out/docker/info.json"
    get /version > "$out/docker/version.json"
    get /networks > "$out/docker/networks.json"
    get /containers/json > "$out/docker/containers.json"
    for id in $(python3 -c 'import json, sys; [print(c["Id"]) for c in json.load(sys.stdin)]' < "$out/docker/containers.json"); do
        get "/containers/$id/json" > "$out/docker/inspect-$(printf '%.12s' "$id").json"
    done
    # Only the fields seccheck.py reads, in Docker's own shape.
    python3 - "$out/docker" <<'EOF'
import json, os, sys

def pick(o, keys):
    return {k: o[k] for k in keys if isinstance(o, dict) and k in o}

d = sys.argv[1]
for name in sorted(os.listdir(d)):
    path = os.path.join(d, name)
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except ValueError:
        continue
    kind = name[:-5]
    if kind == "info":
        doc = pick(doc, ["ServerVersion", "FirewallBackend", "Driver", "CgroupVersion", "SecurityOptions"])
    elif kind == "version":
        doc = pick(doc, ["Version", "ApiVersion", "MinAPIVersion", "Os", "Arch"])
    elif kind == "networks":
        doc = [dict(pick(n, ["Name", "Id", "Driver", "EnableIPv6", "Internal", "Options"]),
                    IPAM={"Config": (n.get("IPAM") or {}).get("Config") or []}) for n in doc]
    elif kind == "containers":
        doc = [pick(c, ["Id", "Names", "Image", "State"]) for c in doc]
    else:
        cfg, hc, ns = doc.get("Config") or {}, doc.get("HostConfig") or {}, doc.get("NetworkSettings") or {}
        doc = dict(pick(doc, ["Id", "Name", "AppArmorProfile"]),
                   Config=pick(cfg, ["Image", "User"]),
                   HostConfig=pick(hc, ["NetworkMode", "Privileged", "PidMode", "CapAdd", "SecurityOpt"]),
                   Mounts=[pick(m, ["Type", "Source", "Destination", "RW"]) for m in doc.get("Mounts") or []],
                   NetworkSettings={"Ports": ns.get("Ports"), "Networks": {
                       k: pick(v, ["NetworkID", "IPAddress", "IPPrefixLen", "GlobalIPv6Address"])
                       for k, v in (ns.get("Networks") or {}).items()}})
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1)
        f.write("\n")
EOF
fi

for f in /etc/ufw/ufw.conf /etc/default/ufw /etc/ufw/user.rules /etc/ufw/user6.rules /etc/ssh/sshd_config \
         /etc/ssh/sshd_config.d/*.conf /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml; do
    [ -f "$f" ] && keep "$f"
done
if command -v cscli > /dev/null; then
    run systemctl-is-active-crowdsec.txt systemctl is-active crowdsec.service
    run cscli-version.txt cscli version
    run cscli-decisions.json cscli decisions list -o json
    run cscli-alerts.json cscli alerts list -o json --since 14d
    run cscli-bouncers.json cscli bouncers list -o json
fi

if [ -z "$dump" ]; then
    echo "recorded in $out; make it anonymous before it leaves the host"
    exit 0
fi
cd "$out" || exit 1
find . -type f | sed 's|^\./||' | sort | while read -r f; do
    if [ $# -gt 0 ]; then
        hit=
        for p in "$@"; do
            # shellcheck disable=SC2254
            case "$f" in $p) hit=1 ;; esac
        done
        [ -n "$hit" ] || continue
    fi
    printf '==> %s %s %s <==\n' "$f" "$(wc -c < "$f" | tr -d ' ')" "$(sha256sum < "$f" | cut -c1-64)"
    cat "$f"
    echo
done
echo "==> end <=="
