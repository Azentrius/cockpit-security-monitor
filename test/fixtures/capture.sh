#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Records what Security Monitor reads on a host, for a new scenario in test/fixtures/. Only
# reads: listings of the addresses, the sockets and the packet filter, sshd -T, Docker's API with
# GET, UFW's files, cscli's lists. Run as root on the host:
#
#   sudo sh capture.sh /tmp/capture
#
# Then copy the folder off the host and make it anonymous BY HAND before it goes into the
# repository: replace public addresses with documentation ranges (192.0.2.0/24, 198.51.100.0/24,
# 203.0.113.0/24, 2001:db8::/32), host, user and container names with neutral ones, and drop
# key comments, tokens and anything else private (test/scan_test.py refuses other public
# addresses). No authorized_keys and no journal are recorded: they hold names and addresses.
set -u
out="${1:?usage: capture.sh OUTDIR}"
mkdir -p "$out/commands" "$out/docker" "$out/files"
run() { name=$1; shift; "$@" > "$out/commands/$name" 2> "$out/commands/$name.err" || echo "$name: exit $?" >> "$out/errors.txt"; }
run ip-addr.json ip -j addr
run ss.txt ss -H -tulpn
run iptables-save.txt iptables-save
run ip6tables-save.txt ip6tables-save
command -v iptables-legacy-save > /dev/null && run iptables-legacy-save.txt iptables-legacy-save
run nft.json nft -j list ruleset
command -v sshd > /dev/null && run sshd-T.txt sshd -T
if [ -S /var/run/docker.sock ]; then
    for p in info version networks containers/json; do
        curl -s --unix-socket /var/run/docker.sock "http://docker/$p" > "$out/docker/$(echo "$p" | tr / -).json"
    done
    for id in $(curl -s --unix-socket /var/run/docker.sock http://docker/containers/json | python3 -c 'import json, sys; [print(c["Id"]) for c in json.load(sys.stdin)]'); do
        curl -s --unix-socket /var/run/docker.sock "http://docker/containers/$id/json" > "$out/docker/inspect-$(printf '%.12s' "$id").json"
    done
fi
for f in /etc/ufw/ufw.conf /etc/default/ufw /etc/ufw/user.rules /etc/ufw/user6.rules /etc/ssh/sshd_config \
         /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml; do
    [ -f "$f" ] && mkdir -p "$out/files$(dirname "$f")" && cp "$f" "$out/files$f"
done
if command -v cscli > /dev/null; then
    run cscli-version.txt cscli version
    run cscli-decisions.json cscli decisions list -o json
    run cscli-alerts.json cscli alerts list -o json --since 14d
    run cscli-bouncers.json cscli bouncers list -o json
fi
echo "recorded in $out; make it anonymous before it leaves the host"
