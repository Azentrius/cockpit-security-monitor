#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The parsers and helpers of seclib.py: address classes, ip, ss, UFW's
files, sshd -T, authorized_keys (sizes and fingerprints as ssh-keygen prints
them), the journal, cscli, the marks file and the Docker client's limits.
Offline, no root needed."""

import ipaddress
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.join(HERE, "..", "lib"))
import seclib  # noqa: E402

FIX = os.path.join(HERE, "fixtures")


def fixture(*parts):
    with open(os.path.join(FIX, *parts), encoding="utf-8") as f:
        return f.read()


class Addresses(unittest.TestCase):
    def test_classes(self):
        vpn = [ipaddress.ip_network("10.8.0.0/24")]
        want = {"203.0.113.7": "internet", "2001:db8::5": "internet", "10.8.0.2": "vpn", "10.0.0.3": "private",
                "192.168.1.4": "private", "fd00::1": "private", "100.64.1.1": "cgnat", "127.0.0.1": "local",
                "::1": "local", "169.254.1.1": "link", "fe80::1": "link", "224.0.0.1": "other",
                "::ffff:203.0.113.7": "internet", "not-an-ip": "other"}
        for addr, cls in want.items():
            self.assertEqual(seclib.source_class(addr, vpn), cls, addr)

    def test_public(self):
        self.assertTrue(seclib.is_public("198.51.100.1"))
        self.assertFalse(seclib.is_public("172.20.1.1"))
        self.assertFalse(seclib.is_public("fc12::1"))
        self.assertFalse(seclib.is_public("ff02::1"))

    def test_widen(self):
        net = ipaddress.ip_network
        self.assertEqual(seclib.widen(net("10.0.0.2/32")), net("10.0.0.0/8"))
        self.assertEqual(seclib.widen(net("10.8.0.1/24", strict=False)), net("10.8.0.0/24"))
        self.assertEqual(seclib.widen(net("203.0.113.9/32")), net("203.0.113.0/24"))

    def test_ip_addr(self):
        ifs = {i["name"]: i for i in seclib.parse_ip_addr(fixture("ufw-docker", "commands", "ip-addr.json"))}
        self.assertEqual(ifs["lo"]["kind"], "local")
        self.assertEqual(ifs["wg0"]["kind"], "vpn")
        self.assertEqual(ifs["docker0"]["kind"], "container")
        self.assertEqual(ifs["br-1a2b3c4d5e6f"]["kind"], "container")
        self.assertEqual([a["class"] for a in ifs["eth0"]["addrs"]], ["internet", "internet", "link"])
        self.assertEqual(ifs["enp7s0"]["addrs"][0]["class"], "private")
        self.assertEqual(seclib.vpn_networks(ifs.values()), [ipaddress.ip_network("10.8.0.0/24")])


class Sockets(unittest.TestCase):
    def test_forms(self):
        text = "\n".join([
            'udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=612,fd=14))',
            "udp UNCONN 0 0 0.0.0.0:51820 0.0.0.0:*",
            'tcp LISTEN 0 4096 *:443 *:* users:(("caddy",pid=1450,fd=8))',
            'tcp LISTEN 0 4096 [::]:22 [::]:* users:(("sshd",pid=1001,fd=4),("systemd",pid=1,fd=101))',
            'tcp LISTEN 0 4096 [fe80::1%eth0]:53 [::]:* users:(("dnsmasq",pid=7,fd=5))',
            'tcp LISTEN 0 4096 [::ffff:127.0.0.1]:8000 *:* users:(("app",pid=8,fd=5))',
            'tcp ESTAB 0 0 10.0.0.2:22 10.0.0.9:5000 users:(("sshd",pid=9,fd=5))',
            'udp UNCONN 0 0 127.0.0.1:323 0.0.0.0:*',
            'udp UNCONN 0 0 127.0.0.1:323 0.0.0.0:* users:(("chronyd",pid=702,fd=5))',
            "garbage line",
        ])
        socks = {(s["proto"], s["addr"], s["port"]): s for s in seclib.parse_ss(text)}
        self.assertEqual(socks[("udp", "127.0.0.53", 53)]["iface"], "lo")
        self.assertEqual(socks[("udp", "0.0.0.0", 51820)]["procs"], [])
        self.assertEqual(socks[("tcp", "*", 443)]["families"], [4, 6])
        self.assertEqual(socks[("tcp", "::", 22)]["families"], [6])
        self.assertEqual([p["name"] for p in socks[("tcp", "::", 22)]["procs"]], ["sshd", "systemd"])
        self.assertEqual(socks[("tcp", "fe80::1", 53)]["iface"], "eth0")
        self.assertEqual(socks[("tcp", "127.0.0.1", 8000)]["families"], [4])
        self.assertNotIn(("tcp", "10.0.0.2", 22), socks, "connections are not listeners")
        self.assertEqual(socks[("udp", "127.0.0.1", 323)]["procs"], [{"name": "chronyd", "pid": 702}],
                         "the same address twice is one socket")

    def test_fixture(self):
        socks = seclib.parse_ss(fixture("ufw-docker", "commands", "ss.txt"))
        self.assertEqual(len(socks), 19)


class Ufw(unittest.TestCase):
    def test_tuples(self):
        rules = seclib.parse_ufw_rules(fixture("ufw-docker", "files", "etc", "ufw", "user.rules"), 4)
        self.assertEqual([(r["action"], r["proto"], r["port"], r["iface_in"], r["comment"]) for r in rules],
                         [("allow", "any", "any", "wg0", "VPN"), ("allow", "tcp", "80,443", "", ""),
                          ("allow", "udp", "443", "", ""), ("allow", "udp", "51820", "", "WireGuard")])
        more = seclib.parse_ufw_rules("\n".join([
            "### tuple ### limit tcp 22 0.0.0.0/0 any 10.8.0.0/24 in",
            "### tuple ### deny_log any any 0.0.0.0/0 any 192.0.2.0/24 in",
            "### tuple ### allow tcp 80,443 0.0.0.0/0 any 0.0.0.0/0 Nginx%20Full - in",
            "### tuple ### route:allow tcp 8080 172.17.0.2 any 0.0.0.0/0 in_eth0!out_docker0",
            "### tuple ### allow tcp 9 0.0.0.0/0 any 0.0.0.0/0 in comment=zz",
        ]), 4)
        self.assertEqual(more[0]["from"], "10.8.0.0/24")
        self.assertEqual((more[1]["action"], more[1]["log"]), ("deny", "log"))
        self.assertEqual(more[2]["app"], "Nginx Full")
        self.assertEqual((more[3]["route"], more[3]["iface_in"], more[3]["iface_out"]), (True, "eth0", "docker0"))
        self.assertEqual(more[4]["comment"], "", "a comment that is not hex is dropped")

    def test_kv(self):
        kv = seclib.parse_kv(fixture("ufw-docker", "files", "etc", "default", "ufw"))
        self.assertEqual((kv["IPV6"], kv["DEFAULT_INPUT_POLICY"]), ("yes", "DROP"))


class Sshd(unittest.TestCase):
    def test_hardened(self):
        cfg = seclib.parse_sshd_t(fixture("ufw-docker", "commands", "sshd-T.txt"))
        self.assertEqual(cfg["listenaddress"], ["[::]:22", "0.0.0.0:22"])
        got = {f["key"]: (f["state"], f["code"]) for f in seclib.assess_sshd(cfg)}
        self.assertEqual(got["passwordauthentication"], ("ok", "password-off"))
        self.assertEqual(got["permitrootlogin"], ("info", "root-key"))
        self.assertEqual(got["kbdinteractiveauthentication"], ("ok", "kbd-off"))
        self.assertEqual(got["x11forwarding"], ("info", "x11-on"))
        self.assertEqual(got["allowusers"], ("info", "no-allow-list"))
        self.assertNotIn("permitemptypasswords", got)

    def test_open(self):
        cfg = seclib.parse_sshd_t("passwordauthentication yes\npermitrootlogin yes\nkbdinteractiveauthentication yes\n"
                                  "usepam yes\npermitemptypasswords yes\nmaxauthtries 10\nallowusers alex deploy\n"
                                  "x11forwarding no\nallowagentforwarding no\n")
        got = {f["key"]: (f["state"], f["code"], f["value"]) for f in seclib.assess_sshd(cfg)}
        self.assertEqual(got["passwordauthentication"][:2], ("warning", "password-on"))
        self.assertEqual(got["kbdinteractiveauthentication"][:2], ("warning", "kbd-pam"))
        self.assertEqual(got["permitemptypasswords"][:2], ("warning", "empty-passwords"))
        self.assertEqual(got["permitrootlogin"][:2], ("warning", "root-yes"))
        self.assertEqual(got["maxauthtries"], ("info", "tries-many", "10"))
        self.assertEqual(got["allowusers"], ("ok", "allow-list", "2"))
        self.assertEqual(got["allowagentforwarding"][0], "ok")

    def test_errors_and_match(self):
        self.assertEqual(seclib.sshd_error("Missing privilege separation directory: /run/sshd\n")[0],
                         "privsep-dir-missing")
        self.assertEqual(seclib.sshd_error("sshd: no hostkeys available -- exiting.")[0], "error")
        self.assertTrue(seclib.has_match_block("Port 22\nMatch User backup\n  ForceCommand x\n"))
        self.assertFalse(seclib.has_match_block("# Match User x\nPort 22\n"))


KEYS = {  # what ssh-keygen -lf prints for the keys in the fixtures
    "bastion": (256, "SHA256:qDKmFG/9kyw+c70mRjy835t7UXT1U0DlyvkwDDsFSKc"),
    "alex@laptop": (256, "SHA256:2K79bJsAg+NO83qU9qr34b0KCHjClsFCTLWZr+geexE"),
    "deploy@ci": (2048, "SHA256:d+vGx8H4xRAWRVfTQCXEWjqwZ+6yPf1gbOa35tMH5OU"),
    "backup": (4096, "SHA256:Znw9MqtaNA8yJ6hAIKK9/FpMNy+c3zbWX/oIn7oS/wg"),
    "phone": (384, "SHA256:iSx73k0WdMOLPwpNKHTTluWQy1GbTOSbSZDzltQ/wTg"),
}


class Keys(unittest.TestCase):
    def test_sizes_and_fingerprints(self):
        keys = []
        for s, user in (("ufw-docker", "root"), ("ufw-docker", "home/alex"), ("hetzner-open", "root")):
            keys += seclib.parse_authorized_keys(fixture(s, "files", user, ".ssh", "authorized_keys"))
        got = {k["comment"]: (k["bits"], k["fingerprint"]) for k in keys}
        self.assertEqual(got, KEYS)

    def test_findings_and_options(self):
        keys = seclib.parse_authorized_keys(fixture("ufw-docker", "files", "home", "alex", ".ssh", "authorized_keys"))
        self.assertEqual([(k["comment"], [x["code"] for x in k["findings"]]) for k in keys],
                         [("alex@laptop", ["no-from"]), ("deploy@ci", ["rsa-short", "no-from"]),
                          ("backup", ["no-from"])])
        self.assertEqual(keys[2]["options"], ["restrict", 'command="/usr/local/bin/backup-receive"'])
        root = seclib.parse_authorized_keys(fixture("ufw-docker", "files", "root", ".ssh", "authorized_keys"))
        self.assertEqual(root[0]["options"], ['from="10.8.0.0/24"', "no-agent-forwarding", "no-X11-forwarding"])
        self.assertEqual(root[0]["findings"], [])
        dsa = seclib.parse_authorized_keys(fixture("nft-native", "files", "home", "ci", ".ssh", "authorized_keys"))
        self.assertEqual((dsa[0]["type"], dsa[0]["bits"], [x["code"] for x in dsa[0]["findings"]]),
                         ("ssh-dss", 1024, ["dsa", "no-from"]))

    def test_quoted_options_and_garbage(self):
        line = 'from="10.8.0.0/24,192.0.2.0/24",command="echo \\"a, b\\"" ' + \
            fixture("ufw-docker", "files", "root", ".ssh", "authorized_keys").split(" ", 1)[1]
        keys = seclib.parse_authorized_keys(line + "\nnot a key at all\nssh-ed25519 !!!notbase64 x\n# comment\n")
        self.assertEqual(keys[0]["options"][0], 'from="10.8.0.0/24,192.0.2.0/24"')
        self.assertEqual(keys[0]["options"][1], 'command="echo \\"a, b\\""')
        self.assertEqual(keys[0]["fingerprint"], KEYS["bastion"][1])
        self.assertEqual([k["type"] for k in keys], ["ssh-ed25519", None, "ssh-ed25519"])
        self.assertIsNone(keys[2]["fingerprint"])

    def test_types(self):
        self.assertTrue(seclib._is_type("ssh-ed25519-cert-v01@openssh.com"))
        self.assertTrue(seclib._is_type("sk-ssh-ed25519-cert-v01@openssh.com"))
        self.assertTrue(seclib._is_type("ecdsa-sha2-nistp256"))
        self.assertFalse(seclib._is_type("ssh-unknown"))

    def test_accounts_and_files(self):
        acc = seclib.login_accounts(fixture("ufw-docker", "files", "etc", "passwd"))
        self.assertEqual([a[0] for a in acc], ["root", "alex", "postgres"])
        self.assertEqual(seclib.key_files([".ssh/authorized_keys .ssh/authorized_keys2"], "alex", "/home/alex"),
                         ["/home/alex/.ssh/authorized_keys", "/home/alex/.ssh/authorized_keys2"])
        self.assertEqual(seclib.key_files(["/etc/ssh/keys/%u %h/.ssh/k none %%x"], "a", "/home/a"),
                         ["/etc/ssh/keys/a", "/home/a/.ssh/k", "/home/a/%x"])
        self.assertEqual(seclib.key_files(None, "r", "/root"), ["/root/.ssh/authorized_keys",
                                                                "/root/.ssh/authorized_keys2"])

    def test_password_kinds(self):
        """passwd -l and usermod -L put "!" in front of the hash: locked. "!", "!!" (RHEL's useradd),
        "*" and "!*" never had a password: a key-only account by design."""
        for field, kind in (("!$6$salt$hash", "locked"), ("!!$y$j9T$hash", "locked"), ("!", "none"),
                            ("!!", "none"), ("*", "none"), ("!*", "none"), ("*LK*", "none"),
                            ("", "empty"), ("$6$salt$hash", "set"), ("$y$j9T$hash", "set")):
            self.assertEqual(seclib.password_kind(field), kind, field)

    def test_shadow(self):
        sh = seclib.parse_shadow(fixture("ufw-docker", "files", "etc", "shadow"))
        self.assertEqual(sh["alex"], {"password": "locked", "expire": None})
        self.assertEqual(sh["root"], {"password": "none", "expire": None})
        self.assertEqual(seclib.parse_shadow("a:!$6$x$y:20000:0:99999:7::19999:\nbad line\nb:*:1::::::x\n"),
                         {"a": {"password": "locked", "expire": 19999}, "b": {"password": "none", "expire": None}})
        self.assertEqual(seclib.parse_shadow(None), {})


class Journal(unittest.TestCase):
    def test_first_entry(self):
        self.assertEqual(seclib.journal_first(fixture("ufw-docker", "commands", "journal-start.jsonl")),
                         1791705600.0)
        for text in ("", "\n", "not json", '{"MESSAGE":"x"}', '{"__REALTIME_TIMESTAMP":"x"}', "[]"):
            self.assertIsNone(seclib.journal_first(text), text)

    def test_hetzner_open(self):
        j = seclib.parse_journal(fixture("hetzner-open", "commands", "journal.jsonl"))
        self.assertEqual([(s["user"], s["source"], s["class"], s["method"]) for s in j["success"]],
                         [("root", "198.51.100.20", "internet", "publickey")])
        self.assertEqual([(f["source"], f["count"], f["users"], f["services"]) for f in j["failed"]],
                         [("192.0.2.50", 6, 1, ["ssh"]), ("192.0.2.90", 1, 1, ["cockpit"]),
                          ("192.0.2.77", 1, 1, ["ssh"])], "most attempts first, then the latest")
        self.assertEqual((j["failed_total"], j["failed_sources"]), (8, 3),
                         "Invalid user and Failed password of one connection count once")

    def test_ufw_docker(self):
        vpn = [ipaddress.ip_network("10.8.0.0/24")]
        j = seclib.parse_journal(fixture("ufw-docker", "commands", "journal.jsonl"), vpn)
        self.assertEqual([(s["service"], s["user"], s["class"]) for s in j["success"]],
                         [("ssh", "root", "vpn"), ("cockpit", "alex", None), ("ssh", "alex", "vpn")])
        self.assertEqual(j["sudo"], [{"user": "alex", "uses": 1, "failures": 1, "last": j["sudo"][0]["last"]}])
        self.assertEqual(j["failed"][0]["class"], "vpn")

    def test_bytes_message_and_junk(self):
        text = '{"SYSLOG_IDENTIFIER":"sshd","_PID":"1","MESSAGE":[65,99,99,101,112,116,101,100,32,112,97,115,115,' \
               '119,111,114,100,32,102,111,114,32,120,32,102,114,111,109,32,49,57,56,46,53,49,46,49,48,48,46,49,32,' \
               '112,111,114,116,32,49,32,115,115,104,50]}\nnot json\n'
        j = seclib.parse_journal(text)
        self.assertEqual(j["success"][0]["method"], "password")


class CrowdSec(unittest.TestCase):
    def test_lists_and_yaml(self):
        self.assertEqual(seclib.parse_json_list("null"), [])
        self.assertIsNone(seclib.parse_json_list("{}"))
        self.assertEqual(seclib.version_tuple(fixture("hetzner-open", "commands", "cscli-version.txt")), (1, 4, 6))
        conf = seclib.yaml_keys(fixture("hetzner-open", "files", "etc", "crowdsec", "bouncers",
                                        "crowdsec-firewall-bouncer.yaml"), ("mode", "nftables_hooks", "iptables_chains"))
        self.assertEqual(conf, {"mode": "nftables", "iptables_chains": ["INPUT"]})
        self.assertEqual(seclib.yaml_keys("mode: nftables\nnftables_hooks: [input, forward]\n", ("nftables_hooks",)),
                         {"nftables_hooks": ["input", "forward"]})
        self.assertEqual(seclib.yaml_keys("nftables_hooks:\n  - input\n  - forward # both\n", ("nftables_hooks",)),
                         {"nftables_hooks": ["input", "forward"]})


class Marks(unittest.TestCase):
    def test_roundtrip(self):
        marks, errors = seclib.parse_marks("# x\nport 8080/tcp Rustdesk relay, on purpose\nport 51820/udp\n"
                                           "container forgejo-runner docker-socket needs the socket\n"
                                           "port 70000/tcp too big\nport 22/sctp nope\ncontainer x unknown-kind\n"
                                           "something else\n")
        self.assertEqual(marks["ports"], {"8080/tcp": "Rustdesk relay, on purpose", "51820/udp": ""})
        self.assertEqual(marks["containers"], {("forgejo-runner", "docker-socket"): "needs the socket"})
        self.assertEqual(errors, [5, 6, 7, 8])
        again, errors = seclib.parse_marks(seclib.format_marks(marks))
        self.assertEqual((again, errors), (marks, []))

    def test_notes(self):
        self.assertTrue(seclib.valid_note("Büro, absichtlich"))
        self.assertFalse(seclib.valid_note("x" * 201))
        self.assertFalse(seclib.valid_note("two\nlines"))
        self.assertFalse(seclib.valid_note("bidi" + chr(0x202E)))
        self.assertTrue(seclib.valid_port_key("1/udp"))
        self.assertFalse(seclib.valid_port_key("0/tcp"))
        self.assertFalse(seclib.valid_port_key("08080/tcp ") or seclib.valid_port_key("80/TCP"))

    def test_clean(self):
        self.assertEqual(seclib.clean("a" + chr(0x202E) + "b" + chr(0x200B) + "c\x07", 10), "a b c")


class Docker(unittest.TestCase):
    def test_only_fixed_paths(self):
        for bad in ("/containers/create", "/containers/abc/kill", "/images/json", "/info/../containers/x/start",
                    "/containers/0123456789ab/json?x=1", "/exec/1/start"):
            with self.assertRaises(ValueError, msg=bad):
                seclib.docker_get(bad, sock="/nonexistent.sock")
        with self.assertRaises(OSError):
            seclib.docker_get("/info", sock="/nonexistent.sock")


class Fail2ban(unittest.TestCase):
    """fail2ban-client's answers, as fail2ban 1.0.2's beautifier and jail reader write them."""

    def test_status(self):
        nl = chr(10)
        self.assertEqual(seclib.parse_f2b_status("Status" + nl + "|- Number of jail:\t3" + nl +
                                                 "`- Jail list:\tnginx-botsearch, recidive, sshd" + nl),
                         ["nginx-botsearch", "recidive", "sshd"])
        self.assertEqual(seclib.parse_f2b_status("Status" + nl + "|- Number of jail:\t0" + nl + "`- Jail list:\t"), [])
        self.assertIsNone(seclib.parse_f2b_status("ERROR   Failed to access socket path"))
        self.assertEqual(seclib.parse_f2b_status("`- Jail list:\tok, bad name, $(x)"), ["ok"])

    def test_jail_status(self):
        nl = chr(10)
        text = nl.join(["Status for the jail: sshd", "|- Filter", "|  |- Currently failed:\t1",
                        "|  |- Total failed:\t41", "|  `- Journal matches:\t_SYSTEMD_UNIT=ssh.service + _COMM=sshd",
                        "`- Actions", "   |- Currently banned:\t2", "   |- Total banned:\t7",
                        "   `- Banned IP list:\t203.0.113.50 2001:db8::7"])
        self.assertEqual(seclib.parse_f2b_jail_status(text), {
            "failed_now": 1, "failed_total": 41, "journal": "_SYSTEMD_UNIT=ssh.service + _COMM=sshd",
            "banned_now": 2, "banned_total": 7, "banned": ["203.0.113.50", "2001:db8::7"]})
        files = seclib.parse_f2b_jail_status("|  `- File list:\t/var/log/a.log /var/log/b.log" + nl +
                                             "   `- Banned IP list:\t")
        self.assertEqual((files["files"], files["banned"]), (["/var/log/a.log", "/var/log/b.log"], []))

    def test_dump(self):
        nl = chr(10)
        lines = [
            "['set', 'dbpurgeage', '14d']", "['set', 'dbfile', '/var/lib/fail2ban/fail2ban.sqlite3']",
            "['add', 'sshd', 'systemd']", "['set', 'sshd', 'maxretry', 5]", "['set', 'sshd', 'bantime', '1h']",
            "['set', 'sshd', 'addjournalmatch', '_SYSTEMD_UNIT=ssh.service', '+', '_COMM=sshd']",
            "['set', 'sshd', 'addignoreip', '127.0.0.1/8', '::1']",
            "['multi-set', 'sshd', 'addfailregex', ['^a <HOST>', '^b <HOST>']]",
            "['set', 'sshd', 'addaction', 'iptables-multiport']",
            "['multi-set', 'sshd', 'action', 'iptables-multiport', [['actionban', '<iptables> -I f2b-<name> 1'], "
            "['port', 'ssh'], ['protocol', 'tcp'], ['chain', '<known/chain>']]]",
            "['add', 'web', 'auto']", "['set', 'web', 'addlogpath', '/var/log/web.log', 'head']",
            "['set', 'web', 'addaction', 'nftables']", "['set', 'web', 'action', 'nftables', 'chain_hook', 'forward']",
            "['set', 'ghost', 'maxretry', 3]", "__import__('os').system('id')", "not a list", "['start', 'sshd']"]
        d = seclib.parse_f2b_dump(nl.join(lines))
        self.assertEqual(d["global"], {"dbpurgeage": "14d", "dbfile": "/var/lib/fail2ban/fail2ban.sqlite3"})
        self.assertEqual(sorted(d["jails"]), ["sshd", "web"], "a jail is known only once added")
        s = d["jails"]["sshd"]
        self.assertEqual((s["backend"], s["maxretry"], s["bantime"], s["journalmatch"], s["ignoreip"], s["failregex"]),
                         ("systemd", 5, "1h", ["_SYSTEMD_UNIT=ssh.service + _COMM=sshd"], ["127.0.0.1/8", "::1"], 2))
        self.assertEqual(s["actions"], [{"name": "iptables-multiport", "opts": {
            "port": "ssh", "protocol": "tcp", "chain": "<known/chain>"}}], "only the options that say where it bans")
        w = d["jails"]["web"]
        self.assertEqual((w["logpaths"], w["actions"][0]["opts"]), (["/var/log/web.log"], {"chain_hook": "forward"}))

    def test_ports(self):
        self.assertEqual(seclib.f2b_ports("ssh"), [(22, 22)])
        self.assertEqual(seclib.f2b_ports("http,https 8080"), [(80, 80), (443, 443), (8080, 8080)])
        self.assertEqual(seclib.f2b_ports("1000:2000"), [(1000, 2000)])
        self.assertIsNone(seclib.f2b_ports("my-service"), "an unknown name: no guess")
        services = seclib.parse_services("# c" + chr(10) + "my-service  4242/tcp  alias2   # note" + chr(10) + "x 1/udp")
        self.assertEqual(seclib.f2b_ports("alias2", services), [(4242, 4242)])


class PageTexts(unittest.TestCase):
    """Every code the helpers emit has its text on the page (plugin/i18n.js)."""

    def test_codes(self):
        with open(os.path.join(HERE, "..", "plugin", "i18n.js"), encoding="utf-8") as f:
            page = f.read()
        codes = set()
        configs = ["",
                   "passwordauthentication yes", "kbdinteractiveauthentication yes", "usepam yes",
                   "permitemptypasswords yes", "permitrootlogin yes", "pubkeyauthentication no", "maxauthtries 9",
                   "allowusers a", "x11forwarding yes", "allowagentforwarding no"]
        nl = chr(10)
        for text in (nl.join(configs), nl.join(["kbdinteractiveauthentication yes", "usepam no",
                                                "permitrootlogin forced-commands-only"]), "permitrootlogin no", ""):
            codes |= {"sshd." + f["code"] for f in seclib.assess_sshd(seclib.parse_sshd_t(text))}
        codes |= {"kind." + k for k in seclib.CONTAINER_KINDS} | {"ck." + k for k in seclib.CONTAINER_KINDS}
        codes |= {"key." + c for c in ("dsa", "rsa-short", "no-from", "unreadable")}
        codes |= {"file." + c for c in ("file-writable", "dir-writable", "file-owner", "dir-owner", "link")}
        for code in sorted(codes):
            self.assertEqual(page.count('"' + code + '"'), 2, code + " in English and German")

    def test_fail2ban_codes(self):
        """Every finding of fail2ban has its text on the page, a warning also in the status; every
        essential part that can be missing has both too."""
        import seccheck
        import secstatus
        with open(os.path.join(HERE, "..", "plugin", "i18n.js"), encoding="utf-8") as f:
            page = f.read()
        warnings = ("not-running", "unmanaged-bans", "input-only", "udp-open", "log-missing", "log-idle", "no-match",
                    "jail-not-running")
        for code in warnings + ("persisted-chains", "allports-input"):
            self.assertEqual(page.count('"f2b.' + code + '"'), 2, code)
        for code in warnings:
            for lang in ("en", "de"):
                self.assertIn("fail2ban." + code, secstatus.T[lang], code)
        for part in seccheck.F2B_ESSENTIAL + ("jails", "skipped"):
            self.assertEqual(page.count('"f2b.part.' + part + '"'), 2, part)
            for lang in ("en", "de"):
                self.assertIn("fail2ban.part." + part, secstatus.T[lang], part)


if __name__ == "__main__":
    unittest.main(verbosity=1)
