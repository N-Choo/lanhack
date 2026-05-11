import os
import subprocess
from collections import defaultdict


class IptablesManager:
    def __init__(self):
        self._rules = []

    def _cmd(self, table, args):
        cmd = ["iptables"]
        if table != "filter":
            cmd += ["-t", table]
        cmd += args
        subprocess.run(cmd, stderr=subprocess.DEVNULL)

    def insert(self, chain, rule_args, table="filter"):
        self._cmd(table, ["-I", chain, "1"] + rule_args)
        self._rules.append(("insert", table, chain, rule_args))

    def delete(self, chain, rule_args, table="filter"):
        self._cmd(table, ["-D", chain] + rule_args)
        for i in range(len(self._rules) - 1, -1, -1):
            op, t, c, r = self._rules[i]
            if op == "insert" and t == table and c == chain and r == rule_args:
                self._rules.pop(i)
                break

    def policy(self, chain, target):
        subprocess.run(["iptables", "-P", chain, target], stderr=subprocess.DEVNULL)
        self._rules.append(("policy", None, None, (chain, target)))

    def restore(self):
        for op, table, chain, detail in reversed(self._rules):
            if op == "insert":
                cmd = ["iptables"]
                if table != "filter":
                    cmd += ["-t", table]
                cmd += ["-D", chain] + detail
                subprocess.run(cmd, stderr=subprocess.DEVNULL)
            elif op == "policy":
                subprocess.run(["iptables", "-P", detail[0], "ACCEPT"], stderr=subprocess.DEVNULL)
        self._rules.clear()


quit_flag = False
show_mac = True
devices = []
blocked_ips = set()
captured_sites = defaultdict(list)
spoof_threads = {}
spy_threads = {}
my_ip = ""
gateway_ip = ""
iface = ""
netmask = ""
quick_discord = False
quick_steam = False
quick_latency_ip = None
quick_tc_qdisc = False
sniff_thread = None

DISCORD_RANGES = ["162.159.0.0/16", "173.245.48.0/20", "108.162.0.0/15", "104.16.0.0/12", "131.0.72.0/22"]
STEAM_RANGES = ["208.64.200.0/22", "208.78.164.0/22", "185.25.182.0/23"]
custom_blocks = {}
global_dns_block = False
https_intercept_on = False
mitm_process = None
harvester_on = False
harvester_thread = None
harvested_creds = []
stealth_mode = False
stealth_intervals = [1.5, 2.3, 1.8, 3.1, 2.7, 1.2, 2.9, 1.6]
auto_scan_active = False
auto_scan_timer = None
bandwidth_data = defaultdict(lambda: [0] * 30)
domain_hits = defaultdict(int)
show_graphs = False
dns_server_thread = None
dns_stop = False
dns_blocklist = set()
_attacks_built = False

iptables = IptablesManager()

CDN_MAP = {"googlevideo.com":"youtube.com","ytimg.com":"youtube.com","ggpht.com":"youtube.com","phncdn.com":"pornhub.com","rncdn7.com":"pornhub.com","rncdn3.com":"pornhub.com","rncdn1.com":"pornhub.com","gstatic.com":"google.com","googleusercontent.com":"google.com"}
OUI_DB = {"b0:a7:b9":"TP-Link","c8:5a:cf":"HP Inc.","f0:f6:c1":"Sonos Inc.","c4:77:af":"ADB","d8:1f:12":"Tuya Smart","70:08:10":"Intel","54:44:a3":"Samsung","10:ae:60":"Amazon","a0:02:dc":"Amazon","7c:1e:52":"Amazon","e8:eb:11":"Asus","00:1a:11":"Google","00:1b:63":"Apple","00:25:00":"Apple","00:26:08":"Apple","00:26:b0":"Apple","00:50:56":"VMware","14:cc:20":"TP-Link","50:c7:6b":"TP-Link","b8:27:eb":"Raspberry Pi","dc:a6:32":"Xiaomi"}

MITM_ADDON = os.path.expanduser("~/.lanhack_mitm_addon.py")
