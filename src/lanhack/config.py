import os, sys, json
import subprocess
from collections import defaultdict
from datetime import datetime

LOG_PATH = "/tmp/lanhack_debug.log"
def log(msg):
    try:
        with open(LOG_PATH, "a") as f:
            f.write(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}\n")
    except: pass


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
sniff_error = ""
status_message = ""

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
dns_spoof_count = 0
_attacks_built = False

iptables = IptablesManager()

STATE_FILE = os.path.expanduser("~/.lanhack_state.json")

def save_state():
    try:
        data = {
            "custom_blocks": {k: v for k, v in custom_blocks.items()},
            "dns_blocklist": list(dns_blocklist),
            "blocked_ips": list(blocked_ips),
        }
        with open(STATE_FILE, "w") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        log(f"save_state failed: {e}")

def load_state():
    try:
        if not os.path.exists(STATE_FILE):
            return
        with open(STATE_FILE) as f:
            data = json.load(f)
        custom_blocks.clear()
        custom_blocks.update(data.get("custom_blocks", {}))
        dns_blocklist.clear()
        dns_blocklist.update(data.get("dns_blocklist", []))
        blocked_ips.clear()
        blocked_ips.update(data.get("blocked_ips", []))
    except Exception as e:
        log(f"load_state failed: {e}")

CDN_MAP = {"googlevideo.com":"youtube.com","ytimg.com":"youtube.com","ggpht.com":"youtube.com","phncdn.com":"pornhub.com","rncdn7.com":"pornhub.com","rncdn3.com":"pornhub.com","rncdn1.com":"pornhub.com","gstatic.com":"google.com","googleusercontent.com":"google.com"}
OUI_DB = {
    "b0:a7:b9":"TP-Link","c8:5a:cf":"HP Inc.","f0:f6:c1":"Sonos Inc.","c4:77:af":"ADB","d8:1f:12":"Tuya Smart",
    "70:08:10":"Intel","54:44:a3":"Samsung","10:ae:60":"Amazon","a0:02:dc":"Amazon","7c:1e:52":"Amazon",
    "e8:eb:11":"Asus","00:1a:11":"Google","00:1b:63":"Apple","00:25:00":"Apple","00:26:08":"Apple",
    "00:26:b0":"Apple","00:50:56":"VMware","14:cc:20":"TP-Link","50:c7:6b":"TP-Link","b8:27:eb":"Raspberry Pi",
    "dc:a6:32":"Xiaomi","00:0c:29":"VMware","00:05:69":"Huawei","08:00:27":"Oracle","00:15:5d":"Microsoft",
    "00:1a:a0":"Microsoft","18:fe:34":"Espressif","24:0a:c4":"Espressif","84:f3:eb":"Espressif",
    "00:1e:42":"D-Link","b0:c5:54":"D-Link","8c:88:2b":"Asus","60:45:cb":"Asus",
    "20:df:b9":"Arris","b4:75:0e":"Arris","40:4d:8f":"Arris","00:09:0f":"HP",
    "3c:d9:2b":"HP Inc.","44:94:fc":"LG","18:ee:69":"LG","00:26:eb":"Samsung",
    "8c:de:52":"Samsung","00:16:6b":"Realtek","e0:91:53":"Realtek","00:24:42":"Realtek",
    "04:4b:ed":"Roku","14:59:c0":"Roku","a0:40:41":"Roku","00:0f:53":"Cisco",
    "18:16:c9":"Cisco","1c:50:cc":"Cisco","24:69:68":"Cisco","54:7f:ee":"Cisco",
    "5c:50:15":"Cisco","64:16:7f":"Cisco","00:25:90":"Cisco-Linksys","00:50:f1":"Cisco-Linksys",
    "00:18:f8":"Cisco-Linksys","00:22:6b":"Netgear","28:c6:3e":"Netgear","6c:b0:ce":"Netgear",
    "84:1b:5e":"Netgear","ac:84:c6":"Netgear","c0:3f:0e":"Netgear","00:17:c8":"Netgear",
    "e0:3f:49":"Netgear","00:10:18":"Netgear","00:0f:b5":"Netgear","04:a1:51":"Netgear",
    "08:00:46":"Sony","00:21:00":"Sony","00:24:be":"Sony","64:d1:54":"Sony",
    "30:52:cb":"Sony","00:19:c7":"Sony","00:26:6c":"Nintendo","00:17:ab":"Nintendo",
    "40:d2:8c":"Nintendo","80:e8:6f":"Nintendo","b8:70:f4":"Nintendo","a4:c0:e1":"Nintendo",
    "10:6f:3f":"Intel","00:1d:e0":"Intel","00:1b:21":"Intel","00:1e:67":"Intel",
    "08:00:12":"Intel","f8:bc:12":"Dell","14:fe:b5":"Dell","84:7b:57":"Dell",
    "00:1e:4f":"Dell","5c:26:0a":"Dell","f0:1f:af":"Dell","e0:db:55":"Dell",
    "34:e6:d7":"Huawei","4c:77:66":"Huawei","58:8a:5a":"Huawei","84:a9:3e":"Huawei",
    "f8:0b:cb":"Huawei","00:21:6a":"Panasonic","c0:76:68":"Panasonic","e0:63:4a":"TP-Link",
    "54:a5:1b":"TP-Link","fc:d4:f6":"TP-Link","30:b5:c2":"TP-Link","64:7c:eb":"TP-Link",
    "54:e6:fc":"TP-Link","00:27:19":"TP-Link","68:72:51":"TP-Link","f4:ec:38":"TP-Link",
    "00:0e:8f":"Toshiba","38:f7:3d":"Canon","ac:82:47":"Xerox","00:21:5a":"Xerox",
    "00:1c:40":"ZTE","04:c0:6f":"ZTE","08:10:77":"ZTE","b0:75:d5":"ZTE",
    "b0:d5:cc":"ZTE","10:68:38":"Xiaomi","48:02:2a":"Xiaomi","90:cd:b6":"Xiaomi",
    "f4:6d:04":"Xiaomi","7c:b3:7b":"Xiaomi","18:c0:db":"Lenovo","38:6b:1c":"Lenovo",
    "5c:e0:c5":"Lenovo","80:a5:89":"Lenovo","b8:70:f4":"Lenovo","00:1b:dc":"Acer",
    "00:22:52":"Acer","34:97:f6":"Acer","50:8d:5f":"Acer","00:1c:25":"Acer",
    "e8:9a:8f":"Ubiquiti","00:27:22":"Ubiquiti","04:18:d6":"Ubiquiti","a0:48:1c":"Ubiquiti",
    "d0:9e:61":"Ubiquiti","6a:5c:35":"Ubiquiti","02:0e:8c":"Hikvision","04:0e:8c":"Hikvision",
    "1c:5c:55":"MikroTik","64:d1:54":"MikroTik","e4:8d:8c":"MikroTik","4c:5f:70":"MikroTik",
    "08:55:31":"MikroTik","00:0c:42":"MikroTik","b0:d5:9d":"Wyze","2c:f0:5d":"Wyze",
    "00:10:fa":"Apple","00:11:24":"Apple","00:1e:c2":"Apple","00:1f:f3":"Apple",
    "00:23:32":"Apple","00:23:6c":"Apple","00:25:bc":"Apple","00:26:bb":"Apple",
    "00:30:65":"Apple","00:3e:e1":"Apple","04:0c:ce":"Apple","04:d3:b0":"Apple",
    "08:66:98":"Apple","0c:30:21":"Apple","0c:74:c2":"Apple","10:93:e9":"Apple",
    "14:7d:da":"Apple","14:99:e2":"Apple","18:65:90":"Apple","1c:36:bb":"Apple",
    "20:2c:f8":"Apple","28:37:37":"Apple","2c:be:eb":"Apple","34:36:3b":"Apple",
    "34:c9:3d":"Apple","38:c9:86":"Apple","3c:15:c2":"Apple","3c:22:fb":"Apple",
    "40:a6:d9":"Apple","44:00:10":"Apple","44:d8:84":"Apple","48:43:7c":"Apple",
    "48:60:bc":"Apple","48:e1:5c":"Apple","4c:32:75":"Apple","58:55:ca":"Apple",
    "5c:ad:cf":"Apple","60:33:4b":"Apple","60:66:ab":"Apple","60:d9:20":"Apple",
    "64:76:ba":"Apple","68:5b:35":"Apple","68:ae:20":"Apple","6c:70:9f":"Apple",
    "70:14:a6":"Apple","70:3e:ac":"Apple","70:cd:60":"Apple","74:e1:b6":"Apple",
    "78:4f:43":"Apple","7c:04:d0":"Apple","7c:11:be":"Apple","7c:6a:8d":"Apple",
    "80:be:05":"Apple","84:38:35":"Apple","84:89:ad":"Apple","88:08:4a":"Apple",
    "88:53:2e":"Apple","88:66:5a":"Apple","8c:2d:aa":"Apple","90:84:0d":"Apple",
    "90:b0:ed":"Apple","94:bf:2d":"Apple","98:01:a7":"Apple","98:fe:94":"Apple",
    "9c:20:7e":"Apple","a4:d1:d2":"Apple","a8:51:ab":"Apple","ac:29:3a":"Apple",
    "ac:61:75":"Apple","b0:65:bd":"Apple","b4:8c:9d":"Apple","b8:86:87":"Apple",
    "bc:92:6b":"Apple","c0:cb:38":"Apple","c4:2b:2c":"Apple","c8:59:c3":"Apple",
    "cc:08:fb":"Apple","cc:20:e8":"Apple","cc:78:3f":"Apple","d0:a6:37":"Apple",
    "d4:61:da":"Apple","d8:a2:5e":"Apple","dc:2b:2a":"Apple","dc:37:14":"Apple",
    "e0:3e:4c":"Apple","e0:f8:47":"Apple","e4:e0:a6":"Apple","e8:b2:4a":"Apple",
    "ec:35:86":"Apple","f0:18:98":"Apple","f0:9a:3e":"Apple","f4:0f:24":"Apple",
    "f4:5c:89":"Apple","f4:cf:a2":"Apple","f8:1e:df":"Apple","f8:1a:67":"Apple",
    "fc:fc:48":"Apple","fc:e9:98":"Apple","ac:bc:32":"Samsung","b0:d5:9e":"Samsung",
    "c8:56:80":"Samsung","04:e5:36":"Samsung","9c:4e:8e":"Samsung","90:b6:86":"Samsung",
    "58:a0:6f":"Samsung","00:12:47":"Samsung","a4:90:05":"Samsung","b8:d7:af":"Samsung",
    "c8:94:02":"Samsung","00:1e:72":"Google","a4:77:33":"Google","bc:e9:2f":"Google",
    "c8:86:90":"Google","d4:f0:2a":"Google","ac:8e:8b":"Google","00:1a:64":"Google",
    "e0:2c:f4":"Google","7c:c5:37":"Google","00:3c:8b":"Google","a8:bb:50":"Google",
    "fc:5b:26":"Google","fc:4a:e9":"Google","f8:8c:21":"Google",
    "00:0a:27":"Apple","00:0a:95":"Apple","00:0d:93":"Apple",
    "00:0e:a6":"Apple","00:11:24":"Apple","00:13:1a":"Apple",
    "00:14:51":"Apple","00:19:60":"Apple","00:1b:63":"Apple",
    "00:1d:4f":"Apple","00:1e:52":"Apple","00:1f:5b":"Apple",
    "00:1f:f3":"Apple","00:20:1a":"Apple","00:21:e9":"Apple",
    "00:22:4c":"Apple","00:23:32":"Apple","00:23:6c":"Apple",
    "00:24:9b":"Apple","00:25:00":"Apple","00:25:4b":"Apple",
    "00:25:bc":"Apple","00:26:08":"Apple","00:26:4a":"Apple",
    "00:26:b0":"Apple","00:26:bb":"Apple","00:30:65":"Apple",
    "00:3e:e1":"Apple","00:3f:2e":"Apple","04:0c:ce":"Apple",
    "04:d3:b0":"Apple","04:f1:3e":"Apple","08:66:98":"Apple",
    "08:74:02":"Apple","08:9b:00":"Apple","0c:30:21":"Apple",
    "0c:74:c2":"Apple","0c:77:1a":"Apple","0c:9d:92":"Apple",
    "10:40:f3":"Apple","10:93:e9":"Apple","14:10:9f":"Apple",
    "14:5a:5d":"Apple","14:7d:da":"Apple","14:99:e2":"Apple",
    "14:c0:cc":"Apple","18:65:90":"Apple","18:82:aa":"Apple",
    "18:ee:69":"Apple","1c:36:bb":"Apple","1c:9a:3b":"Apple",
    "1c:ab:a7":"Apple","20:2c:f8":"Apple","20:7d:74":"Apple",
    "20:9a:0f":"Apple","20:c9:5e":"Apple","24:1e:eb":"Apple",
    "24:a0:74":"Apple","24:bc:82":"Apple","28:37:37":"Apple",
    "28:98:7b":"Apple","28:cf:da":"Apple","2c:20:5b":"Apple",
    "2c:be:eb":"Apple","30:10:e4":"Apple","30:f7:2e":"Apple",
    "34:15:9e":"Apple","34:36:3b":"Apple","34:59:9c":"Apple",
    "34:a3:95":"Apple","34:c9:3d":"Apple","38:c9:86":"Apple",
    "38:f7:3d":"Apple","3c:07:54":"Apple","3c:15:c2":"Apple",
    "3c:22:fb":"Apple","3c:a5:38":"Apple","3c:e9:0e":"Apple",
    "40:38:05":"Apple","40:6c:8f":"Apple","40:a6:d9":"Apple",
    "40:d3:96":"Apple","40:dc:8b":"Apple","44:00:10":"Apple",
    "44:2c:05":"Apple","44:d8:84":"Apple","48:43:7c":"Apple",
    "48:60:bc":"Apple","48:8d:36":"Apple","48:e1:5c":"Apple",
    "4c:32:75":"Apple","4c:6b:e8":"Apple","4c:7c:5f":"Apple",
    "4c:8d:79":"Apple","50:20:38":"Apple","50:a6:7f":"Apple",
    "50:ed:78":"Apple","54:52:00":"Apple","58:55:ca":"Apple",
    "58:8b:f3":"Apple","5c:02:72":"Apple","5c:ad:cf":"Apple",
    "5c:e9:cb":"Apple","60:04:0a":"Apple","60:33:4b":"Apple",
    "60:66:ab":"Apple","60:72:58":"Apple","60:d9:20":"Apple",
    "60:f6:77":"Apple","64:09:80":"Apple","64:76:ba":"Apple",
    "64:a6:51":"Apple","68:09:27":"Apple","68:5b:35":"Apple",
    "68:ae:20":"Apple","68:db:f5":"Apple","6c:70:9f":"Apple",
    "6c:96:cf":"Apple","6c:c2:6b":"Apple","70:14:a6":"Apple",
    "70:3e:ac":"Apple","70:cd:60":"Apple","74:23:44":"Apple",
    "74:e1:b6":"Apple","74:e5:0b":"Apple","78:4f:43":"Apple",
    "78:7b:8a":"Apple","7c:04:d0":"Apple","7c:0a:0c":"Apple",
    "7c:11:be":"Apple","7c:6a:8d":"Apple","7c:b7:3c":"Apple",
    "7c:d1:c3":"Apple","80:be:05":"Apple","80:d4:e2":"Apple",
    "84:38:35":"Apple","84:72:67":"Apple","84:89:ad":"Apple",
    "84:9d:aa":"Apple","84:b2:3f":"Apple","88:08:4a":"Apple",
    "88:1f:a1":"Apple","88:45:63":"Apple","88:53:2e":"Apple",
    "88:66:5a":"Apple","8c:2d:aa":"Apple","8c:58:77":"Apple",
    "8c:7b:9d":"Apple","90:72:40":"Apple","90:84:0d":"Apple",
    "90:b0:ed":"Apple","90:fd:61":"Apple","94:43:e1":"Apple",
    "94:bf:2d":"Apple","94:c6:91":"Apple","98:01:a7":"Apple",
    "98:fe:94":"Apple","9c:04:eb":"Apple","9c:20:7e":"Apple",
    "9c:35:5b":"Apple","9c:8e:99":"Apple","9c:b6:54":"Apple",
    "9c:d2:4b":"Apple","a0:54:30":"Apple","a0:63:1b":"Apple",
    "a0:99:9b":"Apple","a0:ed:cd":"Apple","a4:31:35":"Apple",
    "a4:5e:60":"Apple","a4:6b:b6":"Apple","a4:d1:d2":"Apple",
    "a8:51:ab":"Apple","a8:5b:78":"Apple","a8:86:dd":"Apple",
    "a8:be:3a":"Apple","a8:fa:5d":"Apple","ac:29:3a":"Apple",
    "ac:37:43":"Apple","ac:61:75":"Apple","b0:34:95":"Apple",
    "b0:4b:0b":"Apple","b0:65:bd":"Apple","b4:39:d6":"Apple",
    "b4:8c:9d":"Apple","b4:8e:53":"Apple","b4:f0:ab":"Apple",
    "b8:0b:9d":"Apple","b8:4d:8c":"Apple","b8:86:87":"Apple",
    "b8:e8:56":"Apple","bc:4a:56":"Apple","bc:92:6b":"Apple",
    "c0:35:7a":"Apple","c0:5c:ee":"Apple","c0:63:3c":"Apple",
    "c0:cb:38":"Apple","c4:2b:2c":"Apple","c4:5b:2c":"Apple",
    "c4:7c:8d":"Apple","c4:b3:1c":"Apple","c8:59:c3":"Apple",
    "c8:b9:3e":"Apple","cc:08:fb":"Apple","cc:20:e8":"Apple",
    "cc:78:3f":"Apple","cc:c1:92":"Apple","d0:03:4b":"Apple",
    "d0:a6:37":"Apple","d0:e1:8a":"Apple","d4:08:38":"Apple",
    "d4:61:da":"Apple","d4:0f:86":"Apple","d8:0d:3e":"Apple",
    "d8:1a:5e":"Apple","d8:2d:e1":"Apple","d8:30:62":"Apple",
    "d8:96:95":"Apple","d8:a2:5e":"Apple","dc:2b:2a":"Apple",
    "dc:37:14":"Apple","dc:86:8b":"Apple","dc:9b:9c":"Apple",
    "e0:2e:4d":"Apple","e0:3e:4c":"Apple","e0:52:1a":"Apple",
    "e0:69:95":"Apple","e0:7d:ea":"Apple","e0:ac:cb":"Apple",
    "e0:b9:a5":"Apple","e0:f8:47":"Apple","e4:06:e6":"Apple",
    "e4:5a:a6":"Apple","e4:7c:f9":"Apple","e4:a7:a0":"Apple",
    "e4:e0:a6":"Apple","e8:07:bf":"Apple","e8:2a:ea":"Apple",
    "e8:50:e3":"Apple","e8:b2:4a":"Apple","e8:c1:13":"Apple",
    "e8:c7:5f":"Apple","e8:f1:b0":"Apple","ec:26:ca":"Apple",
    "ec:35:86":"Apple","ec:85:2f":"Apple","ec:ad:b8":"Apple",
    "f0:03:34":"Apple","f0:18:98":"Apple","f0:4b:6a":"Apple",
    "f0:5c:19":"Apple","f0:9a:3e":"Apple","f0:c1:1b":"Apple",
    "f0:db:e2":"Apple","f4:0f:24":"Apple","f4:31:c3":"Apple",
    "f4:5c:89":"Apple","f4:5c:ab":"Apple","f4:cf:a2":"Apple",
    "f4:d1:08":"Apple","f8:05:1a":"Apple","f8:1a:67":"Apple",
    "f8:1e:df":"Apple","f8:4f:57":"Apple","f8:8c:21":"Apple",
    "f8:e9:03":"Apple","fc:14:ea":"Apple","fc:25:3f":"Apple",
    "fc:40:9a":"Apple","fc:e9:98":"Apple","fc:fc:48":"Apple",
}

MITM_ADDON = os.path.expanduser("~/.lanhack_mitm_addon.py")
