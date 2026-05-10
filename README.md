# LANHACK

A terminal-based LAN manipulation toolkit with a modern TUI. ARP spoof, block devices, spy on traffic, inject latency, harvest credentials, and block domains — all from a mouse-clickable interface.

<p align="center">
  <img src="img/lanhack_demo.gif" alt="LANHACK Demo" width="700">
  <br><em>Scan, spy, and monitor in real time — all from a terminal TUI</em>
</p>

## Features

| Category | Feature | Description |
|----------|---------|-------------|
| **Recon** | LAN Scan | Discover all devices (IP, MAC, vendor, hostname) |
| | Device Fingerprinting | Scan open ports to identify device type (Windows, Samsung TV, IoT, etc.) |
| | Auto-Scan | Continuously scan every 30s, detect new devices automatically |
| **Interception** | Spy Mode | ARP-spoof a target without blocking; see every site they visit |
| | Live Monitor | Real-time DNS query and TLS SNI capture across all spied devices |
| | Traffic Graphs | Bar charts for bandwidth per device and top domains |
| | HTTPS Interception (DEMO) | Full HTTPS decryption via mitmproxy (target must trust CA) |
| **Blocking** | Device Block | Cut internet for any device via ARP + iptables (MAC-based, survives DHCP) |
| | Domain Block | Resolve domain to IPs and block FORWARD + OUTPUT chains |
| | Global DNS Block | DNS sinkhole via iptables redirect — blocks every device on the LAN |
| | Quick Blocks | One-click Discord and Steam blocking |
| **Credential Harvest** | HTTP Harvester | Inject JS into HTTP pages to capture form submissions and passwords |
| | HTTPS Credential Extraction | Auto-log POST/PUT bodies containing password/login/token fields |
| **Disruption** | Lag Attack | Add 500ms latency + 5% packet loss to any device via `tc` |
| | Stealth Mode | Randomize ARP intervals (1.2–3.1s) to evade detection |
| **Utility** | Wake-on-LAN | Wake sleeping devices before spying |
| | Export Captures | Save all captured domains and credentials to CSV + JSON |
| | Open Captured Sites | Click any captured domain to open in browser (CDN→main site mapping) |
| | MAC Toggle | Show/hide MAC addresses in the device table |
| | Interface Config | Change network interface at runtime |

## Requirements

- Linux (uses `/proc/net/route`, `iptables`, `tc`, `ip`)
- Python 3.10+
- Root access (`sudo`)

## Quick Start

```bash
git clone https://github.com/N-Choo/lanhack.git
cd lanhack
sudo python3 lanhack.py
```

Dependencies (`scapy`, `textual`, `mitmproxy`) auto-install on first run.

## Tab Reference

| Tab | What it does |
|-----|-------------|
| **Monitor** | Live website stream from spied devices; switch between list view and traffic graphs |
| **Devices** | Scan LAN, set interface/fingerprint, enter target IP, block/spy/WoL, auto-scan, MAC toggle |
| **Attacks** | Quick toggles (Discord/Steam/Lag), device actions (block/unblock/spy by IP), domain block, global DNS, stealth, HTTPS interception, credential harvester |
| **Sites** | Captured domains list; click to open in browser; export to CSV+JSON |

## Complete Workflow Guide

### Basic Surveillance

```
1. Devices tab → Scan LAN
2. Click a device row (loads its IP)
3. Click Spy → traffic routes through your machine
4. Monitor tab → watch every site they visit in real time
5. Sites tab → browse or export captured domains
```

### Full Attack Chain (recon → spy → disrupt → harvest)

```
1. Devices → Scan LAN
2. Devices → Fingerprint (identify what each device is)
3. Devices → Auto Scan (keep detecting new devices)
4. Devices → click target → Spy
5. Monitor → watch live traffic (or switch to Graphs)
6. Attacks → Lag Attack (add latency to frustrate target)
7. Attacks → Block Domain → "discord.com" (block their distractions)
8. Attacks → HTTPS Intercept (target installs CA once → full URL visibility)
9. Attacks → Harvester (capture HTTP form submissions)
10. Attacks → View Captured (see all credentials)
11. Sites → Export (save everything to CSV+JSON)
```

### Stealthy Passive Recon (no packets sent)

```
1. Enable Global DNS Block → starts DNS sinkhole on port 53
2. All LAN DNS traffic is intercepted without ARP spoofing
3. Zero packets sent to target devices — completely invisible
4. Monitor tab shows domains queried by every device
```

### Blocking Discord/Steam for Everyone

```
Method 1 — Quick (needs app running):
  Attacks → Block Discord + Block Steam (adds iptables rules)
  Also toggle Global DNS Block for DNS-level blocking

Method 2 — Permanent:
  Use the built-in Global DNS Block or set up Pi-hole on your network
```

## Feature Details

### Credential Harvester

Two modes, both toggled from the **Attacks** tab:

**HTTP Harvester** (no CA needed, works immediately):
1. Toggle **Harvester** ON — redirects all port 80 traffic through a local Python proxy
2. The proxy injects JavaScript into every HTML page that monitors password fields and form submissions
3. Works on any HTTP site — old routers, IoT dashboards, internal network pages
4. Click **View Captured** to see the last 10 entries

**HTTPS Credential Extraction** (requires HTTPS Interception):
1. Toggle **HTTPS Intercept** ON (target must trust the CA once)
2. mitmproxy loads an addon that scans ALL decrypted POST/PUT bodies
3. Automatically logs any request containing: `password`, `login`, `token`, `secret`, `api_key`, `credit`
4. Results saved to `/tmp/lanhack_creds.txt`

**Combined workflow for maximum coverage:**
```
1. Enable HTTPS Intercept → target trusts CA → all HTTPS decrypted
2. Enable Harvester → all HTTP gets JS injected
3. Both credential sources captured simultaneously
4. Click View Captured to see everything
```

### HTTPS Interception (DEMO)

Toggle in the **Attacks** tab. Auto-installs `mitmproxy`, generates a CA certificate, and redirects all HTTP/HTTPS traffic through it via iptables.

**To use:** the target device must download and trust the CA certificate at `~/.mitmproxy/mitmproxy-ca.pem` (or navigate to `mitm.it` while interception is active). After trust is installed, every HTTPS URL becomes visible — paths, query parameters, and POST data.

**Limitations:** certificate-pinned apps and modern browsers with HSTS preload still show warnings. Requires target cooperation for full HTTPS visibility.

### Device Fingerprinting

After scanning, click **Fingerprint** in the Devices tab. LANHACK sends SYN packets to 15 common ports and matches open port patterns:

| Ports | Likely Device |
|-------|--------------|
| 135, 139, 445 | Windows |
| 22 | Linux/SSH |
| 3689, 62078 | macOS/iOS |
| 7000, 7676 | Samsung TV |
| 554 (RTSP) | IP Camera |
| 8883 (MQTT) | IoT Device |
| 80, 443 | Web Server |

Results appear in the "Fingerprint" column.

### Traffic Graphs

In the **Monitor** tab, click **Graphs** to switch from the site log to live bar charts:
- **Bandwidth per device** — top 5 devices by KB transferred (last 30 packets)
- **Top domains** — most visited domains ranked by hit count
- Updates every 2 seconds. Click **List View** to switch back.

### Auto-Scan

Click **Auto Scan** in the Devices tab — scans your subnet every 30 seconds and silently merges new devices into the existing list. Shows a notification when a previously unseen device joins. Click again to stop.

### Wake-on-LAN

Select a device row or type its IP, then click **WoL** — sends a magic packet to wake a sleeping device before spying or blocking.

### Stealth Mode

Toggle in the Attacks tab. ARP spoof packets use randomized intervals (1.2–3.1s) instead of a fixed 1.5s pattern, blending in with normal network chatter to evade tools like `arpwatch`.

### Global DNS Block

Toggle in the Attacks tab. Starts a Python DNS server on port 53 and redirects all LAN DNS traffic to it via `iptables -t nat -I PREROUTING`. Domains in the blocklist resolve to `127.0.0.1`; everything else forwards to Cloudflare (1.1.1.1). No ARP spoof needed — every device on the network is blocked at the DNS level.

### Export Captures

In the **Sites** tab, click **Export CSV+JSON** — saves all captured domains (timestamps, device IPs, site URLs) and harvested credentials to:
- `lanhack_export_{timestamp}.csv` (opens in Excel/Sheets)
- `lanhack_export_{timestamp}.json` (machine-readable)

### Block by Domain

```
Type "discord.com" → click "Block Domain"
→ resolves to live IPs → blocks FORWARD + OUTPUT via iptables
→ also blocks via Global DNS if that's active
```

## How It Works

LANHACK uses **ARP spoofing** to redirect a target's traffic through your machine. The `scapy` sniffer captures DNS queries and TLS SNI from the forwarded traffic, showing every domain the target visits — even for HTTPS sites.

For blocking, it inserts `iptables` rules at position 1 (before Docker chains) on FORWARD and OUTPUT chains, using MAC addresses to survive DHCP IP changes.

The **Global DNS Block** runs a slim Python DNS server on port 53 that checks each query against the blocklist, returning `127.0.0.1` for blocked domains and forwarding everything else to Cloudflare.

**Credential harvesting** uses two methods:
- HTTP: redirect port 80 to a Python proxy that injects JS into HTML pages
- HTTPS: mitmproxy addon scans decrypted POST/PUT bodies for credential patterns

**Stealth mode** randomizes ARP timing to reduce detectability. **Latency attacks** use `tc` (traffic control) to add jitter, loss, and throttling.

## Limitations

- ARP spoofing is detectable on networks with DAI / port security
- You must keep the app running to maintain blocks and spies
- Only outgoing DNS queries captured (not full HTTPS paths without HTTPS Intercept)
- HTTPS decryption requires installing a custom CA on the target device
- Credential harvester only works on HTTP without HTTPS Intercept enabled

## License

MIT
