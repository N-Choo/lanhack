# LANHACK

A terminal-based LAN manipulation toolkit with a modern TUI. ARP spoof, block devices, spy on traffic, inject latency, and block domains — all from a mouse-clickable interface.

## Screenshots

<p align="center">
  <img src="img/device_page.png" alt="Device List" width="700">
  <br><em>Device scan with block/spy controls</em>
</p>

<table>
  <tr>
    <td align="center" width="50%">
      <img src="img/attacks_page.png" alt="Attacks Tab" style="max-width: 100%; height: auto;">
      <br><em>Quick attacks: Discord/Steam/Lag and block by domain</em>
    </td>
    <td align="center" width="50%">
      <img src="img/monitor_page.png" alt="Live Monitor" style="max-width: 100%; height: auto;">
      <br><em>Live website monitor — see every domain targets visit in real time</em>
    </td>
  </tr>
</table>

## Features

- **LAN Scan** — discover all devices on your network (IP, MAC, vendor, hostname)
- **Block/Unblock** — cut internet access for any device via ARP spoof
- **Spy Mode** — ARP-spoof a target without blocking, see every site they visit
- **Live Monitor** — real-time capture of DNS queries and TLS handshakes across all spied devices
- **Quick Attacks** — one-click Discord/Steam blocking via iptables, latency injection via `tc`
- **Block by Domain** — resolve any domain to IPs and block them (FORWARD + OUTPUT chains)
- **Open Captured Sites** — click any captured domain to open in browser (with CDN→main site mapping)
- **Active Spies List** — shows which IPs are currently being monitored
- **MAC Toggle** — show/hide MAC addresses in the device table
- **Configurable Interface** — set the network interface at runtime

## Requirements

- Linux (uses `/proc/net/route`, `iptables`, `tc`)
- Python 3.10+
- Root access (`sudo`)

## Quick Start

```bash
git clone https://github.com/N-Choo/lanhack.git
cd lanhack
sudo python3 lanhack.py
```

Dependencies (`scapy`, `textual`) auto-install on first run.

## Usage

| Tab | What it does |
|-----|-------------|
| **Monitor** | Live website stream from spied devices |
| **Devices** | Scan LAN, set interface, block/spy by IP, toggle MAC |
| **Attacks** | Discord/Steam/Lag toggles, device actions, block by domain |
| **Sites** | Captured domains, click to open in browser |

### Workflow

1. Open **Devices** tab → set Interface if needed → click **Scan LAN**
2. Click a device row to load its IP, or type one manually
3. Click **Spy** → their traffic routes through your machine
4. Switch to **Monitor** tab → see every website they visit in real time
5. Use **Attacks** tab to block Discord, Steam, or add lag

### Block by Domain

```
Type "discord.com" → click "Block Domain"
→ resolves to live IPs → blocks FORWARD + OUTPUT via iptables
```

## How It Works

LANHACK uses **ARP spoofing** to redirect a target's traffic through your machine. The `scapy` sniffer captures DNS queries and TLS Server Name Indication (SNI) from the forwarded traffic, showing every domain the target visits — even for HTTPS sites.

For blocking, it inserts `iptables` rules at position 1 (before Docker chains) on both the FORWARD and OUTPUT chains.

Latency attacks use `tc` (traffic control) to add jitter, packet loss, and bandwidth throttling.

## Limitations

- ARP spoofing is detectable on networks with DAI / port security
- You must keep the app running to maintain blocks and spies
- Only outgoing DNS queries are captured (not full HTTPS paths)
- HTTPS decryption requires installing a custom CA on the target device

## License

MIT
