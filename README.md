# LANHACK

Terminal-based LAN manipulation toolkit with a modern TUI. ARP spoof, block devices, spy on traffic, inject latency, harvest credentials, and block domains.

<p align="center">
  <img src="img/lanhack_demo.gif" alt="LANHACK Demo" width="700">
</p>

## Quick Start

```bash
git clone https://github.com/N-Choo/lanhack.git
cd lanhack
sudo python3 -m lanhack
```

Dependencies (`scapy`, `textual`, `mitmproxy`) auto-install on first run.

## Tabs

| Tab | Purpose |
|-----|---------|
| **Monitor** | Live websites from spied devices; traffic graphs |
| **Devices** | LAN scan, fingerprint, block/spy/WoL, auto-scan, MAC toggle |
| **Attacks** | Discord/Steam/Lag toggles, domain block, global DNS, stealth, HTTPS intercept, harvester |
| **Sites** | Captured domains; click to open in browser; export CSV+JSON |

## How It Works

**ARP spoofing** redirects a target's traffic through your machine. The `scapy` sniffer captures DNS queries and TLS SNI, revealing every domain visited — even HTTPS.

**Blocking** uses iptables rules (FORWARD + OUTPUT chains) with MAC addresses to survive DHCP changes. All rules tracked by `IptablesManager` and cleaned up on exit.

**Global DNS Block** runs a DNS sinkhole on port 53, redirecting all LAN DNS queries. Blocked domains return `127.0.0.1`; everything else forwards to Cloudflare.

**State persisted** across restarts (`~/.lanhack_state.json`) so blocks survive crashes.

## Requirements

- Linux (`iptables`, `tc`, `ip`)
- Python 3.10+
- Root access (`sudo`)

## License

MIT
