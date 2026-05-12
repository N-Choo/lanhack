import socket, struct

from lanhack import config

def _match_blocked(qname, blocklist):
    labels = qname.split(".")
    for blocked in blocklist:
        block_labels = blocked.split(".")
        for i in range(len(labels) - len(block_labels) + 1):
            if labels[i:i+len(block_labels)] == block_labels:
                return True
    return False

def _dns_server_run():
    DNS_UPSTREAM = ("1.1.1.1", 53)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", 53))
        config.log("DNS server: bound to port 53")
    except OSError as e:
        config.log(f"DNS server: BIND FAILED - {e}")
        return
    sock.settimeout(1)
    config.log("DNS server: listening")
    while not config.quit_flag and not config.dns_stop:
        try:
            data, addr = sock.recvfrom(512)
            if len(data) < 12: continue
            qname_parts = []
            i = 12
            while data[i] != 0:
                length = data[i]
                qname_parts.append(data[i+1:i+1+length].decode(errors='ignore'))
                i += 1 + length
            qname = ".".join(qname_parts).lower()
            config.log(f"DNS query from {addr[0]}: {qname}")
            blocked = _match_blocked(qname, config.dns_blocklist) or _match_blocked(qname, list(config.custom_blocks.keys()))
            if blocked:
                config.log(f"DNS BLOCKED: {qname} from {addr[0]}")
                tid = struct.pack(">H", (data[0] << 8) | data[1])
                flags = struct.pack(">H", 0x8183)
                qdcount = struct.pack(">H", 1)
                ancount = struct.pack(">H", 1)
                nscount = struct.pack(">H", 0)
                arcount = struct.pack(">H", 0)
                rdata = struct.pack(">I", 0x7f000001)
                resp = tid + flags + qdcount + ancount + nscount + arcount + data[12:i+1] + struct.pack(">H",1)+struct.pack(">H",1)+struct.pack(">I",60)+struct.pack(">H",4)+rdata
                sock.sendto(resp, addr)
                config.log(f"DNS sent 127.0.0.1 for {qname}")
                config.dns_spoof_count += 1
            else:
                fwd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                fwd.settimeout(3)
                fwd.sendto(data, DNS_UPSTREAM)
                try:
                    rdata, _ = fwd.recvfrom(512)
                    sock.sendto(rdata, addr)
                except: pass
                fwd.close()
        except socket.timeout: continue
        except: continue
    sock.close()
