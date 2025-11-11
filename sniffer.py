import socket
import struct
import textwrap
import argparse
import time
import json
from collections import Counter, defaultdict, deque

def mac_addr(raw: bytes) -> str:
    return ':'.join(f'{b:02x}' for b in raw)

def ipv4_addr(raw: bytes) -> str:
    return '.'.join(str(b) for b in raw)

def hexdump(src: bytes, length=16):
    # simple hex + ascii view for payload
    result = []
    for i in range(0, len(src), length):
        chunk = src[i:i+length]
        hexa = ' '.join(f'{b:02x}' for b in chunk)
        text = ''.join((chr(b) if 32 <= b < 127 else '.') for b in chunk)
        result.append(f'{i:04x}   {hexa:<{length*3}}   {text}')
    return '\n'.join(result)

def parse_ethernet_frame(data: bytes):
    # Ethernet header is 14 bytes: dst(6) src(6) ethertype(2)
    if len(data) < 14:
        return None
    dst, src, proto = struct.unpack('!6s6sH', data[:14])
    return {
        'dst_mac': mac_addr(dst),
        'src_mac': mac_addr(src),
        'ethertype': proto,
        'payload': data[14:],
    }

def parse_ipv4_packet(data: bytes):
    # IPv4 header: variable length, min 20 bytes
    if len(data) < 20:
        return None
    ver_ihl, tos, total_length, identification, flags_frag, ttl, proto, checksum, src, dst = struct.unpack('!BBHHHBBH4s4s', data[:20])
    version = ver_ihl >> 4
    ihl = (ver_ihl & 0x0F) * 4
    # options + payload
    if len(data) < ihl:
        return None
    payload = data[ihl:total_length]
    return {
        'version': version,
        'ihl': ihl,
        'tos': tos,
        'total_length': total_length,
        'id': identification,
        'flags_frag': flags_frag,
        'ttl': ttl,
        'protocol': proto,
        'checksum': checksum,
        'src_ip': ipv4_addr(src),
        'dst_ip': ipv4_addr(dst),
        'payload': payload,
    }

def parse_tcp_segment(data: bytes):
    if len(data) < 20:
        return None
    src_port, dst_port, seq, ack, offset_reserved_flags, window, checksum, urg_ptr = struct.unpack('!HHLLHHHH', data[:20])
    offset = (offset_reserved_flags >> 12) * 4
    flags = offset_reserved_flags & 0x01FF  # last 9 bits are flags
    payload = data[offset:]
    # decode common flags:
    flag_map = {
        'ns': (flags >> 8) & 0x1,
        'cwr': (flags >> 7) & 0x1,
        'ece': (flags >> 6) & 0x1,
        'urg': (flags >> 5) & 0x1,
        'ack': (flags >> 4) & 0x1,
        'psh': (flags >> 3) & 0x1,
        'rst': (flags >> 2) & 0x1,
        'syn': (flags >> 1) & 0x1,
        'fin': flags & 0x1,
    }
    return {
        'src_port': src_port,
        'dst_port': dst_port,
        'seq': seq,
        'ack': ack,
        'offset': offset,
        'flags': flag_map,
        'window': window,
        'checksum': checksum,
        'urg_ptr': urg_ptr,
        'payload': payload,
    }

def parse_udp_segment(data: bytes):
    if len(data) < 8:
        return None
    src_port, dst_port, length, checksum = struct.unpack('!HHHH', data[:8])
    payload = data[8:length]
    return {
        'src_port': src_port,
        'dst_port': dst_port,
        'length': length,
        'checksum': checksum,
        'payload': payload,
    }
class Sniffer:
    def __init__(self, iface=None, log_path=None, stats_interval=5, max_packets=None):
        self.iface = iface
        self.log_path = log_path
        self.stats_interval = stats_interval
        self.max_packets = max_packets

        # runtime stats
        self.counts = Counter()
        self.bytes_by_ip = Counter()
        self.packets_by_src = Counter()
        self.start_time = time.time()
        self._stop = False
        self.recent = deque(maxlen=50)  # store last 50 parsed packets for quick view

        self.sock = None

    def open_socket(self):
        # Linux: AF_PACKET raw socket receives whole Ethernet frames
        try:
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            if self.iface:
                self.sock.bind((self.iface, 0))
        except PermissionError:
            raise PermissionError("Root privileges are required to open raw sockets. Use sudo.")
        except Exception as e:
            raise RuntimeError(f"Cannot open raw socket on this platform/interface: {e}")

    def _log(self, record):
        if not self.log_path:
            return
        with open(self.log_path, 'a') as f:
            f.write(json.dumps(record) + '\n')

    def print_packet(self, record):
        # pretty print one parsed record to console
        ts = record['timestamp']
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))}] {record['eth']['src_mac']} -> {record['eth']['dst_mac']}  prot=0x{record['eth']['ethertype']:04x}")
        if 'ip' in record and record['ip']:
            ip = record['ip']
            print(f"    IPv4: {ip['src_ip']} -> {ip['dst_ip']}  proto={ip['protocol']} ttl={ip['ttl']} len={ip['total_length']}")
            if 'tcp' in record and record['tcp']:
                tcp = record['tcp']
                flags = ','.join([k for k,v in tcp['flags'].items() if v])
                print(f"      TCP: {tcp['src_port']} -> {tcp['dst_port']}  seq={tcp['seq']} ack={tcp['ack']} flags={flags} payload={len(tcp['payload'])}B")
            elif 'udp' in record and record['udp']:
                udp = record['udp']
                print(f"      UDP: {udp['src_port']} -> {udp['dst_port']}  len={udp['length']} payload={len(udp['payload'])}B")
            else:
                print(f"      L4 payload: {len(ip['payload'])} bytes")
        else:
            print(f"    Non-IPv4 or truncated payload: {len(record['eth']['payload'])} bytes")
        print('-'*72)

    def print_stats(self):
        elapsed = time.time() - self.start_time
        print("\n=== Stats (elapsed {:.1f}s) ===".format(elapsed))
        print("Packets by protocol:", dict(self.counts))
        top_src = self.packets_by_src.most_common(5)
        print("Top source IPs:", top_src)
        top_bytes = self.bytes_by_ip.most_common(5)
        print("Top bytes by IP:", top_bytes)
        print('='*36 + '\n')

    def run(self):
        self.open_socket()
        pkt_seen = 0
        last_stats = time.time()
        print("Sniffer started. Press Ctrl+C to stop.")
        try:
            while True:
                raw_data, addr = self.sock.recvfrom(65535)
                ts = time.time()
                eth = parse_ethernet_frame(raw_data)
                if not eth:
                    continue

                record = {'timestamp': ts, 'eth': eth, 'ip': None, 'tcp': None, 'udp': None}
                # IPv4
                if eth['ethertype'] == 0x0800:
                    ip = parse_ipv4_packet(eth['payload'])
                    record['ip'] = ip
                    if ip:
                        self.counts['ipv4'] += 1
                        self.bytes_by_ip[ip['src_ip']] += ip['total_length']
                        self.packets_by_src[ip['src_ip']] += 1
                        # L4
                        if ip['protocol'] == 6:  # TCP
                            tcp = parse_tcp_segment(ip['payload'])
                            record['tcp'] = tcp
                            self.counts['tcp'] += 1
                        elif ip['protocol'] == 17:  # UDP
                            udp = parse_udp_segment(ip['payload'])
                            record['udp'] = udp
                            self.counts['udp'] += 1
                        else:
                            self.counts[f'ip-proto-{ip["protocol"]}'] += 1
                    else:
                        self.counts['ipv4-truncated'] += 1
                else:
                    # non-ip
                    self.counts[f'eth-0x{eth["ethertype"]:04x}'] += 1

                self.recent.append(record)
                pkt_seen += 1

                # print each packet (you can change printing frequency if noisy)
                self.print_packet(record)

                # log jsonl
                self._log({
                    'timestamp': ts,
                    'eth': {k:v for k,v in eth.items() if k!='payload'},
                    'ip': ({k:v for k,v in record['ip'].items() if k!='payload'} if record['ip'] else None),
                    'tcp': ({k:v for k,v in record['tcp'].items() if k!='payload'} if record['tcp'] else None),
                    'udp': ({k:v for k,v in record['udp'].items() if k!='payload'} if record['udp'] else None),
                })

                # periodic stats print
                now = time.time()
                if (now - last_stats) >= self.stats_interval:
                    self.print_stats()
                    last_stats = now

                if self.max_packets and pkt_seen >= self.max_packets:
                    print("Reached max_packets; stopping.")
                    break

        except KeyboardInterrupt:
            print("\nInterrupted by user.")
        finally:
            try:
                self.sock.close()
            except Exception:
                pass
            # final stats
            self.print_stats()


# ---------- CLI ----------
def main():
    parser = argparse.ArgumentParser(description="Lightweight Packet Sniffer (Linux)")
    parser.add_argument('--iface', '-i', help='Interface to bind to (e.g., eth0). Default: all', default=None)
    parser.add_argument('--log', '-l', help='Optional output JSONL log path', default=None)
    parser.add_argument('--stats-interval', '-s', help='How often to print stats (seconds)', type=int, default=5)
    parser.add_argument('--max-packets', '-n', help='Stop after N packets', type=int, default=None)
    args = parser.parse_args()

    sn = Sniffer(iface=args.iface, log_path=args.log, stats_interval=args.stats_interval, max_packets=args.max_packets)
    sn.run()

if __name__ == '__main__':
    main()
