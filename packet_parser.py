# packet_parser.py
import dpkt
import socket

def inet_to_str(inet):
    """Convert inet object to a readable IP string."""
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntoa(inet)
    except Exception:
        return None

def parse_pcap(filepath, max_packets=None):
    """
    Parse a pcap file and extract IPv4 packet headers.
    Returns a list of dictionaries.
    """
    packets = []

    with open(filepath, 'rb') as f:
        try:
            pcap = dpkt.pcap.Reader(f)
        except Exception as e:
            print("Error reading pcap:", e)
            return packets

        count = 0
        for ts, buf in pcap:
            if max_packets and count >= max_packets:
                break
            count += 1

            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except Exception:
                continue

            # Only process IPv4 packets
            if not isinstance(eth.data, dpkt.ip.IP):
                continue

            ip = eth.data

            pkt = {
                'pkt_id': len(packets) + 1,
                'ts': ts,
                'src_ip': inet_to_str(ip.src),
                'dst_ip': inet_to_str(ip.dst),
                'version': ip.v,
                'ihl': ip.hl,
                'tos': ip.tos,
                'total_length': ip.len,
                'id': ip.id,
                'flags': ip.off >> 13,
                'frag_offset': ip.off & 0x1FFF,
                'ttl': ip.ttl,
                'protocol': ip.p,
                'checksum': ip.sum,
                'options': ip.opts.hex() if ip.opts else None,
                'payload_len': len(ip.data) if ip.data else 0,
                'raw_bytes': buf.hex()[:200]  # first 100 bytes (200 hex chars)
            }

            packets.append(pkt)

    return packets
