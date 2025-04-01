# # #!/usr/bin/env python
# # from scapy.all import sniff, wrpcap

# # def capture_packets(interface, packet_count, output_file):
# #     """
# #     Captures a specified number of network packets from the given interface 
# #     and saves them as a PCAP file.
# #     """
# #     packets = sniff(iface=interface, count=packet_count)
# #     wrpcap(output_file, packets)
# #     print(f"Captured {packet_count} packets on {interface} and saved to {output_file}")

# # # For macOS, typically 'en0' is the primary network interface.
# # capture_packets(interface='Wi-Fi', packet_count=1000, output_file='captured_traffic2.pcap')

# #!/usr/bin/env python
# from scapy.all import sniff, IP, TCP, UDP
# import pandas as pd
# import time

# # Dictionary to store flows
# flows = {}

# def extract_features(flow_key):
#     """Convert flow data into a feature vector."""
#     flow = flows[flow_key]
#     return {
#         'packet_count': flow.get('packet_count', 0),
#         'byte_count': flow.get('byte_count', 0),
#         'sbytes': flow.get('sbytes', 0),
#         'dbytes': flow.get('dbytes', 0),
#         'spkts': flow.get('spkts', 0),
#         'dpkts': flow.get('dpkts', 0),
#         'sload': flow.get('sload', 0),
#         'dload': flow.get('dload', 0),
#         'source_ttl': flow.get('source_ttl', 0),
#         'dest_ttl': flow.get('dest_ttl', 0),
#         'source_tcp_win': flow.get('source_tcp_win', 0),
#         'dest_tcp_win': flow.get('dest_tcp_win', 0),
#         'tcprtt': flow.get('tcprtt', 0),
#         'http_methods': flow.get('http_methods', 0),
#         'ftp_cmds': flow.get('ftp_cmds', 0)
#     }

# def process_packet(packet):
#     """Processes packets and extracts network traffic features."""
#     if IP in packet:
#         src_ip = packet[IP].src
#         dst_ip = packet[IP].dst
#         proto = packet[IP].proto
#         timestamp = time.time()
#         src_port, dst_port, pkt_size, win_size = None, None, len(packet), None

#         if TCP in packet:
#             src_port, dst_port = packet[TCP].sport, packet[TCP].dport
#             win_size = packet[TCP].window
#         elif UDP in packet:
#             src_port, dst_port = packet[UDP].sport, packet[UDP].dport

#         flow_key = (src_ip, dst_ip, src_port, dst_port, proto)

#         # Update flow statistics
#         if flow_key not in flows:
#             flows[flow_key] = {
#                 'start_time': timestamp,
#                 'packet_count': 0, 'byte_count': 0, 'sbytes': 0, 'dbytes': 0,
#                 'spkts': 0, 'dpkts': 0, 'sload': 0, 'dload': 0,
#                 'source_ttl': packet[IP].ttl, 'dest_ttl': None,
#                 'source_tcp_win': win_size, 'dest_tcp_win': None,
#                 'tcprtt': None, 'http_methods': 0, 'ftp_cmds': 0
#             }

#         flow = flows[flow_key]
#         flow['packet_count'] += 1
#         flow['byte_count'] += pkt_size
#         if src_port:
#             flow['sbytes'] += pkt_size
#             flow['spkts'] += 1
#         if dst_port:
#             flow['dbytes'] += pkt_size
#             flow['dpkts'] += 1

#         # Compute traffic rates
#         duration = timestamp - flow['start_time']
#         if duration > 0:
#             flow['sload'] = (flow['sbytes'] * 8) / duration
#             flow['dload'] = (flow['dbytes'] * 8) / duration

# def save_to_csv():
#     """Saves network flows to a CSV file."""
#     df = pd.DataFrame([extract_features(flow) for flow in flows])
#     df.to_csv("network_profile.csv", index=False)
#     print("✅ Network profile saved to network_profile.csv")

# def capture_packets(interface="Wi-Fi", count=1000):
#     """Captures network packets and extracts features."""
#     print(f"🚀 Capturing {count} packets on {interface} and saving to network_profile.csv...")
#     sniff(iface=interface, prn=process_packet, count=count, store=False)
#     save_to_csv()

# if __name__ == "__main__":
#     capture_packets(interface="Wi-Fi", count=100)


#!/usr/bin/env python
from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
import time

# Dictionary to store flows
flows = {}

def extract_features(flow_key):
    """Convert flow data into a feature vector."""
    flow = flows[flow_key]
    return {
        'packet_count': flow.get('packet_count', 0),
        'byte_count': flow.get('byte_count', 0),
        'sbytes': flow.get('sbytes', 0),
        'dbytes': flow.get('dbytes', 0),
        'spkts': flow.get('spkts', 0),
        'dpkts': flow.get('dpkts', 0),
        'sload': flow.get('sload', 0),
        'dload': flow.get('dload', 0),
        'source_ttl': flow.get('source_ttl', 0),
        'dest_ttl': flow.get('dest_ttl', 0),
        'source_tcp_win': flow.get('source_tcp_win', 0),
        'dest_tcp_win': flow.get('dest_tcp_win', 0),
        'tcprtt': flow.get('tcprtt', 0),
        'http_methods': flow.get('http_methods', 0),
        'ftp_cmds': flow.get('ftp_cmds', 0)
    }

def process_packet(packet):
    """Processes packets and extracts network traffic features."""
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        timestamp = time.time()
        src_port, dst_port, pkt_size, win_size = None, None, len(packet), None

        if TCP in packet:
            src_port, dst_port = packet[TCP].sport, packet[TCP].dport
            win_size = packet[TCP].window
        elif UDP in packet:
            src_port, dst_port = packet[UDP].sport, packet[UDP].dport

        flow_key = (src_ip, dst_ip, src_port, dst_port, proto)

        # Update flow statistics
        if flow_key not in flows:
            flows[flow_key] = {
                'start_time': timestamp,
                'packet_count': 0, 'byte_count': 0, 'sbytes': 0, 'dbytes': 0,
                'spkts': 0, 'dpkts': 0, 'sload': 0, 'dload': 0,
                'source_ttl': packet[IP].ttl, 'dest_ttl': None,
                'source_tcp_win': win_size, 'dest_tcp_win': None,
                'tcprtt': None, 'http_methods': 0, 'ftp_cmds': 0
            }

        flow = flows[flow_key]
        flow['packet_count'] += 1
        flow['byte_count'] += pkt_size
        if src_port:
            flow['sbytes'] += pkt_size
            flow['spkts'] += 1
        if dst_port:
            flow['dbytes'] += pkt_size
            flow['dpkts'] += 1

        # Compute traffic rates
        duration = timestamp - flow['start_time']
        if duration > 0:
            flow['sload'] = (flow['sbytes'] * 8) / duration
            flow['dload'] = (flow['dbytes'] * 8) / duration

def save_to_csv():
    """Saves network flows to a CSV file."""
    df = pd.DataFrame([extract_features(flow) for flow in flows])
    df.to_csv("network_profile.csv", index=False)
    print("✅ Network profile saved to network_profile.csv")

def capture_packets(interface="Wi-Fi", count=1000):
    """Continuously captures network packets and extracts features."""
    print(f"🚀 Capturing packets on {interface} until manually stopped (CTRL+C)...")
    try:
        sniff(iface=interface, prn=process_packet, store=False)
    except KeyboardInterrupt:
        print("⚠ Stopping packet capture. Saving data...")
        save_to_csv()

if __name__ == "__main__":
    capture_packets(interface="Wi-Fi")  # No count limit
