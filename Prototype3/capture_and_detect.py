from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
import numpy as np
import time
import joblib

# Load the pre-trained anomaly detection model
model = joblib.load("anomaly_detector.pkl")

# Dictionary to store active network flows
active_flows = {}

def extract_features(flow):
    """Convert active flow into feature vector for anomaly detection."""
    return [
        flow.get('packet_count', 0),
        flow.get('byte_count', 0),
        flow.get('sbytes', 0),
        flow.get('dbytes', 0),
        flow.get('spkts', 0),
        flow.get('dpkts', 0),
        flow.get('sload', 0),
        flow.get('dload', 0),
        flow.get('source_ttl', 0),
        flow.get('dest_ttl', 0),
        flow.get('source_tcp_win', 0),
        flow.get('dest_tcp_win', 0),
        flow.get('tcprtt', 0),
        flow.get('http_methods', 0),
        flow.get('ftp_cmds', 0)
    ]

def detect_anomalies(flow_key):
    """Detect anomalies in real-time based on extracted network features."""
    flow = active_flows[flow_key]
    import pandas as pd

    # Convert extracted features into a DataFrame with column names
    feature_vector = pd.DataFrame([extract_features(flow)], columns=[
        'packet_count', 'byte_count', 'sbytes', 'dbytes', 'spkts', 'dpkts',
        'sload', 'dload', 'source_ttl', 'dest_ttl', 'source_tcp_win', 'dest_tcp_win',
        'tcprtt', 'http_methods', 'ftp_cmds'
    ])

    # Now pass the feature_vector with correct column names
    # prediction = model.predict(feature_vector)[0]

    prediction = model.predict(feature_vector)[0]  # -1 means anomaly
    print(f"Checking flow: {flow_key} → Prediction: {prediction}")  # Debug print
    if prediction == -1:
        print(f"🚨 ALERT: Anomalous flow detected! {flow_key}")
        # Implement mitigation actions here (e.g., block IP, log, alert admin)

def process_packet(packet):
    """Processes packets, extracts features, and detects anomalies in real-time."""
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

        # Initialize or update network flow statistics
        if flow_key not in active_flows:
            active_flows[flow_key] = {
                "start_time": timestamp,
                "packet_count": 0, "byte_count": 0, "sbytes": 0, "dbytes": 0,
                "spkts": 0, "dpkts": 0, "sload": 0, "dload": 0,
                "source_ttl": packet[IP].ttl, "dest_ttl": None,
                "source_tcp_win": win_size, "dest_tcp_win": None,
                "tcprtt": None, "http_methods": 0, "ftp_cmds": 0
            }

        flow = active_flows[flow_key]
        flow["packet_count"] += 1
        flow["byte_count"] += pkt_size
        if src_port:
            flow["sbytes"] += pkt_size
            flow["spkts"] += 1
        if dst_port:
            flow["dbytes"] += pkt_size
            flow["dpkts"] += 1

        # Compute traffic load
        duration = timestamp - flow["start_time"]
        if duration > 0:
            flow["sload"] = (flow["sbytes"] * 8) / duration
            flow["dload"] = (flow["dbytes"] * 8) / duration

        # Detect anomalies in real-time
        detect_anomalies(flow_key)

def capture_packets(interface="Wi-Fi", count=100):
    """Captures network packets and performs real-time anomaly detection."""
    print(f"🚀 Capturing {count} packets on {interface} with real-time anomaly detection...")
    sniff(iface=interface, prn=process_packet, count=count, store=False)

if __name__ == "__main__":
    capture_packets(interface="Wi-Fi", count=100)
