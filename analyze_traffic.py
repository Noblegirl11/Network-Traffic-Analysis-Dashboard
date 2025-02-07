from collections import defaultdict
from scapy.all import rdpcap, IP, TCP, UDP
import time

# Path to the captured packets file
PCAP_FILE = "/Volumes/Thrisha SSD/captured_packets.pcap"

# Dictionaries for analysis
packet_counts = defaultdict(int)
port_scans = defaultdict(set)
timestamps = []

# Thresholds for attack detection
DDOS_THRESHOLD = 100
PORT_SCAN_THRESHOLD = 5
TRAFFIC_SPIKE_THRESHOLD = 100

def analyze_traffic():
    packets = rdpcap(PCAP_FILE)
    for packet in packets:
        current_time = int(time.time())
        timestamps.append(current_time)

        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            # DDoS detection
            packet_counts[dst_ip] += 1
            if packet_counts[dst_ip] > DDOS_THRESHOLD:
                print(f"[!] Potential DDoS attack detected! Target IP: {dst_ip}")

            # Port scan detection
            if TCP in packet or UDP in packet:
                dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport
                port_scans[src_ip].add(dst_port)
                if len(port_scans[src_ip]) > PORT_SCAN_THRESHOLD:
                    print(f"[!] Port scan detected from IP: {src_ip}")

            # Traffic spike detection
            if len([ts for ts in timestamps if ts > current_time - 5]) > TRAFFIC_SPIKE_THRESHOLD:
                print(f"[!] Traffic spike detected!")

            # Print packet summary
            print(f"\n[+] Packet Captured: {packet.summary()}")
            print(f"    Source IP: {src_ip}")
            print(f"    Destination IP: {dst_ip}")
            if TCP in packet:
                print(f"    Protocol: TCP | Src Port: {packet[TCP].sport} | Dst Port: {packet[TCP].dport}")
            elif UDP in packet:
                print(f"    Protocol: UDP | Src Port: {packet[UDP].sport} | Dst Port: {packet[UDP].dport}")

if __name__ == "__main__":
    analyze_traffic()
