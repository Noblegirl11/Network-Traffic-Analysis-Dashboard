from scapy.all import sniff, wrpcap, IP, TCP, UDP
from collections import defaultdict
import time

PCAP_FILE = "/Volumes/Thrisha SSD/captured_packets.pcap"

# Dictionaries for analysis
packet_counts = defaultdict(int)  # Counts packets per destination IP (for DDoS detection)
port_scans = defaultdict(set)    # Tracks ports scanned by source IP (for port scan detection)
timestamps = []                  # Tracks packet timestamps for traffic spike detection

# Threshold values for detecting attacks
DDOS_THRESHOLD = 100           # Packets per second to flag DDoS
PORT_SCAN_THRESHOLD = 5        # Number of ports scanned in a short time to flag port scan
TRAFFIC_SPIKE_THRESHOLD = 100  # Packets per 5 seconds to flag traffic spike

# Packet processing function
def packet_callback(packet):
    current_time = int(time.time())
    timestamps.append(current_time)

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # DDoS Detection
        packet_counts[dst_ip] += 1
        if packet_counts[dst_ip] > DDOS_THRESHOLD:
            print(f"[!] Potential DDoS attack detected! Target IP: {dst_ip}")

        # Port Scan Detection
        if TCP in packet or UDP in packet:
            dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport
            port_scans[src_ip].add(dst_port)
            if len(port_scans[src_ip]) > PORT_SCAN_THRESHOLD:
                print(f"[!] Port scan detected from IP: {src_ip}")

        # Traffic Spike Detection
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

        # Save packet to PCAP file
        wrpcap(PCAP_FILE, packet, append=True)

# Start sniffing
print(f"Starting packet sniffing... Saving to {PCAP_FILE}")
sniff(iface="en0", prn=packet_callback, store=False)
