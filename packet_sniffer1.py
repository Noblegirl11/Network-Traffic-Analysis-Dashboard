import time
from scapy.all import sniff, wrpcap, IP, TCP, UDP
import os

# Save packets to external hard disk
PCAP_FILE = "/Volumes/Thrisha SSD/captured_packets1.pcap"

# Sniffing limits
PACKET_LIMIT = 100  # Stop after capturing 100 packets
TIME_LIMIT = 60  # Stop after 60 seconds

start_time = time.time()
packet_count = 0

# Function to process captured packets
def packet_callback(packet):
    global packet_count

    if IP in packet:
        print(f"\n[+] Packet Captured: {packet.summary()}")
        print(f"    Source IP: {packet[IP].src}")
        print(f"    Destination IP: {packet[IP].dst}")

        if TCP in packet:
            print(f"    Protocol: TCP | Src Port: {packet[TCP].sport} | Dst Port: {packet[TCP].dport}")
        elif UDP in packet:
            print(f"    Protocol: UDP | Src Port: {packet[UDP].sport} | Dst Port: {packet[UDP].dport}")

        # Save packet to pcap file
        wrpcap(PCAP_FILE, packet, append=True)
        packet_count += 1

# Stop function (based on time or packet limit)
def stop_sniffing(packet):
    return (time.time() - start_time > TIME_LIMIT) or (packet_count >= PACKET_LIMIT)

# Start sniffing on macOS (use en0 for Wi-Fi, en1/en2 for Ethernet)
print(f"Starting packet sniffing... Saving to {PCAP_FILE}")
sniff(iface="en0", prn=packet_callback, store=False, stop_filter=stop_sniffing)

print("\n✅ Packet sniffing stopped! Data saved in:", PCAP_FILE)
