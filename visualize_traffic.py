import matplotlib.pyplot as plt
from collections import Counter
from scapy.all import rdpcap, IP, TCP, UDP

# Path to the captured packets file
PCAP_FILE = "/Volumes/Thrisha SSD/captured_packets.pcap"

# Read captured packets
packets = rdpcap(PCAP_FILE)

# List of source IPs for packet count visualization
ip_addresses = []

# Analyze packets for visualization
for packet in packets:
    if IP in packet:
        ip_addresses.append(packet[IP].src)

# Count IP occurrences
ip_counts = Counter(ip_addresses)

# Plot the number of packets per source IP
plt.bar(ip_counts.keys(), ip_counts.values())
plt.title('Number of Packets per Source IP Address')
plt.xlabel('IP Address')
plt.ylabel('Packet Count')
plt.xticks(rotation=45)
plt.tight_layout()
plt.show()
