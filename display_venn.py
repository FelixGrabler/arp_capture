import os
from scapy.all import rdpcap, ARP, Ether, UDP, BOOTP
from collections import defaultdict
import matplotlib.pyplot as plt
from matplotlib_venn import venn3

# Get the directory of the script file
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Use os.path.join to create full file paths
PCAP_DIR = os.path.join(BASE_DIR, "pcap_files")


def count_protocols():
    protocol_counts = defaultdict(set)

    for filename in os.listdir(PCAP_DIR):
        if filename.endswith(".pcap"):
            packets = rdpcap(os.path.join(PCAP_DIR, filename))

            for packet in packets:
                if ARP in packet:
                    protocol_counts["ARP"].add(packet[Ether].src)
                if UDP in packet:
                    if packet[UDP].sport == 67 or packet[UDP].dport == 67:
                        protocol_counts["DHCP"].add(packet[Ether].src)
                    elif packet[UDP].sport == 5353 or packet[UDP].dport == 5353:
                        protocol_counts["mDNS"].add(packet[Ether].src)

    return protocol_counts


def plot_counts(protocol_counts):
    venn3(
        [
            set(protocol_counts["ARP"]),
            set(protocol_counts["mDNS"]),
            set(protocol_counts["DHCP"]),
        ],
        set_labels=("ARP", "mDNS", "DHCP"),
    )
    plt.show()


def main():
    protocol_counts = count_protocols()
    plot_counts(protocol_counts)


if __name__ == "__main__":
    main()
