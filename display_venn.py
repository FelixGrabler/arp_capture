import os
from datetime import datetime
from scapy.all import rdpcap, ARP, Ether, UDP, ICMP
from collections import defaultdict
import matplotlib.pyplot as plt
from matplotlib_venn import venn3

# Get the directory of the script file
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Use os.path.join to create full file paths
PCAP_DIR = os.path.join(BASE_DIR, "pcap_files")


def is_within_time_range(filename, start_time, end_time):
    timestamp_str = filename.split("_")[1].split(".")[
        0
    ]  # Get the timestamp part of the filename
    timestamp = datetime.strptime(timestamp_str, "%Y%m%d%H%M%S")

    return start_time <= timestamp <= end_time


def count_protocols():
    protocol_counts = defaultdict(set)
    start_time = datetime.strptime("20230721100000", "%Y%m%d%H%M%S")
    end_time = datetime.strptime("20230721103000", "%Y%m%d%H%M%S")

    for filename in os.listdir(PCAP_DIR):
        if filename.startswith("arp_") and is_within_time_range(
            filename, start_time, end_time
        ):
            packets = rdpcap(os.path.join(PCAP_DIR, filename))

            for packet in packets:
                if ARP in packet:
                    protocol_counts["ARP"].add(packet[Ether].src)
                if ICMP in packet:
                    protocol_counts["ICMP"].add(packet[Ether].src)
                if UDP in packet:
                    if packet[UDP].sport == 5353 or packet[UDP].dport == 5353:
                        protocol_counts["mDNS"].add(packet[Ether].src)

    return protocol_counts


def plot_counts(protocol_counts):
    venn3(
        [
            set(protocol_counts["ARP"]),
            set(protocol_counts["ICMP"]),
            set(protocol_counts["mDNS"]),
        ],
        set_labels=("ARP", "ICMP", "mDNS"),
    )
    plt.show()


def main():
    protocol_counts = count_protocols()
    plot_counts(protocol_counts)


if __name__ == "__main__":
    main()
