import os
from scapy.all import rdpcap, ARP, ICMP, Ether, UDP, DNS, BOOTP
from collections import defaultdict
import matplotlib.pyplot as plt

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
                if ICMP in packet:
                    protocol_counts["ICMP"].add(packet[Ether].src)
                if UDP in packet:
                    if packet[UDP].sport == 67 or packet[UDP].dport == 67:
                        protocol_counts["DHCP"].add(packet[Ether].src)
                    elif packet[UDP].sport == 53 or packet[UDP].dport == 53:
                        protocol_counts["DNS"].add(packet[Ether].src)
                    elif packet[UDP].sport == 1900 or packet[UDP].dport == 1900:
                        protocol_counts["SSDP"].add(packet[Ether].src)
                    elif packet[UDP].sport == 5353 or packet[UDP].dport == 5353:
                        protocol_counts["mDNS"].add(packet[Ether].src)
                if Ether in packet:
                    if packet[Ether].type == 0x88CC:
                        protocol_counts["LLDP"].add(packet[Ether].src)
                    elif packet[Ether].type == 0x2000:
                        protocol_counts["CDP"].add(packet[Ether].src)
                    elif packet[Ether].type == 0x6003:
                        protocol_counts["DEC MOP"].add(packet[Ether].src)

    # Convert to counts
    for protocol in protocol_counts:
        protocol_counts[protocol] = len(protocol_counts[protocol])

    return protocol_counts


def plot_counts(protocol_counts):
    protocols = list(protocol_counts.keys())
    counts = [protocol_counts[protocol] for protocol in protocols]

    plt.bar(protocols, counts)
    plt.xlabel("Protocol")
    plt.ylabel("Distinct MAC Addresses")
    plt.title("MAC Addresses by Protocol")
    plt.show()


def main():
    protocol_counts = count_protocols()
    plot_counts(protocol_counts)


if __name__ == "__main__":
    main()
