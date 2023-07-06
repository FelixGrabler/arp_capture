#!/bin/bash

# Create a directory to store the pcap files if it does not exist
mkdir -p /etc/arp_capture/pcap_files

TIMESTAMP=$(/bin/date +%Y%m%d%H%M%S)
FILENAME="/etc/arp_capture/pcap_files/arp_$TIMESTAMP.pcap"

# Capture ARP packets for 5 minutes
timeout 60 tshark -i wlan0 -f "arp or icmp or udp port 67 or udp port 53 or udp port 1900 or udp port 5353 or ether proto 0x88cc or ether proto 0x2000 or ether proto 0x6003" -w $FILENAME
