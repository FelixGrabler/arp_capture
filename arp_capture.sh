#!/bin/bash

# Create a directory to store the pcap files if it does not exist
mkdir -p /etc/arp_capture/pcap_files

while true
do
    TIMESTAMP=$(/bin/date +%Y%m%d%H%M%S)
    FILENAME="/etc/arp_capture/pcap_files/arp_$TIMESTAMP.pcap"

    # Capture ARP packets for 5 minutes
    timeout 1800 tshark -i wlan0 -f "arp" -w $FILENAME
done