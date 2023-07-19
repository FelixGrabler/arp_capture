#!/bin/bash

# Create a directory to store the pcap files if it does not exist
/bin/mkdir -p /etc/arp_capture/pcap_files

# Try to get the date from Google
GOOGLE_DATE=$(curl -I http://google.com 2>/dev/null | /bin/grep -i Date: | cut -d' ' -f3-7)

if [ -z "$GOOGLE_DATE" ]; then
    # If Google didn't return a date, use the system date
    TIMESTAMP=$(/bin/date +%Y%m%d%H%M%S)
else
    # If Google returned a date, reformat it
    TIMESTAMP=$(/bin/date -d "$GOOGLE_DATE" +"%Y%m%d%H%M%S" --date='TZ="Europe/Vienna"')
fi

FILENAME="/etc/arp_capture/pcap_files/arp_$TIMESTAMP.pcap"

# Capture ARP packets for 5 minutes
timeout 60 tshark -i wlan0 -f "arp or icmp or udp port 67 or udp port 53 or udp port 1900 or udp port 5353 or ether proto 0x88cc or ether proto 0x2000 or ether proto 0x6003" -w $FILENAME
