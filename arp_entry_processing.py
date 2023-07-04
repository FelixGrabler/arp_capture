import os
import glob
import sqlite3
import argparse
from scapy.all import *

DATABASE = '/etc/arp_capture/mac.db'
PCAP_DIR = '/etc/arp_capture/pcap_files/'

def initialize_db():
    try:
        with sqlite3.connect(DATABASE) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS mac_addresses (
                    timestamp TEXT,
                    address TEXT,
                    PRIMARY KEY (timestamp, address)
                )
            """)
    except Exception as e:
        print(f"ERROR: Failed to initialize database: {e}")

def extract_timestamp(filename):
    # filename format: arp_yyyyMMddhhmmss.pcap
    basename = os.path.basename(filename)
    return basename[4:18]  # Extract timestamp portion

def process_pcap_file(filename):
    # Extract timestamp from filename
    timestamp = extract_timestamp(filename)

    # Read pcap file
    try:
        packets = rdpcap(filename)
    except Exception as e:
        print(f"ERROR: Failed to read pcap file {filename}: {e}")
        return

    # Extract and store unique MAC addresses
    mac_addresses = set(packet[ARP].hwsrc for packet in packets)

    # Store unique MAC addresses in database
    try:
        with sqlite3.connect(DATABASE) as conn:
            for address in mac_addresses:
                conn.execute("INSERT OR IGNORE INTO mac_addresses (timestamp, address) VALUES (?, ?)", (timestamp, address))
                print(f"Stored MAC address: {address} with timestamp: {timestamp}")
    except Exception as e:
        print(f"ERROR: Failed to update database: {e}")
        return

    # If the processing was successful, delete the file
    try:
        os.remove(filename)
        print(f"Deleted processed file: {filename}")
    except Exception as e:
        print(f"ERROR: Failed to delete processed file {filename}: {e}")

def process_pcap_files():
    # Get all pcap files, sorted by name (thus by timestamp due to the naming scheme)
    pcap_files = sorted(filename for filename in os.listdir(PCAP_DIR) if filename.startswith('arp_') and filename.endswith('.pcap'))

    # Exclude the last file (might still be written to)
    pcap_files = pcap_files[:-1]

    for filename in pcap_files:
        process_pcap_file(os.path.join(PCAP_DIR, filename))

if __name__ == "__main__":
    initialize_db()
    process_pcap_files()