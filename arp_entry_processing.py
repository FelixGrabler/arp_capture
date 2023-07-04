import os
import sqlite3
from scapy.all import *
from datetime import datetime, timedelta
import pandas as pd

DATABASE = '/etc/arp_capture/mac.db'
PCAP_DIR = '/etc/arp_capture/pcap_files/'

def initialize_db():
    with sqlite3.connect(DATABASE) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS mac_addresses (
                timestamp TEXT,
                address TEXT,
                PRIMARY KEY (timestamp, address)
            )
        """)

def round_up_to_nearest_half_hour(dt):
    if dt.minute % 30 or dt.second:
        return dt + timedelta(minutes=30 - dt.minute % 30, seconds=-dt.second)
    else:
        return dt

def extract_timestamp(filename):
    basename = os.path.basename(filename)
    return datetime.strptime(basename[4:18], "%Y%m%d%H%M%S")  # Convert to datetime object

def process_pcap_file(filename):
    timestamp = extract_timestamp(filename)

    try:
        packets = rdpcap(filename)
    except Exception as e:
        print(f"ERROR: Failed to read pcap file {filename}: {e}")
        return

    mac_addresses = set(packet[ARP].hwsrc for packet in packets if ARP in packet and packet[ARP].op == 2)

    if mac_addresses:
        timestamp = round_up_to_nearest_half_hour(timestamp)
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            for address in mac_addresses:
                try:
                    cursor.execute("INSERT OR IGNORE INTO mac_addresses (timestamp, address) VALUES (?, ?)", (str(timestamp), address))
                except sqlite3.IntegrityError:
                    continue  # Ignore duplicates
    try:
        os.remove(filename)
        print(f"Deleted processed file: {filename}")
    except Exception as e:
        print(f"ERROR: Failed to delete processed file {filename}: {e}")

def fill_gaps():
    with sqlite3.connect(DATABASE) as conn:
        df = pd.read_sql("SELECT * FROM mac_addresses", conn)

    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df.sort_values(["address", "timestamp"], inplace=True)

    groups = df.groupby("address")

    new_rows = []
    for name, group in groups:
        last_row = None
        for i, row in group.iterrows():
            if last_row is None:
                new_rows.append(row)
            elif (
                timedelta(minutes=30)
                < row["timestamp"] - last_row["timestamp"]
                <= timedelta(hours=2)
            ):
                fill_timestamps = pd.date_range(
                    start=last_row["timestamp"] + timedelta(minutes=30),
                    end=row["timestamp"] - timedelta(minutes=30),
                    freq="30T",
                )
                for timestamp in fill_timestamps:
                    new_row = row.copy()
                    new_row["timestamp"] = timestamp
                    new_rows.append(new_row)
                new_rows.append(row)
            else:
                new_rows.append(row)
            last_row = row

    new_df = pd.DataFrame(new_rows)

    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        for index, row in new_df.iterrows():
            try:
                cursor.execute("INSERT OR IGNORE INTO mac_addresses (timestamp, address) VALUES (?, ?)", (str(row["timestamp"]), row["address"]))
            except sqlite3.IntegrityError:
                continue  # Ignore duplicates

def process_pcap_files():
    pcap_files = sorted(filename for filename in os.listdir(PCAP_DIR) if filename.startswith('arp_') and filename.endswith('.pcap'))

    pcap_files = pcap_files[:-1]

    for filename in pcap_files:
        process_pcap_file(os.path.join(PCAP_DIR, filename))

    fill_gaps()

if __name__ == "__main__":
    initialize_db()
    process_pcap_files()
