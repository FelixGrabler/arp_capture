import os
import sqlite3
from scapy.all import rdpcap
from scapy.layers.l2 import Ether
from datetime import datetime, timedelta
import pandas as pd
import logging
from logging.handlers import RotatingFileHandler

DATABASE = "/etc/arp_capture/mac.db"
PCAP_DIR = "/etc/arp_capture/pcap_files/"
LOG_DIR = "/etc/arp_capture/logs"

# Check if the log directory exists, if not, create it
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

# Setting up logging
log_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

log_file = os.path.join(LOG_DIR, "arp_capture.log")

# Use a rotating file handler to limit file size and number of backup log files
handler = RotatingFileHandler(
    log_file, mode="a", maxBytes=100 * 1024, backupCount=2, encoding=None, delay=0
)
handler.setFormatter(log_formatter)
handler.setLevel(logging.INFO)

logger = logging.getLogger()
logger.setLevel(logging.INFO)

logger.addHandler(handler)


def initialize_db():
    with sqlite3.connect(DATABASE) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS mac_addresses (
                timestamp TEXT,
                address TEXT,
                PRIMARY KEY (timestamp, address)
            )
        """
        )


def round_up_to_nearest_half_hour(dt):
    if dt.minute % 30 or dt.second:
        return dt + timedelta(minutes=30 - dt.minute % 30, seconds=-dt.second)
    else:
        return dt


def extract_timestamp(filename):
    basename = os.path.basename(filename)
    return datetime.strptime(
        basename[4:18], "%Y%m%d%H%M%S"
    )  # Convert to datetime object


def process_pcap_file(filename):
    timestamp = extract_timestamp(filename)

    try:
        packets = rdpcap(filename)
    except Exception as e:
        logging.error("Failed to read pcap file {}: {}".format(filename, e))
        return

    mac_addresses = set(packet[Ether].src for packet in packets if Ether in packet)

    if mac_addresses:
        timestamp = round_up_to_nearest_half_hour(timestamp)
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            for address in mac_addresses:
                try:
                    cursor.execute(
                        "INSERT OR IGNORE INTO mac_addresses (timestamp, address) VALUES (?, ?)",
                        (str(timestamp), address),
                    )
                except sqlite3.IntegrityError:
                    continue  # Ignore duplicates
    try:
        os.remove(filename)
        logging.info(
            "Deleted processed file: {}. Processed MAC addresses: {}.".format(
                filename, len(mac_addresses)
            )
        )
    except Exception as e:
        logging.error("Failed to delete processed file {}: {}".format(filename, e))


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
                30 * 60
                <= (row["timestamp"] - last_row["timestamp"]).total_seconds()
                <= 2 * 60 * 60
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
        for _, row in new_df.iterrows():
            try:
                cursor.execute(
                    "INSERT OR IGNORE INTO mac_addresses (timestamp, address) VALUES (?, ?)",
                    (str(row["timestamp"]), row["address"]),
                )
            except sqlite3.IntegrityError:
                continue  # Ignore duplicates


def process_pcap_files():
    pcap_files = sorted(
        filename
        for filename in os.listdir(PCAP_DIR)
        if filename.startswith("arp_") and filename.endswith(".pcap")
    )

    # Exclude the last file because it is still written to
    pcap_files = pcap_files[:-1]

    for filename in pcap_files:
        process_pcap_file(os.path.join(PCAP_DIR, filename))

    fill_gaps()


if __name__ == "__main__":
    initialize_db()
    process_pcap_files()
