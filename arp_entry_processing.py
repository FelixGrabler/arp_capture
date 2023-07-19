import os
import sqlite3
from scapy.all import rdpcap
from scapy.layers.l2 import Ether
from datetime import datetime, timedelta
import pandas as pd
import logging
from logging.handlers import RotatingFileHandler

DATABASE = "/etc/arp_capture/mac.db"
COUNT_DATABASE = "/etc/arp_capture/count.db"
PCAP_DIR = "/etc/arp_capture/pcap_files/"
LOG_DIR = "/etc/arp_capture/logs"

debug = (
    False  # Set this to True to not delete old mac data and to disable count feature
)

# Check if the log directory exists, if not, create it
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

# Setting up logging
log_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

log_file = os.path.join(LOG_DIR, "arp_capture.log")

# Use a rotating file handler to limit file size and number of backup log files
handler = RotatingFileHandler(
    log_file, mode="a", maxBytes=33 * 1024, backupCount=2, encoding=None, delay=0
)
handler.setFormatter(log_formatter)
handler.setLevel(logging.INFO)

logger = logging.getLogger()
logger.setLevel(logging.INFO)

logger.addHandler(handler)


def initialize_db():
    try:
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
    except Exception as e:
        logging.error(f"Failed to initialize mac_addresses database: {e}")

    try:
        with sqlite3.connect(COUNT_DATABASE) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS mac_counts (
                    timestamp TEXT,
                    count INTEGER,
                    PRIMARY KEY (timestamp)
                )
            """
            )
    except Exception as e:
        logging.error(f"Failed to initialize mac_counts database: {e}")


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
            # Batch insert all MAC addresses
            cursor.executemany(
                "INSERT OR IGNORE INTO mac_addresses (timestamp, address) VALUES (?, ?)",
                [(str(timestamp), address) for address in mac_addresses],
            )

    try:
        os.remove(filename)
        logging.info("{} ({})".format(filename, len(mac_addresses)))
    except Exception as e:
        logging.error("Failed to delete processed file {}: {}".format(filename, e))


def fill_gaps():
    try:
        with sqlite3.connect(DATABASE) as conn:
            # Use SQL to fill gaps
            conn.execute(
                """
                INSERT OR IGNORE INTO mac_addresses (timestamp, address)
                SELECT
                    datetime(
                        julianday(timestamp) + (30 * 60) / (24 * 60 * 60),
                        'unixepoch'
                    ),
                    address
                FROM mac_addresses
                WHERE
                    EXISTS (
                        SELECT *
                        FROM mac_addresses AS later
                        WHERE
                            later.address = mac_addresses.address
                            AND (later.timestamp > mac_addresses.timestamp)
                            AND (
                                julianday(later.timestamp)
                                - julianday(mac_addresses.timestamp)
                            ) * (24 * 60 * 60) BETWEEN (30 * 60) + 1 AND 2 * 60 * 60
                    )
                """
            )
    except Exception as e:
        logging.error(f"Failed to fill gaps in mac_addresses: {e}")


def count_and_delete_old_data():
    three_hours_ago = datetime.now() - timedelta(hours=3)

    try:
        with sqlite3.connect(DATABASE) as conn:
            # Count MAC addresses
            counts = pd.read_sql(
                """
                SELECT
                    timestamp,
                    COUNT(address) as count
                FROM mac_addresses
                WHERE timestamp < ?
                GROUP BY timestamp
                """,
                conn,
                params=(str(three_hours_ago),),
            )
    except Exception as e:
        logging.error(f"Failed to count mac_addresses: {e}")

    try:
        with sqlite3.connect(COUNT_DATABASE) as conn:
            cursor = conn.cursor()
            for index, row in counts.iterrows():
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO mac_counts (timestamp, count)
                    VALUES (?, ?)
                """,
                    (row["timestamp"], row["count"]),
                )
            conn.commit()
    except Exception as e:
        logging.error(f"Failed to write counts to mac_counts database: {e}")

    try:
        with sqlite3.connect(DATABASE) as conn:
            # Delete old data
            conn.execute(
                "DELETE FROM mac_addresses WHERE timestamp < ?", (str(three_hours_ago),)
            )
    except Exception as e:
        logging.error(f"Failed to delete old data from mac_addresses: {e}")


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


def main():
    try:
        initialize_db()
    except Exception as e:
        logging.error(f"Failed to initialize database: {e}")

    try:
        process_pcap_files()
    except Exception as e:
        logging.error(f"Failed to process pcap files: {e}")

    try:
        fill_gaps()
    except Exception as e:
        logging.error(f"Failed to fill gaps in mac_addresses: {e}")

    if not debug:
        try:
            count_and_delete_old_data()
        except Exception as e:
            logging.error(f"Failed to count and delete old data: {e}")


if __name__ == "__main__":
    main()
