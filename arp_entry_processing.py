import logging
import os
import sqlite3
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler
from multiprocessing import Pool

import pandas as pd
from scapy.all import rdpcap
from scapy.layers.l2 import Ether

BASE_DIR = os.getcwd()
DATABASE = os.path.join(BASE_DIR, "mac.db")
COUNT_DATABASE = os.path.join(BASE_DIR, "count.db")
PCAP_DIR = os.path.join(BASE_DIR, "pcap_files/")
LOG_DIR = os.path.join(BASE_DIR, "logs/")

debug = (
    False  # Set this to True to not delete old mac data and to disable count feature
)

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
    """
    Initializes the databases used for storing mac addresses and their counts.
    """
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
        logging.error("Failed to initialize mac_addresses database: {}".format(e))

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
        logging.error("Failed to initialize mac_counts database: {}".format(e))


def round_up_to_nearest_half_hour(dt):
    """
    Rounds up the given datetime object to the nearest half hour.

    :param dt: The datetime object to round up.
    :return: The datetime object rounded up to the nearest half hour.
    """
    if dt.minute % 30 or dt.second:
        return dt + timedelta(minutes=30 - dt.minute % 30, seconds=-dt.second)
    else:
        return dt


def extract_timestamp(filename):
    """
    Extracts the timestamp from the given filename.

    :param filename: The filename to extract the timestamp from.
    :return: The extracted timestamp as a datetime object.
    """
    basename = os.path.basename(filename)
    return datetime.strptime(
        basename[4:18], "%Y%m%d%H%M%S"
    )  # Convert to datetime object


def process_pcap_file(filename):
    """
    Processes the given pcap file.

    :param filename: The name of the pcap file to process.
    """
    print(filename, end="")
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
            cursor.executemany(
                "INSERT OR IGNORE INTO mac_addresses (timestamp, address) VALUES (?, ?)",
                [(str(timestamp), address) for address in mac_addresses],
            )

    try:
        os.remove(filename)
        logging.info("{} ({})".format(filename, len(mac_addresses)))
        print(" ✅ {}".format(len(mac_addresses)))
    except Exception as e:
        logging.error("Failed to delete processed file {}: {}".format(filename, e))
        print(" ❌")


def process_pcap_files():
    """
    Processes all pcap files in the specified directory.
    """
    pcap_files = sorted(
        filename
        for filename in os.listdir(PCAP_DIR)
        if filename.startswith("arp_") and filename.endswith(".pcap")
    )

    # Exclude the last file because it is still written to
    pcap_files = pcap_files[:-1]

    with Pool() as p:
        p.map(
            process_pcap_file,
            [os.path.join(PCAP_DIR, filename) for filename in pcap_files],
        )


def fill_gaps():
    """
    Fills gaps in the mac addresses data.
    """
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
        logging.error("Failed to fill gaps in mac_addresses: {}".format(e))


def count_and_delete_old_data():
    """
    Counts and deletes old data from the databases.
    """
    delete_cutoff = datetime.now() - timedelta(hours=10)
    count_cutoff = datetime.now() - timedelta(hours=3)

    try:
        with sqlite3.connect(DATABASE) as conn:
            # Count MAC addresses
            counts = pd.read_sql(
                """
                SELECT
                    timestamp,
                    COUNT(address) as count
                FROM mac_addresses
                WHERE timestamp > ?
                GROUP BY timestamp
                """,
                conn,
                params=(str(count_cutoff),),
            )
        print("{} counts ✅ ".format(len(counts)), end="")
    except Exception as e:
        logging.error("Failed to count mac_addresses: {}".format(e))
        print("❌ ", end="")

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
        print("✅ ", end="")
    except Exception as e:
        logging.error("Failed to write counts to mac_counts database: {}".format(e))
        print("❌ ", end="")

    try:
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT COUNT(*) FROM mac_addresses WHERE timestamp < ?",
                (str(delete_cutoff),),
            )
            count_del = cursor.fetchone()[0]
            print("{} ".format(count_del), end="")
            logging.info("Deleted {} old entries".format(count_del))

            conn.execute(
                "DELETE FROM mac_addresses WHERE timestamp < ?", (str(delete_cutoff),)
            )
        print("✅ ", end="")

    except Exception as e:
        logging.error("Failed to delete old data from mac_addresses: {}".format(e))
        print("❌ ", end="")


def fill_gaps_in_count_db():
    """
    Fills gaps in the count data using the specified rules.
    """
    try:
        with sqlite3.connect(COUNT_DATABASE) as conn:
            df = pd.read_sql(
                "SELECT timestamp, count FROM mac_counts ORDER BY timestamp",
                conn,
                index_col="timestamp",
                parse_dates=["timestamp"],
            )

        # Resample to 30-minute intervals
        df = df.resample("30T").asfreq()

        # Forward-fill for up to 3 hours
        df = df.fillna(method="ffill", limit=6)

        # Fill remaining gaps with data from one week ago, then one day ago
        for i, row in df.iterrows():
            if pd.isnull(row["count"]):
                week_ago = i - pd.DateOffset(weeks=1)
                day_ago = i - pd.DateOffset(days=1)

                if week_ago in df.index and pd.notnull(df.loc[week_ago, "count"]):
                    df.loc[i, "count"] = df.loc[week_ago, "count"]
                elif day_ago in df.index and pd.notnull(df.loc[day_ago, "count"]):
                    df.loc[i, "count"] = df.loc[day_ago, "count"]

        # Fill any remaining NaNs with 0
        df = df.fillna(0)

        # Write the filled data back to the database
        df.to_sql("mac_counts", conn, if_exists="replace")

    except Exception as e:
        logging.error("Failed to fill gaps in count data: {}".format(e))


def main():
    """
    Main function for the script.
    """
    try:
        print("initialize_db ", end="")
        initialize_db()
        print("✅")
    except Exception as e:
        logging.error("Failed to initialize database: {}".format(e))
        print("❌")

    try:
        process_pcap_files()
    except Exception as e:
        logging.error("Failed to process pcap files: {}".format(e))
        print("❌")

    try:
        print("filling gaps ", end="")
        fill_gaps()
        print("✅")
    except Exception as e:
        logging.error("Failed to fill gaps in mac_addresses: {}".format(e))
        print("❌")

    if not debug:
        try:
            print("Counting and deleting old data ", end="")
            count_and_delete_old_data()
            print("✅")
            fill_gaps_in_count_db()
        except Exception as e:
            logging.error("Failed to count and delete old data: {}".format(e))
            print("❌")


if __name__ == "__main__":
    main()
