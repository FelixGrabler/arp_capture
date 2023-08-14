import logging
import os
import sqlite3
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler
from multiprocessing import Pool

import pandas as pd
from scapy.all import rdpcap
from scapy.layers.l2 import Ether

# BASE_DIR = os.getcwd()
BASE_DIR = "/etc/arp_capture/"
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
    log_file, mode="a", maxBytes=30 * 1024, backupCount=3, encoding=None, delay=0
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
                    timestamp DATETIME,
                    address TEXT,
                    is_original INTEGER,
                    PRIMARY KEY (timestamp, address)
                )
            """
            )
    except Exception as e:
        logging.error("Failed to initialize mac_addresses database: {}".format(e))
        raise e

    try:
        with sqlite3.connect(COUNT_DATABASE) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS mac_counts (
                    timestamp DATETIME PRIMARY KEY,
                    count INTEGER,
                    generation_method TEXT
                )
                """
            )
    except Exception as e:
        logging.error("Failed to initialize mac_counts database: {}".format(e))
        raise e


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

    # Ignore file if timestamp is before 2020
    if timestamp.year < 2020:
        return

    # read file content
    try:
        packets = rdpcap(filename)
    except Exception as e:
        logging.error("Failed to read pcap file {}: {}".format(filename, e))
        print("❌")
        return

    mac_addresses = set(packet[Ether].src for packet in packets if Ether in packet)

    # insert mac addresses into mac.db
    if mac_addresses:
        timestamp = round_up_to_nearest_half_hour(timestamp)
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.executemany(
                "INSERT OR REPLACE INTO mac_addresses (timestamp, address, is_original) VALUES (?, ?, ?)",
                [(timestamp.isoformat(), address, 1) for address in mac_addresses],  # Mark original entries as 1
            )
            print(" ({} original) ".format(cursor.rowcount), end="")
        
            # Fill entries for the next 1.5 hours
            for i in range(1, 4):
                filled_timestamp = timestamp + timedelta(minutes=i*30)
                cursor.executemany(
                    "INSERT OR IGNORE INTO mac_addresses (timestamp, address, is_original) VALUES (?, ?, ?)",
                    [(filled_timestamp.isoformat(), address, 0) for address in mac_addresses],  # Mark filled entries as 0
                )
                print("({} fake) ".format(cursor.rowcount), end="")

    # remove file
    try:
        os.remove(filename)
        logging.info("{} ({} MACs, {} packets)".format(filename, len(mac_addresses), len(packets)))
        print(" ✅ ({} MACs, {} packets)".format(len(mac_addresses), len(packets)))
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
        if filename.endswith(".pcap")
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
    Fills gaps in the mac.db that are <2h
    """
    try:
        with sqlite3.connect(DATABASE) as conn:
            # Use SQL to fill gaps in mac.db that are <2h
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR IGNORE INTO mac_addresses (timestamp, address)
                SELECT
                    -- Create new timestamps by adding 30 minutes to existing timestamps
                    datetime(
                        julianday(timestamp) + (30) / (24 * 60),
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
                            -- The timestamp of the later record must be greater than the current record
                            AND (later.timestamp > mac_addresses.timestamp)
                            -- The gap between the current and later record must be between 30 minutes and 2 hours
                            AND (
                                julianday(later.timestamp)
                                - julianday(mac_addresses.timestamp)
                            ) * (24 * 60 * 60) BETWEEN (30 * 60) + 1 AND 2 * 60 * 60
                    )
                """
            )
            print("({})".format(cursor.rowcount), end="")
            logging.info("mac.db fillings: {}".format(cursor.rowcount))

    except Exception as e:
        # Log any exceptions that may occur during execution
        logging.error("Failed to fill gaps in mac_addresses: {}".format(e))


def count_and_delete_old_data():
    """
    Counts and deletes old data from the databases.
    """
    delete_cutoff = datetime.now() - timedelta(hours=100)
    count_cutoff = datetime.now() - timedelta(hours=0)

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
                params=(str(count_cutoff),),
            )
        print("({} counts) ✅ ".format(len(counts)), end="")
    except Exception as e:
        logging.error("Failed to count mac_addresses: {}".format(e))
        print("❌ ", end="")

    try:
        with sqlite3.connect(COUNT_DATABASE) as conn:
            cursor = conn.cursor()
            for index, row in counts.iterrows():
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO mac_counts (timestamp, count, generation_method)
                    VALUES (?, ?, ?)
                """,
                    (row["timestamp"], row["count"], "original"),
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
                "DELETE FROM mac_addresses WHERE timestamp < ?", (str(delete_cutoff),)
            )
            count_del = cursor.rowcount
            print("({} old) ".format(count_del), end="")
            logging.info("Deleted ({}) old entries".format(count_del))

        print("✅ ", end="")

    except Exception as e:
        logging.error("Failed to delete old data from mac_addresses: {}".format(e))
        print("❌ ", end="")


def delete_pre_2000_entries():
    """
    Deletes all entries from the count.db database before the year 2000 and
    prints the number of deleted entries.
    """
    try:
        with sqlite3.connect(COUNT_DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM mac_counts WHERE strftime('%Y', timestamp) < '2000'"
            )
            deleted_entries = cursor.rowcount
            if deleted_entries > 0:
                print("({} <2000 counts)".format(deleted_entries), end="")
                logging.info("({} <2000 counts)".format(deleted_entries))
    except Exception as e:
        logging.error("Failed to delete pre-2000 entries from count.db: {}".format(e))
        print("❌")


def fill_gaps_in_count_db():
    """
    Fills gaps in the count data using the specified rules.
    """
    try:
        with sqlite3.connect(COUNT_DATABASE) as conn:
            df = pd.read_sql(
                "SELECT timestamp, count, generation_method FROM mac_counts ORDER BY timestamp",
                conn,
                index_col="timestamp",
                parse_dates=["timestamp"],
            )

        # Fill gaps with linear interpolation if less than 2 hours, then with data from one week ago, then one day ago, then linear interpolation
        for i, row in df.iterrows():
            if pd.isnull(row["count"]):
                before = df[df.index < i].last_valid_index()
                after = df[df.index > i].first_valid_index()
                if after and before and after - before <= pd.Timedelta(hours=2):
                    df.loc[i, "count"] = df.loc[before, "count"] + (
                        df.loc[after, "count"] - df.loc[before, "count"]
                    ) / ((after - before) / pd.Timedelta(minutes=30))
                    df.loc[i, "generation_method"] = "linear"
                else:
                    week_ago = i - pd.DateOffset(weeks=1)
                    day_ago = i - pd.DateOffset(days=1)

                    if week_ago in df.index and pd.notnull(df.loc[week_ago, "count"]):
                        df.loc[i, "count"] = df.loc[week_ago, "count"]
                        df.loc[i, "generation_method"] = "week"
                    elif day_ago in df.index and pd.notnull(df.loc[day_ago, "count"]):
                        df.loc[i, "count"] = df.loc[day_ago, "count"]
                        df.loc[i, "generation_method"] = "day"
                    else:
                        df.loc[i, "count"] = df.loc[before, "count"] + (
                            df.loc[after, "count"] - df.loc[before, "count"]
                        ) / ((after - before) / pd.Timedelta(minutes=30))
                        df.loc[i, "generation_method"] = "linear"

        # Fill any remaining NaNs with 0
        df["count"].fillna(0, inplace=True)
        df["generation_method"].fillna("no data", inplace=True)

        # Write the filled data back to the database
        # df.to_sql("mac_counts", conn, if_exists="replace")  # causes the PK to vanish

        # Connect to the database
        with sqlite3.connect(COUNT_DATABASE) as conn:
            cursor = conn.cursor()

            # Insert data row by row, but ignore any conflicts
            for i, row in df.iterrows():
                timestamp_str = i.isoformat()
                cursor.execute("""
                    INSERT OR IGNORE INTO mac_counts(timestamp, count, generation_method) 
                    VALUES (?, ?, ?)
                """, (timestamp_str, row["count"], row["generation_method"]))

            conn.commit()

    except Exception as e:
        logging.error("Failed to fill gaps in count data: {}".format(e))


def main():
    """
    Main function for the script.
    """
    logging.info("")
    logging.info("Starting new execution at {}".format(datetime.now()))

    try:
        print("initialize_db ", end="")
        initialize_db()
        print("✅")
    except Exception as e:
        print("❌")

    try:
        process_pcap_files()
    except Exception as e:
        logging.error("Failed to process pcap files: {}".format(e))
        print("❌")

    # try:
    #     print("filling gaps ", end="")
    #     fill_gaps()
    #     print("✅")
    # except Exception as e:
    #     logging.error("Failed to fill gaps in mac_addresses: {}".format(e))
    #     print("❌")

    try:
        print("Deleting pre-2000 entries: ", end="")
        delete_pre_2000_entries()
        print("✅")
    except Exception as e:
        logging.error("Failed to delete pre-2000 entries from count.db: {}".format(e))
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
