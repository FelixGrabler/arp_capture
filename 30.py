import sqlite3
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from mac_vendor_lookup import MacLookup
from datetime import datetime

DATABASE = "C:/Users/user/Documents/ARP/mac.db"


def lookup_mac_address(mac):
    vendor = None
    try:
        vendor = MacLookup().lookup(mac)
    finally:
        return vendor if vendor else mac


def format_timestamp(timestamp):
    dt = datetime.strptime(timestamp, "%Y%m%d%H%M%S")
    return dt.strftime("%d.%m %H:%M")


def get_sorted_mac_vendors(df):
    unique_mac_addresses = df["address"].unique()
    vendors = [lookup_mac_address(mac) for mac in unique_mac_addresses]
    sorted_indices = np.argsort(vendors)

    return unique_mac_addresses[sorted_indices], np.array(vendors)[sorted_indices]


def group_into_intervals(df_sorted):
    # Convert timestamps to datetime, assuming they are in the format "yyyyMMddHHmmss"
    df_sorted["timestamp"] = pd.to_datetime(
        df_sorted["timestamp"], format="%Y%m%d%H%M%S"
    )

    # Convert timestamps to 30 minute intervals
    df_sorted["timestamp"] = df_sorted["timestamp"].dt.floor("30T")

    # Convert timestamps back to string format
    df_sorted["timestamp"] = df_sorted["timestamp"].dt.strftime("%Y%m%d%H%M%S")

    # Check if MAC address is present in each 30-minute interval
    df_grouped = df_sorted.groupby(["timestamp", "address"]).any().reset_index()

    return df_grouped


def get_presence_matrix(df_grouped):
    # Pivot table based on address and timestamp, values don't matter since we only care about presence, hence use address itself
    df_pivot = df_grouped.pivot(index="address", columns="timestamp", values="address")

    # Create a binary matrix indicating presence (1) or absence (nan) of MAC address at each timestamp
    presence_matrix = ~df_pivot.isnull()

    return presence_matrix


def plot_mac_presence(
    presence_matrix_sorted, sorted_mac_addresses, sorted_vendors, timestamps
):
    plt.figure(figsize=(10, 6))
    plt.imshow(presence_matrix_sorted, cmap="Blues", aspect="auto")

    # Add an almost transparent grid
    plt.grid(color="gray", linestyle="--", alpha=0.2)

    plt.title("Presence of MAC Addresses at Different Timestamps")
    plt.xlabel("Timestamp")
    plt.ylabel("MAC Address")

    # Set custom tick labels for y-axis (MAC addresses)
    plt.yticks(np.arange(len(sorted_mac_addresses)), sorted_vendors)

    # Set custom tick labels for x-axis (timestamps)
    x_ticks = np.arange(len(timestamps))
    formatted_labels = [format_timestamp(timestamp) for timestamp in timestamps]
    plt.xticks(x_ticks, formatted_labels, rotation=45, ha="right")

    # Set spacings
    plt.subplots_adjust(left=0.17, bottom=0.1, right=0.99, top=0.975)

    plt.show()


def analyze_db():
    # Connect to the SQLite database
    with sqlite3.connect(DATABASE) as conn:
        # Read the data into a pandas DataFrame
        df = pd.read_sql_query("SELECT * FROM mac_addresses", conn)

    df_sorted = df.sort_values(by="address")

    df_grouped = group_into_intervals(df_sorted)

    sorted_mac_addresses, sorted_vendors = get_sorted_mac_vendors(df_grouped)

    presence_matrix = get_presence_matrix(df_grouped)

    # Sort timestamps in ascending order (latest to newest) and sort presence matrix based on sorted timestamps
    timestamps = sorted(df_grouped["timestamp"].unique())
    presence_matrix_sorted = presence_matrix[timestamps]

    plot_mac_presence(
        presence_matrix_sorted, sorted_mac_addresses, sorted_vendors, timestamps
    )


if __name__ == "__main__":
    analyze_db()
