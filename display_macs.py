import sqlite3
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from mac_vendor_lookup import MacLookup
from datetime import datetime

DATABASE = "processed.db"


def lookup_mac_address(mac):
    return mac
    try:
        vendor = MacLookup().lookup(mac)
        return vendor
    except Exception:
        return mac


def format_timestamp(timestamp):
    dt = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
    return dt.strftime("%d.%m %H:%M")


def get_sorted_mac_vendors(df):
    unique_mac_addresses = df["address"].unique()
    vendors = [lookup_mac_address(mac) for mac in unique_mac_addresses]
    sorted_indices = np.argsort(vendors)
    return unique_mac_addresses[sorted_indices], np.array(vendors)[sorted_indices]


def get_presence_matrix(df_sorted):
    df_pivot = df_sorted.pivot(index="address", columns="timestamp", values="address")
    presence_matrix = ~df_pivot.isnull()
    return presence_matrix


def plot_mac_presence(
    presence_matrix_sorted, sorted_mac_addresses, sorted_vendors, timestamps
):
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.imshow(presence_matrix_sorted, cmap="Blues", aspect="auto")
    ax.grid(color="gray", linestyle="--", alpha=0.2)

    ax.set_title("Presence of MAC Addresses at Different Timestamps")
    ax.set_xlabel("Timestamp")
    ax.set_ylabel("MAC Address")

    ax.set_yticks(np.arange(len(sorted_mac_addresses)))
    ax.set_yticklabels(sorted_vendors)

    x_ticks = np.arange(len(timestamps))
    formatted_labels = [format_timestamp(timestamp) for timestamp in timestamps]
    ax.set_xticks(x_ticks)
    ax.set_xticklabels(formatted_labels, rotation=45, ha="right")

    fig.tight_layout()
    fig.subplots_adjust(left=0.17, bottom=0.1, right=0.99, top=0.975)
    plt.show()


def analyze_db():
    with sqlite3.connect(DATABASE) as conn:
        df = pd.read_sql_query("SELECT * FROM mac_addresses", conn)

    df_sorted = df.sort_values(by="address")

    sorted_mac_addresses, sorted_vendors = get_sorted_mac_vendors(df_sorted)
    presence_matrix = get_presence_matrix(df_sorted)

    timestamps = sorted(df_sorted["timestamp"].unique())
    presence_matrix_sorted = presence_matrix.loc[sorted_mac_addresses, timestamps]

    plot_mac_presence(
        presence_matrix_sorted, sorted_mac_addresses, sorted_vendors, timestamps
    )


if __name__ == "__main__":
    analyze_db()
