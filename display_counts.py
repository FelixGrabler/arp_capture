import os
import sqlite3
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import numpy as np
import pandas as pd
from datetime import datetime

DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "count.db")


def format_timestamp(timestamp):
    dt = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
    return dt.strftime("%d.%m %H:%M")


def sample_ticks_and_labels(x_ticks, labels, sample_size):
    if len(x_ticks) > sample_size:
        step_size = len(x_ticks) // sample_size
        x_ticks = x_ticks[::step_size]
        labels = labels[::step_size]
    return x_ticks, labels


def analyze_db():
    with sqlite3.connect(DATABASE) as conn:
        df = pd.read_sql_query("SELECT * FROM mac_counts", conn)

    df_sorted = df.sort_values(by="timestamp")

    fig, ax = plt.subplots(figsize=(10, 6))
    ax.plot(df_sorted["timestamp"], df_sorted["count"], marker="o")
    ax.grid(True)  # Adding grid

    ax.set_title("Count of MAC Addresses Over Time")
    ax.set_xlabel("Timestamp")
    ax.set_ylabel("Count")

    x_ticks = np.arange(len(df_sorted["timestamp"]))
    formatted_labels = [
        format_timestamp(timestamp) for timestamp in df_sorted["timestamp"]
    ]
    x_ticks, formatted_labels = sample_ticks_and_labels(x_ticks, formatted_labels, 100)
    ax.set_xticks(x_ticks)
    ax.set_xticklabels(formatted_labels, rotation=45, ha="right")

    ax.xaxis.set_major_locator(
        ticker.MultipleLocator(2)
    )  # Add grid lines every 2 datasets, i.e., every hour

    fig.tight_layout()
    plt.show()  # Show the plot


if __name__ == "__main__":
    analyze_db()
