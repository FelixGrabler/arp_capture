import os
import sqlite3
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import pandas as pd

DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "count.db")


def format_timestamp(timestamp):
    return timestamp.strftime("%d.%m %H:%M")


def analyze_db():
    with sqlite3.connect(DATABASE) as conn:
        df = pd.read_sql_query("SELECT * FROM mac_counts", conn)

    # Convert 'timestamp' to datetime and set as index
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df.set_index("timestamp", inplace=True)

    # Create new datetime index with all half-hour intervals
    new_index = pd.date_range(start=df.index.min(), end=df.index.max(), freq="30T")

    # Reindex dataframe to include all half-hour intervals
    df = df.reindex(new_index)

    fig, ax = plt.subplots(figsize=(10, 6))
    ax.plot(df.index, df["count"], marker="o")

    ax.set_title("Count of MAC Addresses Over Time")
    ax.set_xlabel("Timestamp")
    ax.set_ylabel("Count")

    # Set x-axis labels to only show labels for every third hour
    ax.xaxis.set_major_locator(mdates.HourLocator(interval=3))
    ax.xaxis.set_minor_locator(
        mdates.HourLocator(interval=1)
    )  # Set minor ticks every hour for the grid
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%d.%m %H:%M"))
    ax.grid(
        True, which="both"
    )  # Enable grid for both major (every third hour) and minor (every hour) ticks

    # Rotate x-axis labels for better readability
    plt.xticks(rotation=45)

    fig.tight_layout()
    plt.show()  # Show the plot


if __name__ == "__main__":
    analyze_db()
