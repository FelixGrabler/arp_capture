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

    # Define the colors for each generation_method
    colors = {"original": "blue", "week": "green", "day": "yellow", "linear": "red"}

    # Plot individual datapoints with respective colors and adjusted size
    for method, color in colors.items():
        subset = df[df["generation_method"] == method]
        ax.scatter(
            subset.index, subset["count"], color=color, label=method, zorder=2, s=20
        )  # Half the size of nodes

    # Plot colored line segments with adjusted thickness
    previous_point = None
    for idx, row in df.iterrows():
        if previous_point is not None:
            color = colors.get(row["generation_method"], "grey")
            ax.plot(
                [previous_point[0], idx],
                [previous_point[1], row["count"]],
                color=color,
                zorder=1,
                linewidth=2,
            )  # Double the line thickness

        previous_point = (idx, row["count"])

    ax.set_title("Count of MAC Addresses Over Time")
    ax.set_xlabel("Timestamp")
    ax.set_ylabel("Count")
    ax.legend()  # Add legend to differentiate generation methods

    # Set x-axis labels to only show labels for every third hour
    ax.xaxis.set_major_locator(mdates.HourLocator(interval=3))
    ax.xaxis.set_minor_locator(
        mdates.HourLocator(interval=1)
    )  # Set minor ticks every hour for the grid
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%d.%m %H:%M"))

    # Grid with zorder set to be behind both the line and the scatter points
    ax.grid(True, which="both", zorder=0)

    # Rotate x-axis labels for better readability
    plt.xticks(rotation=45)

    fig.tight_layout()
    fig.subplots_adjust(left=0.027, bottom=0.086, right=0.987, top=0.97)
    plt.show()  # Show the plot


if __name__ == "__main__":
    analyze_db()
