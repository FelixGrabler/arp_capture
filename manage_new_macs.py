import sqlite3
import pandas as pd
from datetime import datetime, timedelta


def round_up_to_nearest_half_hour(dt):
    if dt.minute % 30 or dt.second:
        return dt + timedelta(minutes=30 - dt.minute % 30, seconds=-dt.second)
    else:
        return dt


def process_db(file_path):
    with sqlite3.connect(file_path) as conn:
        df = pd.read_sql("SELECT * FROM mac_addresses", conn)

    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["timestamp"] = df["timestamp"].apply(round_up_to_nearest_half_hour)

    df.sort_values(["address", "timestamp"], inplace=True)

    groups = df.groupby("address")

    debug = False

    new_rows = []
    for name, group in groups:
        last_row = None
        # print()
        # print()
        for i, row in group.iterrows():
            # if row["address"] == "b0:a7:b9:45:2f:18":
            #     debug = True
            if last_row is None:
                new_rows.append(row)
                # print(row["address"])
            elif (
                timedelta(minutes=30)
                < row["timestamp"] - last_row["timestamp"]
                <= timedelta(hours=3)
            ):
                # If the gap is up to 2 hours, fill the gap with duplicate entries
                if debug:
                    print("filling gaps for ", row["timestamp"])
                fill_timestamps = pd.date_range(
                    start=last_row["timestamp"] + timedelta(minutes=30),
                    end=row["timestamp"] - timedelta(minutes=30),
                    freq="30T",
                )
                for timestamp in fill_timestamps:
                    new_row = row.copy()
                    new_row["timestamp"] = timestamp
                    new_rows.append(new_row)
                    if debug:
                        print("filled gap: ", new_row["timestamp"])
                new_rows.append(row)
            else:
                # If the gap is more than 2 hours, add the row as it is
                new_rows.append(row)
                if debug:
                    print("stand alone row ", row["timestamp"])
            last_row = row
            debug = False

    new_df = pd.DataFrame(new_rows)

    return new_df


def merge_db(file_path, target_path="processed.db"):
    new_df = process_db(file_path)
    conn = sqlite3.connect(target_path)

    # Instead of using to_sql, we'll loop over the DataFrame and insert the records one by one
    cursor = conn.cursor()
    counter = 0
    for index, row in new_df.iterrows():
        # if row["address"] == "b0:a7:b9:45:2f:18":
        #     print("INSERT", row["timestamp"])
        try:
            cursor.execute(
                """
                INSERT INTO mac_addresses (timestamp, address)
                VALUES (?, ?)
            """,
                (str(row["timestamp"]), row["address"]),
            )
        except (
            sqlite3.IntegrityError
        ) as e:  # Catch and ignore the error when inserting a duplicate
            # if row["address"] == "b0:a7:b9:45:2f:18":
            #     print("DUPLICATE", row["timestamp"], str(e))
            pass
        else:
            counter += 1
    conn.commit()
    conn.close()

    print("Inserted", counter, "new entries into processed.db")


if __name__ == "__main__":
    file_path = "mac.db"
    merge_db(file_path)
