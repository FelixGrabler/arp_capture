import sqlite3
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

# Connect to the database
conn = sqlite3.connect('mac.db')
cursor = conn.cursor()

# Query to fetch data including is_original
query = "SELECT timestamp, address, is_original FROM mac_addresses"
cursor.execute(query)
data = cursor.fetchall()

# Close connection
conn.close()

# Convert the data into a pandas DataFrame
df = pd.DataFrame(data, columns=['timestamp', 'address', 'is_original'])

# Create a matrix with rows as MAC addresses and columns as timestamps
unique_addresses = df['address'].unique()
unique_timestamps = df['timestamp'].unique()

matrix = np.zeros((len(unique_addresses), len(unique_timestamps)))

for _, row in df.iterrows():
    i = np.where(unique_addresses == row['address'])[0][0]
    j = np.where(unique_timestamps == row['timestamp'])[0][0]
    matrix[i, j] = 2 if row['is_original'] == 1 else 1

# Plotting the heatmap
plt.figure(figsize=(14, 8))
plt.imshow(matrix, aspect='auto', cmap='Blues')
plt.yticks(np.arange(len(unique_addresses)), unique_addresses)
plt.xticks(np.arange(len(unique_timestamps)), unique_timestamps, rotation=45)
plt.xlabel('Timestamp')
plt.ylabel('MAC Address')
plt.title('Presence of Devices Over Time')
plt.grid(which='both', axis='both', linestyle='-', color='lightgrey', linewidth=0.5)
plt.tight_layout()
plt.show()
