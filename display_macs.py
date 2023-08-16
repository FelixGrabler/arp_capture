import sqlite3
import pandas as pd
import matplotlib.pyplot as plt

# Connect to the database
conn = sqlite3.connect('mac.db')
cursor = conn.cursor()

# Query to fetch data
query = "SELECT timestamp, address FROM mac_addresses"
cursor.execute(query)
data = cursor.fetchall()

# Close connection
conn.close()

# Convert the data into a pandas DataFrame
df = pd.DataFrame(data, columns=['timestamp', 'address'])

# Plotting the data
plt.figure(figsize=(14, 8))
for address in df['address'].unique():
    subset = df[df['address'] == address]
    plt.plot(subset['timestamp'], subset['address'], 'o-', label=address)

plt.title('Presence of Devices Over Time')
plt.xlabel('Timestamp')
plt.ylabel('MAC Address')
plt.xticks(rotation=45)
plt.tight_layout()
plt.legend(loc='upper left', bbox_to_anchor=(1, 1))
plt.show()
