import sqlite3
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import networkx as nx
import datetime
import statistics  # For calculating mean, median, and standard deviation in analyze_db function


def visualize_packet_flow_from_db(db_file):
  # Create a connection to the database
  conn = sqlite3.connect(db_file)

  # Create a cursor object to execute SQL queries
  cursor = conn.cursor()

  # Create a directed graph
  G = nx.DiGraph()

  # Add nodes for client and server
  G.add_node('Client')
  G.add_node('Server')

  # Execute a SELECT query to fetch packet data
  select_sql = 'SELECT id, direction, relative_timestamp FROM packets'
  cursor.execute(select_sql)

  # Fetch all rows returned by the query
  rows = cursor.fetchall()

  # Add edges for packet flow
  for row in rows:
    packet_id, direction, timestamp = row

    if direction == 'client_to_server':
      source = 'Client'
      target = 'Server'
    elif direction == 'server_to_client':
      source = 'Server'
      target = 'Client'
    else:
      continue  # Skip packets with unknown direction

    # Add the packet as a node with its ID as the label
    G.add_node(packet_id)
    G.nodes[packet_id]['label'] = str(packet_id)

    # Add an edge representing the packet flow
    G.add_edge(source, packet_id, timestamp=timestamp)
    G.add_edge(packet_id, target)

  # Position the nodes using a spring layout algorithm
  pos = nx.spring_layout(G, seed=42)

  # Draw the nodes
  nx.draw_networkx_nodes(G, pos, node_size=500, node_color='lightblue')

  # Draw the edges
  nx.draw_networkx_edges(G, pos, edge_color='gray', arrowsize=10)

  # Draw labels for packet nodes
  packet_labels = nx.get_node_attributes(G, 'label')
  nx.draw_networkx_labels(G, pos, packet_labels, font_color='black')

  # Draw labels for client and server nodes
  nx.draw_networkx_labels(G,
                          pos, {
                            'Client': 'Client',
                            'Server': 'Server'
                          },
                          font_color='red')

  # Set plot title and display the diagram
  plt.title('Packet Flow Diagram')
  plt.axis('off')
  plt.show()

  # Close the cursor
  cursor.close()

  # Close the connection
  conn.close()


def visualize_packet_duration_histogram(db_file):
  # Create a connection to the database
  conn = sqlite3.connect(db_file)

  # Read the packet durations from the table
  select_sql = 'SELECT relative_timestamp FROM packets'
  cursor = conn.cursor()
  cursor.execute(select_sql)
  durations = [row[0] for row in cursor.fetchall()]

  # Plot the histogram
  plt.hist(durations, bins=10)
  plt.xlabel('Packet Duration')
  plt.ylabel('Frequency')
  plt.title('Distribution of Packet Durations')
  plt.show()

  # Close the cursor
  cursor.close()

  # Close the connection
  conn.close()


# Visualize Packet Size Distribution:
def visualize_packet_size_distribution(db_file):
  # Create a connection to the database
  conn = sqlite3.connect(db_file)

  # Read the packet sizes from the table
  select_sql = 'SELECT tcp_payload_len FROM packets'
  cursor = conn.cursor()
  cursor.execute(select_sql)
  packet_sizes = [row[0] for row in cursor.fetchall()]

  # Plot the histogram
  plt.hist(packet_sizes, bins=10)
  plt.xlabel('Packet Size')
  plt.ylabel('Frequency')
  plt.title('Distribution of Packet Sizes')
  plt.show()

  # Close the cursor
  cursor.close()

  # Close the connection
  conn.close()


#Visualize TCP Flags Distribution:
# Visualize Packet Sequence Numbers:
def visualize_packet_sequence_numbers(db_file):
  # Create a connection to the database
  conn = sqlite3.connect(db_file)

  # Read the sequence numbers from the table
  select_sql = 'SELECT seqno, direction FROM packets'
  cursor = conn.cursor()
  cursor.execute(select_sql)
  rows = cursor.fetchall()

  # Separate sequence numbers based on direction
  client_seqnos = []
  server_seqnos = []
  for seqno, direction in rows:
    if direction == 'client_to_server':
      client_seqnos.append(seqno)
    elif direction == 'server_to_client':
      server_seqnos.append(seqno)

  # Plot the sequence numbers
  plt.plot(client_seqnos, label='Client to Server')
  plt.plot(server_seqnos, label='Server to Client')
  plt.xlabel('Packet Index')
  plt.ylabel('Sequence Number')
  plt.title('Packet Sequence Numbers')
  plt.legend()
  plt.show()

  # Close the cursor
  cursor.close()

  # Close the connection
  conn.close()


def calculate_packet_interarrival_time(database_file):
  # Create a connection to the database
  conn = sqlite3.connect(database_file)

  # Create a cursor object to execute SQL queries
  cursor = conn.cursor()

  # Execute a SELECT query to fetch the relative timestamps from the packets table
  select_sql = 'SELECT relative_timestamp FROM packets'
  cursor.execute(select_sql)

  # Fetch all rows returned by the query
  rows = cursor.fetchall()

  # Close the cursor and the connection
  cursor.close()
  conn.close()

  # Extract the timestamps from the rows
  timestamps = [row[0] for row in rows]

  # Convert the relative timestamps to datetime objects
  datetime_timestamps = [
    datetime.datetime.fromtimestamp(ts) for ts in timestamps
  ]

  # Calculate the interarrival times in seconds
  interarrival_times = [0]  # Start with 0 as the first interarrival time
  for i in range(1, len(datetime_timestamps)):
    time_diff = datetime_timestamps[i] - datetime_timestamps[i - 1]
    interarrival_time = time_diff.total_seconds()
    interarrival_times.append(interarrival_time)

  return datetime_timestamps[1:], interarrival_times[1:]


def visualize_packet_interarrival_time(database_file):
  # Calculate the interarrival times
  datetime_timestamps, interarrival_times = calculate_packet_interarrival_time(
    database_file)

  # Plot the interarrival times
  plt.plot(datetime_timestamps, interarrival_times)
  plt.xlabel('Time')
  plt.ylabel('Interarrival Time (s)')
  plt.title('Packet Interarrival Time')
  plt.show()


# Visualize Packet Throughput Over Time:
def calculate_packet_throughput(database_file):
  # Create a connection to the database
  conn = sqlite3.connect(database_file)

  # Create a cursor object to execute SQL queries
  cursor = conn.cursor()

  # Execute a SELECT query to fetch the relative timestamps and packet lengths from the packets table
  select_sql = 'SELECT relative_timestamp, tcp_payload_len FROM packets'
  cursor.execute(select_sql)

  # Fetch all rows returned by the query
  rows = cursor.fetchall()

  # Close the cursor and the connection
  cursor.close()
  conn.close()

  # Extract the timestamps and packet lengths from the rows
  timestamps = [row[0] for row in rows]
  packet_lengths = [row[1] for row in rows]

  # Convert the relative timestamps to datetime objects
  datetime_timestamps = [
    datetime.datetime.fromtimestamp(ts) for ts in timestamps
  ]

  # Calculate the throughput in bytes per second
  throughput = []
  for i in range(1, len(datetime_timestamps)):
    time_diff = datetime_timestamps[i] - datetime_timestamps[i - 1]

    if time_diff.total_seconds() == 0:
      throughput.append(0)  # Set throughput as 0 when time difference is zero
    else:
      throughput_value = packet_lengths[i] / time_diff.total_seconds()
      throughput.append(throughput_value)

  return datetime_timestamps[:-1], throughput


def visualize_packet_throughput(database_file):
  # Calculate the throughput
  datetime_timestamps, throughput = calculate_packet_throughput(database_file)

  # Create a figure and axis
  fig, ax = plt.subplots()

  # Plot the throughput
  ax.plot(datetime_timestamps, throughput)
  ax.set_xlabel('Time')
  ax.set_ylabel('Throughput (Bytes/s)')
  ax.set_title('Packet Throughput')

  # Format the x-axis tick labels
  ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d %H:%M:%S'))
  plt.xticks(rotation=45, ha='right')

  # Display the plot
  plt.tight_layout()
  plt.show()


#Visualize Window Size Variation:
def visualize_window_size_variation(db_file):
  # Create a connection to the database
  conn = sqlite3.connect(db_file)

  # Read the window sizes from the table
  select_sql = 'SELECT window, relative_timestamp FROM packets'
  cursor = conn.cursor()
  cursor.execute(select_sql)
  rows = cursor.fetchall()

  # Separate window sizes and timestamps
  window_sizes = [row[0] for row in rows]
  timestamps = [row[1] for row in rows]

  # Convert timestamps to datetime objects
  datetime_timestamps = [
    datetime.datetime.fromtimestamp(ts) for ts in timestamps
  ]

  # Plot the window size variation
  plt.plot(datetime_timestamps, window_sizes)
  plt.xlabel('Timestamp')
  plt.ylabel('Window Size')
  plt.title('Window Size Variation')
  plt.gca().xaxis.set_major_formatter(
    mdates.DateFormatter('%Y-%m-%d %H:%M:%S'))
  plt.gcf().autofmt_xdate()
  plt.show()

  # Close the cursor
  cursor.close()

  # Close the connection
  conn.close()


def calculate_rtt(database_file):
  # Create a connection to the database
  conn = sqlite3.connect(database_file)

  # Create a cursor object to execute SQL queries
  cursor = conn.cursor()

  # Execute a SELECT query to fetch all rows from the packets table
  select_sql = 'SELECT direction, relative_timestamp FROM packets'
  cursor.execute(select_sql)

  # Fetch all rows returned by the query
  rows = cursor.fetchall()

  # Close the cursor and the connection
  cursor.close()
  conn.close()

  rtt_list = []  # List of RTT values to be returned by the function

  for i in range(1, len(rows)):
    curr_direction, curr_timestamp = rows[i]
    prev_direction, prev_timestamp = rows[i - 1]

    if curr_direction != prev_direction:
      rtt = curr_timestamp - prev_timestamp
      rtt_list.append(rtt)

  return rtt_list


def visualize_rtt_from_db(database_file):
  # Calculate RTT values from the database
  rtt_values = calculate_rtt(database_file)

  # Calculate mean, median, and standard deviation of RTT values
  mean_rtt = statistics.mean(rtt_values)
  median_rtt = statistics.median(rtt_values)
  std_dev_rtt = statistics.stdev(rtt_values)

  # Plot a histogram of RTT values
  plt.hist(rtt_values, bins=10)
  plt.xlabel('RTT')
  plt.ylabel('Frequency')
  plt.title('Distribution of RTT')

  # Plot mean, median, and standard deviation as vertical lines
  plt.axvline(mean_rtt,
              color='red',
              linestyle='dashed',
              linewidth=2,
              label=f'Mean RTT: {mean_rtt:.2f}')
  plt.axvline(median_rtt,
              color='green',
              linestyle='dashed',
              linewidth=2,
              label=f'Median RTT: {median_rtt:.2f}')
  plt.axvline(mean_rtt + std_dev_rtt,
              color='purple',
              linestyle='dashed',
              linewidth=2,
              label=f'STD Dev: {std_dev_rtt:.2f}')
  plt.axvline(mean_rtt - std_dev_rtt,
              color='purple',
              linestyle='dashed',
              linewidth=2)
  plt.show()
  plt.close()


# Add more visualization functions as needed

# Example usage
if __name__ == '__main__':
  db_file = 'database.db'
  visualize_packet_flow_from_db(db_file)
  visualize_packet_duration_histogram(db_file)
  visualize_packet_size_distribution(db_file)
  visualize_packet_sequence_numbers(db_file)
  visualize_packet_interarrival_time(db_file)
  visualize_packet_throughput(db_file)
  visualize_window_size_variation(db_file)
  visualize_rtt_from_db(db_file)
