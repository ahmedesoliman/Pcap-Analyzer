import os
import statistics # For calculating mean, median, and standard deviation in analyze_db function
import sys 
import time # For printing timestamps in printable_timestamp function
import pickle # For pickling packets in pickle_pcap function
import sqlite3 # For creating the database in load_pickle_to_sql function

import tkinter as tk # For creating the main window in create_main_window function
import matplotlib.pyplot as plt # For plotting histogram in analyze_db function
import pandas as pd # For printing packet data in print_packet_data function
import networkx as nx # For packet flow diagram in visualize_packet_flow_from_db function

from scapy.utils import RawPcapReader # For reading packets from a pcap file in pickle_pcap function
from scapy.layers.l2 import Ether # For packet dissection in pickle_pcap function
from scapy.layers.inet import IP, TCP # For packet dissection in pickle_pcap function
from enum import Enum # For PktDirection enum in pickle_pcap function
from tkinter import messagebox # For displaying error messages in fetch_packets function
from tqdm import tqdm # For progress bar in pickle_pcap function
from tkinter import ttk # For Treeview widget in fetch_packets function


from visualize import visualize_packet_flow_from_db, visualize_packet_duration_histogram

# Specify the path and name of the database file
database_file = 'your_database.db'

# Create a connection to the database
conn = sqlite3.connect(database_file)

# Create a cursor object to execute SQL queries
cursor = conn.cursor()

# Define the SQL statement to create a table
create_table_sql = '''CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY,
    direction TEXT,
    ordinal INTEGER,
    relative_timestamp REAL,
    tcp_flags TEXT,
    seqno INTEGER,
    ackno INTEGER,
    tcp_payload_len INTEGER,
    tcp_payload BLOB,
    window INTEGER
)'''

# Execute the SQL statement to create the table
cursor.execute(create_table_sql)


class PktDirection(Enum):
  not_defined = 0
  client_to_server = 1
  server_to_client = 2


def printable_timestamp(ts, resol):
  ts_sec = ts // resol
  ts_subsec = ts % resol
  ts_sec_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts_sec))
  return '{}.{}'.format(ts_sec_str, ts_subsec)


def pickle_pcap(pcap_file_in, pickle_file_out):

  print('Processing {}...'.format(pcap_file_in))

  client = '192.168.1.137:57080'
  server = '152.19.134.43:80'

  (client_ip, client_port) = client.split(':')
  (server_ip, server_port) = server.split(':')

  count = 0
  interesting_packet_count = 0

  server_sequence_offset = None
  client_sequence_offset = None

  # List of interesting packets, will finally be pickled.
  # Each element of the list is a dictionary that contains fields of interest
  # from the packet.
  packets_for_analysis = []

  # Get the total number of packets
  total_packets = len(packets_for_analysis)

  # Initialize the progress bar
  progress_bar = tqdm(total=total_packets, desc='Processing', unit=' packets')

  client_recv_window_scale = 0
  server_recv_window_scale = 0

  for (
      pkt_data,
      pkt_metadata,
  ) in RawPcapReader(pcap_file_in):
    count += 1
    # Update the progress bar
    progress_bar.update()

    ether_pkt = Ether(pkt_data)
    if 'type' not in ether_pkt.fields:
      # LLC frames will have 'len' instead of 'type'.
      # We disregard those
      continue

    if ether_pkt.type != 0x0800:
      # disregard non-IPv4 packets
      continue

    ip_pkt = ether_pkt[IP]

    if ip_pkt.proto != 6:
      # Ignore non-TCP packet
      continue

    tcp_pkt = ip_pkt[TCP]

    direction = PktDirection.not_defined

    if ip_pkt.src == client_ip:
      if tcp_pkt.sport != int(client_port):
        continue
      if ip_pkt.dst != server_ip:
        continue
      if tcp_pkt.dport != int(server_port):
        continue
      direction = PktDirection.client_to_server
    elif ip_pkt.src == server_ip:
      if tcp_pkt.sport != int(server_port):
        continue
      if ip_pkt.dst != client_ip:
        continue
      if tcp_pkt.dport != int(client_port):
        continue
      direction = PktDirection.server_to_client
    else:
      continue

    interesting_packet_count += 1
    if interesting_packet_count == 1:
      first_pkt_timestamp = (pkt_metadata.tshigh << 32) | pkt_metadata.tslow
      first_pkt_timestamp_resolution = pkt_metadata.tsresol
      first_pkt_ordinal = count

    last_pkt_timestamp = (pkt_metadata.tshigh << 32) | pkt_metadata.tslow
    last_pkt_timestamp_resolution = pkt_metadata.tsresol
    last_pkt_ordinal = count

    this_pkt_relative_timestamp = last_pkt_timestamp - first_pkt_timestamp

    if direction == PktDirection.client_to_server:
      if client_sequence_offset is None:
        client_sequence_offset = tcp_pkt.seq
      relative_offset_seq = tcp_pkt.seq - client_sequence_offset
    else:
      assert direction == PktDirection.server_to_client
      if server_sequence_offset is None:
        server_sequence_offset = tcp_pkt.seq
      relative_offset_seq = tcp_pkt.seq - server_sequence_offset

    # If this TCP packet has the Ack bit set, then it must carry an ack
    # number.
    if 'A' not in str(tcp_pkt.flags):
      relative_offset_ack = 0
    else:
      if direction == PktDirection.client_to_server:
        relative_offset_ack = tcp_pkt.ack - server_sequence_offset
      else:
        relative_offset_ack = tcp_pkt.ack - client_sequence_offset

    # Determine the TCP payload length. IP fragmentation will mess up this
    # logic, so first check that this is an unfragmented packet
    if (ip_pkt.flags == 'MF') or (ip_pkt.frag != 0):
      print('No support for fragmented IP packets')
      return False

    tcp_payload_len = ip_pkt.len - (ip_pkt.ihl * 4) - (tcp_pkt.dataofs * 4)

    # Look for the 'Window Scale' TCP option if this is a SYN or SYN-ACK
    # packet.
    if 'S' in str(tcp_pkt.flags):
      for (
          opt_name,
          opt_value,
      ) in tcp_pkt.options:
        if opt_name == 'WScale':
          if direction == PktDirection.client_to_server:
            client_recv_window_scale = opt_value
          else:
            server_recv_window_scale = opt_value
          break

    # Create a dictionary and populate it with data that we'll need in the
    # analysis phase.

    pkt_data = {}
    pkt_data['direction'] = direction
    pkt_data['ordinal'] = last_pkt_ordinal
    pkt_data['relative_timestamp'] = this_pkt_relative_timestamp / \
                                     pkt_metadata.tsresol
    pkt_data['tcp_flags'] = str(tcp_pkt.flags)
    pkt_data['seqno'] = relative_offset_seq
    pkt_data['ackno'] = relative_offset_ack
    pkt_data['tcp_payload_len'] = tcp_payload_len
    pkt_data['tcp_payload'] = bytes(tcp_pkt.payload)
    if direction == PktDirection.client_to_server:
      pkt_data['window'] = tcp_pkt.window << client_recv_window_scale
    else:
      pkt_data['window'] = tcp_pkt.window << server_recv_window_scale

    packets_for_analysis.append(pkt_data)

  # Close the progress bar
  progress_bar.close()
  # ---
  data = {
    'client_ip': client_ip,
    'server_ip': server_ip,
    'packets': packets_for_analysis
  }

  print('{} contains {} packets ({} interesting)'.format(
    pcap_file_in, count, interesting_packet_count))

  # print('First packet in connection: Packet #{} {}'.format(
  #   first_pkt_ordinal,
  #   printable_timestamp(first_pkt_timestamp, first_pkt_timestamp_resolution)))
  # print(' Last packet in connection: Packet #{} {}'.format(
  #   last_pkt_ordinal,
  #   printable_timestamp(last_pkt_timestamp, last_pkt_timestamp_resolution)))

  print('Writing pickle file {}...'.format(pickle_file_out), end='')
  with open(pickle_file_out, 'wb') as pickle_fd:
    pickle.dump(data, pickle_fd)
  print('done.')


# ---


def load_pickle_to_sql(pickle_file_in, db_file):
  print('Processing {}...'.format(pickle_file_in))

  # Create a connection to the database
  conn = sqlite3.connect(db_file)

  # Create a cursor object to execute SQL queries
  cursor = conn.cursor()

  # Delete existing data from the packets table
  delete_sql = 'DELETE FROM packets'
  cursor.execute(delete_sql)

  # Commit the changes to the database
  conn.commit()

  # Load packets from the pickled file
  with open(pickle_file_in, 'rb') as pickle_fd:
    data = pickle.load(pickle_fd)

  # Extract client IP, server IP, and packets for analysis from the loaded data
  client_ip = data['client_ip']
  server_ip = data['server_ip']
  packets_for_analysis = data['packets']

  # Get the total number of packets
  total_packets = len(packets_for_analysis)

  # Create a progress bar
  progress_bar = tqdm(total=total_packets, unit='packet')

  # Iterate through packets_for_analysis and insert each packet into the table
  for pkt_data in packets_for_analysis:
    direction = pkt_data['direction'].value
    ordinal = pkt_data['ordinal']
    relative_timestamp = pkt_data['relative_timestamp']
    tcp_flags = pkt_data['tcp_flags']
    seqno = pkt_data['seqno']
    ackno = pkt_data['ackno']
    tcp_payload_len = pkt_data['tcp_payload_len']
    tcp_payload = pkt_data['tcp_payload']
    window = pkt_data['window']

    insert_sql = '''
            INSERT INTO packets (direction, ordinal, relative_timestamp, tcp_flags, seqno, ackno, tcp_payload_len, tcp_payload, window)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        '''
    values = (direction, ordinal, relative_timestamp, tcp_flags, seqno, ackno,
              tcp_payload_len, tcp_payload, window)
    cursor.execute(insert_sql, values)

    # Update the progress bar
    progress_bar.update(1)

  # Commit the changes to the database
  conn.commit()

  # Close the cursor
  cursor.close()

  # Close the connection
  conn.close()

  # Close the progress bar
  progress_bar.close()

  print('Stored {} packets in the database.'.format(total_packets))


def print_packet_data(db_file, direction=None):
  # Create a connection to the database
  conn = sqlite3.connect(db_file)

  # Read all packets from the table into a DataFrame
  df = pd.read_sql_query('SELECT * FROM packets', conn)

  # Display the DataFrame
  print(df)

  # Close the connection
  conn.close()


def calculate_rtt_from_db(db_file):
  # Create a connection to the database
  conn = sqlite3.connect(db_file)

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


def analyze_db(db_file):
  # Calculate RTT values from the database
  rtt_values = calculate_rtt_from_db(db_file)

  # Calculate mean, median, and standard deviation of RTT values
  mean_rtt = statistics.mean(rtt_values)
  median_rtt = statistics.median(rtt_values)
  std_dev_rtt = statistics.stdev(rtt_values)

  # Plot a histogram of RTT values
  plt.hist(rtt_values, bins=10)
  plt.xlabel('RTT')
  plt.ylabel('Frequency')
  plt.title('Distribution of RTT')
  plt.show()
  plt.close()


def calculate_packet_duration(timestamp):
  # Retrieve the previous packet's relative timestamp from the database
  select_previous_sql = 'SELECT MAX(relative_timestamp) FROM packets WHERE relative_timestamp < ?'
  cursor.execute(select_previous_sql, (timestamp, ))
  previous_timestamp = cursor.fetchone()[0]

  if previous_timestamp is None:
    # No previous packet found, duration is 0 or unknown
    duration = 0
  else:
    # Calculate the duration by subtracting the previous timestamp from the current timestamp
    duration = timestamp - previous_timestamp

  # Return the duration
  return duration


def analyze_packet(packet_id):
  select_sql = 'SELECT * FROM packets WHERE id = ?'
  cursor.execute(select_sql, (packet_id, ))

  # Fetch the selected row
  row = cursor.fetchone()

  if row:
    id, direction, ordinal, relative_timestamp, tcp_flags, seqno, ackno, tcp_payload_len, tcp_payload, window = row
    # Perform analysis on the selected packet
    print("Analyzing Packet ID:", id)
    print("Direction:", direction)
    # Example Analysis:
    # Calculate packet duration
    packet_duration = calculate_packet_duration(relative_timestamp)

    # Print packet details
    print("Ordinal:", ordinal)
    print("Relative Timestamp:", relative_timestamp)
    print("TCP Flags:", tcp_flags)
    print("Sequence Number:", seqno)
    print("Acknowledgment Number:", ackno)
    print("TCP Payload Length:", tcp_payload_len)
    print("TCP Pay Load: ", tcp_payload)
    print("Window:", window)

    # Print packet duration
    print("Packet Duration:", packet_duration)

    # Perform further analysis on the packet as needed
  else:
    print("Packet not found.")


# Define a function to interactively select and analyze packets
def select_and_analyze_packets():
  packet_id = input(
    "Enter the ID of the packet you want to analyze (or 'q' to quit): ")

  if packet_id.lower() == 'q':
    return

  analyze_packet(packet_id)

  # Prompt for further actions
  option = input("Do you want to select and analyze another packet? (y/n): ")
  if option.lower() == 'y':
    select_and_analyze_packets()


def fetch_packets(db_file, start_id, end_id):
  # Create a connection to the database
  conn = sqlite3.connect(db_file)

  # Create a cursor object to execute SQL queries
  cursor = conn.cursor()

  # Execute the SELECT query to fetch packets within the specified ID range
  select_sql = 'SELECT * FROM packets WHERE id BETWEEN ? AND ?'
  cursor.execute(select_sql, (start_id, end_id))

  # Fetch all rows returned by the query
  rows = cursor.fetchall()

  if rows:
    # Create a new window for displaying the packets
    window = tk.Toplevel()
    window.title("Fetched Packets")

    # Create a Treeview widget
    tree = ttk.Treeview(window)
    tree['columns'] = tuple(range(len(rows[0])))

    # Configure the column headings
    column_names = [desc[0] for desc in cursor.description]
    for i, name in enumerate(column_names):
      tree.heading(i, text=name)

    # Insert the rows into the Treeview
    for row in rows:
      tree.insert('', 'end', values=row)

    # Pack the Treeview to fill the window
    tree.pack(fill='both', expand=True)

  else:
    messagebox.showinfo("No Packets",
                        "No packets found in the specified ID range.")

  # Close the cursor
  cursor.close()

  # Close the connection
  conn.close()


def create_main_window(db_file):
  # Create the main window
  window = tk.Tk()
  window.title("Packet Analyzer")

  # Function to handle button click and fetch packets within the specified ID range
  def on_fetch_click():
    start_id = int(start_id_entry.get())
    end_id = int(end_id_entry.get())
    fetch_packets(db_file, start_id, end_id)

  # Create labels and entry fields for start ID and end ID
  start_id_label = tk.Label(window, text="Start ID:")
  start_id_label.pack()
  start_id_entry = tk.Entry(window)
  start_id_entry.pack()

  end_id_label = tk.Label(window, text="End ID:")
  end_id_label.pack()
  end_id_entry = tk.Entry(window)
  end_id_entry.pack()

  # Create a button to fetch packets within the specified ID range
  fetch_button = tk.Button(window,
                           text="Fetch Packets",
                           command=on_fetch_click)
  fetch_button.pack(pady=10)

  # Run the main event loop
  window.mainloop()


pickle_pcap('example-01.pcap', 'example-01.pickle')
# with open('example-01.pickle', 'rb') as pickle_fd:
#   data = pickle.load(pickle_fd)
#   for item in data:
#     print('The data is : ', item)
load_pickle_to_sql('example-01.pickle', database_file)
# print_packet_data(database_file)
# select_and_analyze_packets()
# Call the visualize_packet_flow_from_db function to generate the packet flow diagram

analyze_db(database_file)
create_main_window(database_file)


# Call the visualization functions as needed
visualize_packet_flow_from_db(database_file)
visualize_packet_duration_histogram(database_file)
