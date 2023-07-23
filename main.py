import os

import sys
import time  # For printing timestamps in printable_timestamp function
import pickle  # For pickling packets in pickle_pcap function
import sqlite3  # For creating the database in load_pickle_to_sql function
import textwrap
import binascii

import tkinter as tk  # For creating the main window in create_main_window function
import matplotlib.pyplot as plt  # For plotting histogram in analyze_db function
import pandas as pd  # For printing packet data in print_packet_data function
import networkx as nx  # For packet flow diagram in visualize_packet_flow_from_db function

from scapy.all import *
from scapy.utils import RawPcapReader  # For reading packets from a pcap file in pickle_pcap function
from scapy.layers.l2 import Ether  # For packet dissection in pickle_pcap function
from scapy.layers.inet import IP, TCP  # For packet dissection in pickle_pcap function
from enum import Enum  # For PktDirection enum in pickle_pcap function
from tkinter import messagebox  # For displaying error messages in fetch_packets function
from tqdm import tqdm  # For progress bar in pickle_pcap function
from tkinter import ttk  # For Treeview widget in fetch_packets function
from prettytable import PrettyTable

from visualize import visualize_packet_flow_from_db, visualize_packet_duration_histogram, visualize_packet_size_distribution, visualize_packet_sequence_numbers, visualize_packet_interarrival_time, visualize_packet_throughput, visualize_window_size_variation, visualize_rtt_from_db

# Specify the path and name of the database file
database_file = 'database.db'

pcap_file = 'ahmed_pc.pcap'

pickle_file = 'pickle_file.pickle'

# Create a connection to the database
conn = sqlite3.connect(database_file)

# Create a cursor object to execute SQL queries
cursor = conn.cursor()

# Define the SQL statement to create a table
create_table_sql = '''CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY,
    src_ip TEXT,
    dst_ip TEXT,
    direction TEXT,
    ordinal INTEGER,
    relative_timestamp REAL,
    tcp_flags TEXT,
    seqno INTEGER,
    ackno INTEGER,
    tcp_payload_len INTEGER,
    tcp_payload BLOB,
    window INTEGER,
    src_mac TEXT,
    dst_mac TEXT
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

  connections = []
  interesting_packet_count = 0

  packet_iterator = rdpcap(pcap_file_in)

  total_packets = len(packet_iterator)
  progress_bar = tqdm(total=total_packets, desc='Processing', unit=' packets')

  for pkt in packet_iterator:
    try:
      ether_pkt = pkt[Ether]
    except IndexError:
      # Skip packets without an Ethernet layer
      continue

    if 'type' not in ether_pkt.fields:
      # LLC frames will have 'len' instead of 'type'.
      # We disregard those
      continue

    if ether_pkt.type != 0x0800:
      # Disregard non-IPv4 packets
      continue

    ip_pkt = pkt[IP]

    if ip_pkt.proto != 6:
      # Ignore non-TCP packets
      continue

    src_ip, dst_ip = ip_pkt.src, ip_pkt.dst
    tcp_pkt = ip_pkt[TCP]

    src_port, dst_port = tcp_pkt.sport, tcp_pkt.dport

    # Check if this packet belongs to a connection
    connection_key = (src_ip, src_port, dst_ip, dst_port)

    interesting_packet_count += 1

    if connection_key not in [conn['connection_key'] for conn in connections]:
      # This is a new connection, add it to the connections list
      connection_data = {'connection_key': connection_key, 'packets': []}
      connections.append(connection_data)

    # Append the packet data to the corresponding connection
    connection_data = next(conn for conn in connections
                           if conn['connection_key'] == connection_key)
    packet_data = {
      'ordinal': interesting_packet_count,
      'relative_timestamp': pkt.time,
      'tcp_flags': str(tcp_pkt.flags),
      'seqno': tcp_pkt.seq,
      'ackno': tcp_pkt.ack,
      'tcp_payload_len': ip_pkt.len - (ip_pkt.ihl * 4) - (tcp_pkt.dataofs * 4),
      'tcp_payload': bytes(tcp_pkt.payload),
      'window': tcp_pkt.window,
      'direction': str(PktDirection.client_to_server),  # Convert to string
      'src_mac': ether_pkt.src,
      'dst_mac': ether_pkt.dst,
    }

    connection_data['packets'].append(packet_data)

    progress_bar.update()

  progress_bar.close()

  print('{} contains {} packets ({} interesting)'.format(
    pcap_file_in, total_packets, interesting_packet_count))

  print('Writing pickle file {}...'.format(pickle_file_out), end='')
  with open(pickle_file_out, 'wb') as pickle_fd:
    pickle.dump(connections, pickle_fd)
  print('done.')


###-------------------------------------------------------------------###


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
    connections = pickle.load(pickle_fd)

  # Get the total number of packets
  total_packets = sum(len(connection['packets']) for connection in connections)

  # Create a progress bar
  progress_bar = tqdm(total=total_packets, unit='packet')

  # Iterate through connections and their packets and insert each packet into the table
  for connection in connections:
    for pkt_data in connection['packets']:
      src_ip = connection['connection_key'][
        0]  # Get the source IP from the connection key
      dst_ip = connection['connection_key'][
        2]  # Get the destination IP from the connection key
      direction = pkt_data['direction']
      ordinal = int(pkt_data['ordinal'])  # Convert ordinal to integer
      relative_timestamp = int(
        pkt_data['relative_timestamp'])  # Convert timestamp to integer
      tcp_flags = pkt_data['tcp_flags']
      seqno = pkt_data['seqno']
      ackno = pkt_data['ackno']
      tcp_payload_len = pkt_data['tcp_payload_len']
      tcp_payload = pkt_data['tcp_payload']
      window = pkt_data['window']
      src_mac = pkt_data['src_mac']
      dst_mac = pkt_data['dst_mac']

      insert_sql = '''
                INSERT INTO packets (src_ip, dst_ip, direction, ordinal, relative_timestamp, tcp_flags, seqno, ackno, tcp_payload_len, tcp_payload, window, src_mac, dst_mac)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?,?,?,?,?)
            '''
      values = (src_ip, dst_ip, direction, ordinal, relative_timestamp,
                tcp_flags, seqno, ackno, tcp_payload_len,
                sqlite3.Binary(tcp_payload), window, src_mac, dst_mac)
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


###------------------------------------------###


def print_packet_data(db_file, direction=None):
  # Create a connection to the database
  conn = sqlite3.connect(db_file)

  # Read all packets from the table into a DataFrame
  df = pd.read_sql_query('SELECT * FROM packets', conn)

  # Display the DataFrame
  print(df)

  # Close the connection
  conn.close()


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


def print_packet_content(packet_id):
  select_sql = 'SELECT * FROM packets WHERE id = ?'
  cursor.execute(select_sql, (packet_id, ))

  # Fetch the selected row
  row = cursor.fetchone()

  if row:
    _, src_ip, dst_ip, direction, ordinal, relative_timestamp, tcp_flags, seqno, ackno, tcp_payload_len, tcp_payload, window, src_mac, dst_mac = row

    # Create a PrettyTable object
    table = PrettyTable()

    # Set the field names for the table
    table.field_names = ["Field", "Value"]

    # Add packet details as rows to the table
    table.add_row(["Packet ID", packet_id])
    table.add_row(["Source IP", src_ip])
    table.add_row(["Destination IP", dst_ip])
    table.add_row(["Direction", direction])
    table.add_row(["Ordinal", ordinal])
    table.add_row(["Relative Timestamp", relative_timestamp])
    table.add_row(["TCP Flags", tcp_flags])
    table.add_row(["Sequence Number", seqno])
    table.add_row(["Acknowledgment Number", ackno])
    table.add_row(["TCP Payload Length", tcp_payload_len])
    table.add_row(["Window", window])
    table.add_row(["Source MAC", src_mac])
    table.add_row(["Destination MAC", dst_mac])

    try:
      # Attempt to decode the TCP payload as UTF-8
      payload_text = binascii.hexlify(tcp_payload).decode("utf-8")
    except UnicodeDecodeError:
      # If decoding as UTF-8 fails, decode with errors="replace" to replace invalid characters
      payload_text = tcp_payload.decode("utf-8", errors="replace")

    # Add the TCP payload to the table with text wrapping
    payload_wrapped = textwrap.fill(payload_text, width=80)
    table.add_row(["TCP Payload", payload_wrapped])

    # Set the alignment of the table to "l" for left alignment
    table.align = "l"

    # Print the table
    print(table)
  else:
    print("Packet not found.")


def analyze_packet(packet_id):
  select_sql = 'SELECT * FROM packets WHERE id = ?'
  cursor.execute(select_sql, (packet_id, ))

  # Fetch the selected row
  row = cursor.fetchone()

  if row:
    id, src_ip, dst_ip, direction, ordinal, relative_timestamp, tcp_flags, seqno, ackno, tcp_payload_len, tcp_payload, window, src_mac, dst_mac = row
    # Example Analysis:
    # Calculate packet duration
    packet_duration = calculate_packet_duration(relative_timestamp)
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

  print_packet_content(packet_id)
  analyze_packet(packet_id)

  # Prompt for further actions
  option = input("Do you want to select and analyze another packet? (y/n): ")
  if option.lower() == 'y':
    select_and_analyze_packets()


pickle_pcap(pcap_file, pickle_file)
load_pickle_to_sql(pickle_file, database_file)
print_packet_data(database_file)
select_and_analyze_packets()

# Call the visualization functions as needed
visualize_packet_flow_from_db(database_file)
visualize_packet_duration_histogram(database_file)
visualize_packet_size_distribution(database_file)
visualize_packet_sequence_numbers(database_file)
visualize_packet_interarrival_time(database_file)
visualize_packet_throughput(database_file)
visualize_window_size_variation(database_file)
visualize_rtt_from_db(database_file)
