import sqlite3
import matplotlib.pyplot as plt
import networkx as nx


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

# Visualize Packet Interarrival Time:
def visualize_packet_interarrival_time(db_file):
    # Create a connection to the database
    conn = sqlite3.connect(db_file)

    # Read the relative timestamps from the table
    select_sql = 'SELECT relative_timestamp FROM packets'
    cursor = conn.cursor()
    cursor.execute(select_sql)
    timestamps = [row[0] for row in cursor.fetchall()]

    # Convert timestamps to datetime objects
    datetime_timestamps = [datetime.datetime.fromtimestamp(ts) for ts in timestamps]

    # Calculate the interarrival time between consecutive packets
    interarrival_times = [datetime_timestamps[i] - datetime_timestamps[i-1] for i in range(1, len(datetime_timestamps))]

    # Plot the interarrival times
    plt.plot(datetime_timestamps[1:], interarrival_times)
    plt.xlabel('Timestamp')
    plt.ylabel('Interarrival Time')
    plt.title('Packet Interarrival Time')
    plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d %H:%M:%S'))
    plt.gcf().autofmt_xdate()
    plt.show()

    # Close the cursor
    cursor.close()

    # Close the connection
    conn.close()

# Visualize Packet Throughput Over Time:
def visualize_packet_throughput(db_file, interval=1):
    # Create a connection to the database
    conn = sqlite3.connect(db_file)

    # Read the relative timestamps and payload lengths from the table
    select_sql = 'SELECT relative_timestamp, tcp_payload_len FROM packets'
    cursor = conn.cursor()
    cursor.execute(select_sql)
    rows = cursor.fetchall()

    # Calculate the throughput over time
    timestamps = [row[0] for row in rows]
    payload_lengths = [row[1] for row in rows]
    throughput = [sum(payload_lengths[i:i+interval]) / interval for i in range(0, len(payload_lengths), interval)]

    # Convert timestamps to datetime objects
    datetime_timestamps = [datetime.datetime.fromtimestamp(ts) for ts in timestamps[::interval]]

    # Plot the throughput over time
    plt.plot(datetime_timestamps, throughput)
    plt.xlabel('Timestamp')
    plt.ylabel('Throughput')
    plt.title('Packet Throughput Over Time')
    plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d %H:%M:%S'))
    plt.gcf().autofmt_xdate()
    plt.show()

    # Close the cursor
    cursor.close()

    # Close the connection
    conn.close()

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
    datetime_timestamps = [datetime.datetime.fromtimestamp(ts) for ts in timestamps]

    # Plot the window size variation
    plt.plot(datetime_timestamps, window_sizes)
    plt.xlabel('Timestamp')
    plt.ylabel('Window Size')
    plt.title('Window Size Variation')
    plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d %H:%M:%S'))
    plt.gcf().autofmt_xdate()
    plt.show()

    # Close the cursor
    cursor.close()

    # Close the connection
    conn.close()

# Add more visualization functions as needed


# Example usage
if __name__ == '__main__':
    db_file = 'database.db'
    visualize_packet_flow_from_db(db_file)
    visualize_packet_duration_histogram(db_file)
