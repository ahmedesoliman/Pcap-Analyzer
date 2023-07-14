import networkx as nx
import matplotlib.pyplot as plt
import sqlite3


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

  # Close the cursor
  cursor.close()

  # Close the connection
  conn.close()

  return G


# Call the visualize_packet_flow_from_db function with the database file as an argument
graph = visualize_packet_flow_from_db('your_database.db')

# Position the nodes using a spring layout algorithm
pos = nx.spring_layout(graph, seed=42)

# Draw the nodes
nx.draw_networkx_nodes(graph, pos, node_size=500, node_color='lightblue')

# Draw the edges
nx.draw_networkx_edges(graph, pos, edge_color='gray', arrowsize=10)

# Draw labels for packet nodes
packet_labels = nx.get_node_attributes(graph, 'label')
nx.draw_networkx_labels(graph, pos, packet_labels, font_color='black')

# Draw labels for client and server nodes
nx.draw_networkx_labels(graph,
                        pos, {
                          'Client': 'Client',
                          'Server': 'Server'
                        },
                        font_color='red')

# Set plot title and display the diagram
plt.title('Packet Flow Diagram')
plt.axis('off')
plt.show()
