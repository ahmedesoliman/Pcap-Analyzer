import sqlite3
import database

import tkinter as tk  # For creating the main window in create_main_window function

from tkinter import ttk  # For Treeview widget in fetch_packets function
from tkinter import messagebox  # For displaying error messages in fetch_packets function



def fetch_packets():

  start_id = int(start_id_entry.get())
  end_id = int(end_id_entry.get())
  packets = fetch_packets_from_database(database_file, start_id, end_id)

  if packets:
    messagebox.showinfo("Packets", f"Fetched {len(packets)} packets!")
    display_packets(packets)
  else:
    messagebox.showinfo("No Packets",
                        "No packets found in the specified ID range.")


def fetch_packets_from_database(db_file, start_id, end_id):
  # Create a connection to the database
  conn = sqlite3.connect(db_file)

  # Create a cursor object to execute SQL queries
  cursor = conn.cursor()

  # Execute the SELECT query to fetch packets within the specified ID range
  select_sql = 'SELECT * FROM packets WHERE id BETWEEN ? AND ?'
  cursor.execute(select_sql, (start_id, end_id))

  # Fetch all rows returned by the query
  rows = cursor.fetchall()

  # Close the cursor
  cursor.close()

  # Close the connection
  conn.close()

  return rows


def display_packets(packets):
  # Create a new window for displaying the packets
  window = tk.Toplevel()
  window.title("Fetched Packets")

  # Create a Treeview widget
  tree = ttk.Treeview(window)
  tree['columns'] = tuple(range(len(packets[0])))

  # Configure the column headings
  column_names = [desc[0] for desc in cursor.description]
  for i, name in enumerate(column_names):
    tree.heading(i, text=name)

  # Insert the rows into the Treeview
  for packet in packets:
    tree.insert('', 'end', values=packet)

  # Create a button to analyze the selected packet
  analyze_button = tk.Button(window,
                             text="Analyze Packet",
                             command=lambda: analyze_packet(tree.selection()))
  analyze_button.pack(pady=10)

  # Pack the Treeview to fill the window
  tree.pack(fill='both', expand=True)


def analyze_packet(selection):
  if selection:
    selected_packet = tree.item(selection[0])['values']
    print("Selected Packet:", selected_packet)
    # Add your analysis code here for the selected packet
  else:
    messagebox.showinfo("No Packet Selected",
                        "Please select a packet to analyze.")


def create_main_window():
  # Create the main window
  window = tk.Tk()
  window.title("Packet Analyzer")

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
  fetch_button = tk.Button(window, text="Fetch Packets", command=fetch_packets)
  fetch_button.pack(pady=10)

  # Run the main event loop
  window.mainloop()


if __name__ == "__main__":
  database_file = 'database.db'
  create_main_window()
