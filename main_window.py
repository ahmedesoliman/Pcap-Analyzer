import sqlite3
import tkinter as tk
from tkinter import messagebox
import database


def fetch_packets():
  start_id = int(start_id_entry.get())
  end_id = int(end_id_entry.get())
  packets = database.fetch_packets(database_file, start_id, end_id)

  if packets:
    messagebox.showinfo("Packets", f"Fetched {len(packets)} packets!")
    for packet in packets:
      print(packet)
  else:
    messagebox.showinfo("No Packets",
                        "No packets found in the specified ID range.")


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
