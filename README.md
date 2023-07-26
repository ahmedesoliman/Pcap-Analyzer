## Main.py

The provided code is a Python script that performs packet analysis and visualization tasks based on data stored in an SQLite database. The script imports various libraries, defines several functions for packet analysis and visualization, and demonstrates how to use these functions. The script also includes analysis functions for HTTP-related information, such as popular URLs, User-Agent values, security headers, HTTPS adoption, authentication headers, and suspicious URL patterns.

### Here's an overview of the main components and functionalities of the script:

### Libraries and Imports:

The script imports various libraries required for packet analysis, data processing, visualization, and database operations.

### Visualization Functions:

The script defines several visualization functions using the matplotlib and networkx libraries to visualize packet flow, packet duration histogram, packet size distribution, packet sequence numbers, packet interarrival time, packet throughput, window size variation, and round-trip time (RTT) distribution.

### Packet Analysis Functions:

The script provides functions to analyze various aspects of the captured packets, such as calculating packet interarrival time, packet duration, and RTT. Additionally, it includes functions to analyze HTTP-related information, such as popular URLs, User-Agent values, security headers, HTTPS adoption, authentication headers, and suspicious URL patterns.

### Database Interaction:

The script interacts with an SQLite database to store and retrieve packet data. It creates a table named "packets" with appropriate columns to store packet information.

### Interactive Analysis:

The script offers an interactive function called select_and_analyze_packets that allows users to select and analyze individual packets from the database. It displays packet information and performs example analysis, such as calculating packet duration.

### Main Execution:

The script provides a main block that demonstrates how to use the various visualization and analysis functions. It loads packet data from a pcap file, converts and stores it in the SQLite database, and then calls the print_packet_data function to display packet details. It also calls the HTTP-related analysis functions to analyze HTTP traffic information.

Please note that this is just an overview of the script's functionality. Depending on the specific use case and the structure of the SQLite database and pcap file, additional adjustments or modifications might be required to tailor the script to specific requirements.

Before running the script, ensure that the required libraries are installed. You can install missing libraries using pip, e.g.

```shell
pip install matplotlib networkx pandas scapy tqdm prettytable
```

Also, ensure you have the required pcap file in the specified location (pcap_file variable) before running the script.

### The required libraries and how to install them on the shell before running the program:

- scapy: A powerful packet manipulation library for Python. To install scapy, use pip:

```shell
pip install scapy
```

- pandas: A library for data manipulation and analysis. To install pandas, use pip:

```shell
pip install pandas
```

- pickle: A library for serializing and deserializing Python objects. To install pickle, use pip:

```shell
pip install pickle
```

- sqlite3: A library for SQLite database operations. To install sqlite3, use pip:

```shell
pip install sqlite3
```

- matplotlib: A library for data visualization. To install matplotlib, use pip:

```shell
pip install matplotlib
```

- networkx: A library for graph visualization. To install networkx, use pip:

```shell
pip install networkx
```

- datetime: A library for manipulating dates and times. To install datetime, use pip:

```shell
pip install datetime
```

- tqdm: A library for adding progress bars to loops. To install tqdm, use pip:

```shell
pip install tqdm
```

- prettytable: A library for formatted tables. To install prettytable, use pip:

```shell
pip install prettytable
```

- argparse: A library for parsing command-line arguments. To install argparse, use pip:

```shell
pip install argparse
```

Make sure you have Python installed on your system before proceeding with the library installations.

Once you have installed these libraries, you can run the program with the required dependencies. For example, you can run the program in your shell using the Python interpreter:

```shell
python your_program_name.py
```

Replace your_program_name.py with the actual name of your Python script. The program should then start executing with the necessary libraries available.

## Analyze.py:

The provided Python script named "analyze.py" contains functions to analyze a PCAP (Packet Capture) file using SQLite and Pandas. The script performs various analyses on the captured network traffic data. Here's a summary of each analysis function:

`analyze_popular_urls(db_file, top_n=10)`: This function analyzes the popular URLs accessed in the captured network traffic. It extracts HTTP requests from the payload and counts the occurrences of each URL, then returns the top N (default is 10) most popular URLs.

`analyze_user_agents(db_file, top_n=10)`: This function analyzes the User-Agent strings from the captured HTTP requests. It counts the occurrences of each User-Agent and returns the top N (default is 10) most common User-Agent strings.

`analyze_security_headers(db_file)`: This function analyzes security-related headers in the HTTP responses. It looks for specific headers like Strict-Transport-Security, X-Frame-Options, Content-Security-Policy, X-XSS-Protection, X-Content-Type-Options, and X-Content-Security-Policy. It extracts the values of these headers and returns the results.

`analyze_https_adoption(db_file)`: This function analyzes the adoption of HTTPS in the captured network traffic. It counts the occurrences of HTTP and HTTPS requests and returns the counts of each.

`analyze_authentication_headers(db_file)`: This function analyzes authentication-related headers in the captured HTTP requests and responses. It looks for headers like Authorization and WWW-Authenticate. It extracts the values of these headers and returns the results.

`analyze_suspicious_url_patterns(db_file)`: This function identifies suspicious URL patterns from the captured HTTP requests. It uses regular expressions to match URLs containing strings like "sql", "cmd", "php", "jsp", and "asp". It returns the URLs that match these patterns.

In the script's main block, it parses the command-line arguments to specify the path to the SQLite database file (representing the PCAP data). Then, it calls each analysis function and prints the results.

To use this script, you need to have Python and the required dependencies (Pandas and SQLite) installed on your system. You can run the script from the command line and pass the path to the SQLite database file as an argument. For example:

```console
python analyze.py path/to/pcap_data.db
```

The script will then execute all the analysis functions on the provided PCAP data and display the results for each analysis.

## Visualize.py

`visualize_packet_flow_from_db(db_file)`: This function creates a directed graph to visualize the packet flow between the client and server. It fetches packet data from the database and represents the packet flow as nodes and edges in the graph. The nodes 'Client' and 'Server' represent the client and server endpoints, respectively.

`visualize_packet_duration_histogram(db_file)`: This function visualizes the distribution of packet durations. It reads the relative timestamps of the packets from the database and plots a histogram to show the frequency of packet durations.

`visualize_packet_size_distribution(db_file)`: This function visualizes the distribution of packet sizes. It reads the TCP payload lengths of the packets from the database and plots a histogram to show the frequency of packet sizes.

`visualize_packet_sequence_numbers(db_file)`: This function visualizes the packet sequence numbers over time. It reads the sequence numbers and their directions (client to server or server to client) from the database. It then plots the sequence numbers on the y-axis against the packet index on the x-axis, differentiating between client-to-server and server-to-client packets.

`visualize_packet_interarrival_time(database_file)`: This function calculates and visualizes the interarrival time between consecutive packets. It calculates the time difference between each packet's relative timestamp and the previous packet's timestamp. The interarrival times are then plotted against their corresponding timestamps.

`visualize_packet_throughput(database_file)`: This function calculates and visualizes the packet throughput over time. It calculates the throughput as the number of bytes transmitted per second. The throughput values are plotted against their corresponding timestamps.

`visualize_window_size_variation(db_file)`: This function visualizes the variation of window sizes over time. It reads the window sizes and their timestamps from the database and plots them over time.

`visualize_rtt_from_db(database_file)`: This function calculates and visualizes the Round-Trip Time (RTT) values between consecutive packets. It calculates the time difference between packets with different directions (client-to-server and server-to-client) to obtain the RTT. It then plots a histogram of the RTT values and shows mean, median, and standard deviation as vertical lines on the plot.

Note: The functions assume that the database contains specific columns, such as 'direction', 'relative_timestamp', 'tcp_payload_len', 'seqno', 'window', etc. If your database schema is different, you may need to modify these functions accordingly.

To use these visualizations, you need to have Python and the required dependencies (Matplotlib, NetworkX, and datetime) installed on your system. You can run the script from the command line and pass the path to the SQLite database file as an argument. For example:

You can run the script from the shell command line and specify the function to be executed along with the path to the SQLite database file. For example:

```shell
python Visualize.py path/to/pcap_data.db --function packet_flow
```

This will execute the `visualize_packet_flow_from_db` function and display the packet flow diagram. Similarly, you can run other functions one by one by changing the `--function` argument.

For example:

```shell
python Visualize.py path/to/pcap_data.db --function duration_histogram
python Visualize.py path/to/pcap_data.db --function size_distribution
python Visualize.py path/to/pcap_data.db --function sequence_numbers
python Visualize.py path/to/pcap_data.db --function interarrival_time
python Visualize.py path/to/pcap_data.db --function throughput
python Visualize.py path/to/pcap_data.db --function window_size_variation
python Visualize.py path/to/pcap_data.db --function rtt
```

The script will then execute all the visualization functions on the provided database and display the plots for each visualization.
