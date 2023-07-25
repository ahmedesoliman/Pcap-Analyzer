import argparse
import sqlite3
import pandas as pd  # For printing packet data in print_packet_data function


#Popular URLs Analysis:
def analyze_popular_urls(db_file, top_n=10):
  conn = sqlite3.connect(db_file)
  query = '''
        SELECT src_ip, dst_ip, tcp_payload
        FROM packets
        WHERE tcp_payload LIKE '%HTTP%'
    '''
  df = pd.read_sql_query(query, conn)

  # Extract URLs from HTTP requests
  df['url'] = df['tcp_payload'].str.extract(r'GET ([^\s]+) HTTP')

  # Count occurrences of each URL
  popular_urls = df['url'].value_counts().nlargest(top_n)

  conn.close()
  return popular_urls


#User-Agent Analysis:
def analyze_user_agents(db_file, top_n=10):
  conn = sqlite3.connect(db_file)
  query = '''
        SELECT src_ip, dst_ip, tcp_payload
        FROM packets
        WHERE tcp_payload LIKE '%User-Agent:%'
    '''
  df = pd.read_sql_query(query, conn)

  # Extract User-Agent values from HTTP requests
  df['user_agent'] = df['tcp_payload'].str.extract(r'User-Agent: ([^\r\n]+)')

  # Count occurrences of each User-Agent
  user_agents = df['user_agent'].value_counts().nlargest(top_n)

  conn.close()
  return user_agents


#Security Header Analysis:
def analyze_security_headers(db_file):
  conn = sqlite3.connect(db_file)
  query = '''
        SELECT src_ip, dst_ip, tcp_payload
        FROM packets
        WHERE tcp_payload LIKE '%HTTP%'
    '''
  df = pd.read_sql_query(query, conn)

  # Extract security-related headers from HTTP responses
  security_headers = df['tcp_payload'].str.extractall(
    r'(Strict-Transport-Security:|X-Frame-Options:|Content-Security-Policy:|X-XSS-Protection:|X-Content-Type-Options:|X-Content-Security-Policy:) ([^\r\n]+)'
  )

  conn.close()
  return security_headers


#HTTPS Adoption Analysis:
def analyze_https_adoption(db_file):
  conn = sqlite3.connect(db_file)
  query = '''
        SELECT src_ip, dst_ip, tcp_payload
        FROM packets
        WHERE tcp_payload LIKE '%HTTP%'
    '''
  df = pd.read_sql_query(query, conn)

  # Count occurrences of HTTP and HTTPS requests
  http_vs_https = df['tcp_payload'].str.extract(
    r'([A-Z]+) (https?:\/\/[^\s]+) HTTP')
  https_count = (http_vs_https[0] == 'CONNECT').sum()
  http_count = (http_vs_https[0] == 'GET').sum()

  conn.close()
  return https_count, http_count


#Authentication Analysis:
def analyze_authentication_headers(db_file):
  conn = sqlite3.connect(db_file)
  query = '''
        SELECT src_ip, dst_ip, tcp_payload
        FROM packets
        WHERE tcp_payload LIKE '%Authorization:% OR tcp_payload LIKE '%WWW-Authenticate:%'
    '''
  df = pd.read_sql_query(query, conn)

  # Extract authentication-related headers from HTTP requests and responses
  auth_headers = df['tcp_payload'].str.extractall(
    r'(Authorization:|WWW-Authenticate:) ([^\r\n]+)')

  conn.close()
  return auth_headers


# Suspicious URL Patterns Analysis:
def analyze_suspicious_url_patterns(db_file):
  conn = sqlite3.connect(db_file)
  query = '''
        SELECT src_ip, dst_ip, tcp_payload
        FROM packets
        WHERE tcp_payload LIKE '%HTTP%'
    '''
  df = pd.read_sql_query(query, conn)

  # Identify suspicious URL patterns using regular expressions
  suspicious_urls = df['tcp_payload'].str.extractall(
    r'GET ([^\s]+) HTTP').reset_index(drop=True)
  suspicious_urls.columns = ['url']

  suspicious_patterns = suspicious_urls[suspicious_urls['url'].str.contains(
    r'sql|cmd|php|jsp|asp', case=False, na=False)]

  conn.close()
  return suspicious_patterns


if __name__ == '__main__':
  parser = argparse.ArgumentParser(description='Network Traffic Analysis')
  parser.add_argument('database_file',
                      type=str,
                      help='Path to the SQLite database file')
  args = parser.parse_args()

  database_file = args.database_file
  popular_urls = analyze_popular_urls(database_file)
  user_agents = analyze_user_agents(database_file)
  security_headers = analyze_security_headers(database_file)
  https_count, http_count = analyze_https_adoption(database_file)
  auth_headers = analyze_authentication_headers(database_file)
  suspicious_patterns = analyze_suspicious_url_patterns(database_file)

  # Display the results
  print("----- Popular URLs Analysis -----")
  print(popular_urls)

  print("\n----- User-Agent Analysis -----")
  print(user_agents)

  print("\n----- Security Headers Analysis -----")
  print(security_headers)

  print("\n----- HTTPS Adoption Analysis -----")
  print(f"HTTPS Requests: {https_count}")
  print(f"HTTP Requests: {http_count}")

  print("\n----- Authentication Headers Analysis -----")
  print(auth_headers)

  print("\n----- Suspicious URL Patterns Analysis -----")
  print(suspicious_patterns)
