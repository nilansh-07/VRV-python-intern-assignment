import re
import csv
from collections import Counter
from prettytable import PrettyTable

# Web Server Log Analyzer
# ----------------------
# This script analyzes web server logs to track traffic patterns and detect security threats.
# It generates reports in HTML, CSV, and terminal formats.
# Author: Nilansh Kumar

# Configuration
log_file_path = "sample.log"
output_csv_path = "web_log_analysis_results.csv"
output_html_path = "web_log_analysis_report.html"
FAILED_LOGIN_THRESHOLD = 5

def parse_log_file(file_path):
    """
    Parses web server logs into structured data.

    Args:
        file_path (str): Path to the log file.

    Returns:
        list: A list of dictionaries containing IP, method, endpoint, and status.
    """
    with open(file_path, "r") as file:
        logs = file.readlines()
    log_data = []
    log_pattern = re.compile(
        r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[.*?\] "(?P<method>\w+) (?P<endpoint>\S+) HTTP/\d+\.\d+" (?P<status>\d+) .*'
    )
    for line in logs:
        match = log_pattern.match(line)
        if match:
            log_data.append(match.groupdict())
    return log_data

def analyze_requests_per_ip(log_data):
    """
    Counts requests from each IP address.

    Args:
        log_data (list): Parsed log entries.

    Returns:
        list: A list of tuples with IP and request count, sorted by count.
    """
    ip_counter = Counter(log['ip'] for log in log_data)
    return ip_counter.most_common()

def analyze_most_accessed_endpoint(log_data):
    """
    Finds the most frequently accessed endpoint.

    Args:
        log_data (list): Parsed log entries.

    Returns:
        tuple: A tuple of (endpoint, count) or None if no endpoint is found.
    """
    endpoint_counter = Counter(log['endpoint'] for log in log_data)
    most_accessed = endpoint_counter.most_common(1)
    return most_accessed[0] if most_accessed else None

def detect_suspicious_activity(log_data, threshold=FAILED_LOGIN_THRESHOLD):
    """
    Identifies IPs with excessive failed logins.

    Args:
        log_data (list): Parsed log entries.
        threshold (int): Failed login limit.

    Returns:
        dict: A dictionary of suspicious IPs and their failed counts.
    """
    failed_login_counter = Counter(
        log['ip'] for log in log_data if log['status'] == '401'
    )
    suspicious_ips = {ip: count for ip, count in failed_login_counter.items() if count > threshold}
    return suspicious_ips

def save_to_csv(ip_requests, most_accessed_endpoint, suspicious_activity, output_path):
    """
    Exports analysis results to a CSV file.

    Args:
        ip_requests (list): IP traffic data.
        most_accessed_endpoint (tuple): Popular endpoint data.
        suspicious_activity (dict): Security alerts.
        output_path (str): Target file path.
    """
    with open(output_path, mode='w', newline='') as csv_file:
        writer = csv.writer(csv_file)

        # Write requests per IP
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_requests:
            writer.writerow([ip, count])

        # Write most accessed endpoint
        writer.writerow([])
        writer.writerow(["Most Frequently Accessed Endpoint", "Access Count"])
        if most_accessed_endpoint:
            writer.writerow(most_accessed_endpoint)

        # Write suspicious activity
        writer.writerow([])
        writer.writerow(["Suspicious Activity Detected"])
        writer.writerow(["IP Address", "Failed Login Attempts"])
        for ip, count in suspicious_activity.items():
            writer.writerow([ip, count])

def save_to_html(ip_requests, most_accessed_endpoint, suspicious_activity, output_path):
    """
    Generates an interactive HTML report.

    Args:
        ip_requests (list): IP traffic data.
        most_accessed_endpoint (tuple): Popular endpoint data.
        suspicious_activity (dict): Security alerts.
        output_path (str): Target file path.
    """
    with open(output_path, "w") as html_file:
        html_file.write("""
<html>
  <head>
    <title>Log Analysis Report</title>
    <style>
      body {
        font-family: Arial, sans-serif;
        margin: 20px;
        background-color: #f4f4f9;
        color: #333;
      }
      h1, h2 {
        text-align: center;
        color: #0047ab;
      }
      table {
        width: 80%;
        margin: 20px auto;
        border-collapse: collapse;
        box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
        background-color: #ffffff;
      }
      th, td {
        border: 1px solid #dddddd;
        text-align: center;
        padding: 10px;
      }
      th {
        background-color: #0047ab;
        color: white;
        font-weight: bold;
      }
      tr:nth-child(even) {
        background-color: #f9f9f9;
      }
      tr:hover {
        background-color: #f1f1f1;
      }
    </style>
  </head>
  <body>
    <h1>Log Analysis Report</h1>
    <h2>Requests Per IP</h2>
    <table>
      <tr>
        <th>IP Address</th>
        <th>Request Count</th>
      </tr>
""")
        for ip, count in ip_requests:
            html_file.write(f"      <tr><td>{ip}</td><td>{count}</td></tr>\n")
        html_file.write("""
    </table>
    <h2>Most Frequently Accessed Endpoint</h2>
""")
        if most_accessed_endpoint:
            html_file.write(f"    <p>{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)</p>\n")
        else:
            html_file.write("    <p>No endpoints accessed.</p>\n")
        html_file.write("""
    <h2>Suspicious Activity Detected</h2>
    <table>
      <tr>
        <th>IP Address</th>
        <th>Failed Login Attempts</th>
      </tr>
""")
        for ip, count in suspicious_activity.items():
            html_file.write(f"      <tr><td>{ip}</td><td>{count}</td></tr>\n")
        html_file.write("""
    </table>
  </body>
</html>
""")

def display_results(ip_requests, most_accessed_endpoint, suspicious_activity):
    """
    Displays results in the terminal using formatted tables.

    Args:
        ip_requests (list): IP traffic data.
        most_accessed_endpoint (tuple): Popular endpoint data.
        suspicious_activity (dict): Security alerts.
    """
    print("\n=== Requests Per IP ===")
    table = PrettyTable(["IP Address", "Request Count"])
    for ip, count in ip_requests:
        table.add_row([ip, count])
    print(table)

    print("\n=== Most Frequently Accessed Endpoint ===")
    if most_accessed_endpoint:
        print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
    else:
        print("No endpoints accessed.")

    print("\n=== Suspicious Activity Detected ===")
    if suspicious_activity:
        suspicious_table = PrettyTable(["IP Address", "Failed Login Attempts"])
        for ip, count in suspicious_activity.items():
            suspicious_table.add_row([ip, count])
        print(suspicious_table)
    else:
        print("No suspicious activity detected.")

def main():
    """
    Runs the complete analysis workflow: Parse logs, analyze data, and generate reports.
    """
    log_data = parse_log_file(log_file_path)

    ip_requests = analyze_requests_per_ip(log_data)
    most_accessed_endpoint = analyze_most_accessed_endpoint(log_data)
    suspicious_activity = detect_suspicious_activity(log_data)

    display_results(ip_requests, most_accessed_endpoint, suspicious_activity)

    save_to_csv(ip_requests, most_accessed_endpoint, suspicious_activity, output_csv_path)

    save_to_html(ip_requests, most_accessed_endpoint, suspicious_activity, output_html_path)

    print(f"\nResults saved to {output_csv_path} and {output_html_path}")

if __name__ == "__main__":
    main()
