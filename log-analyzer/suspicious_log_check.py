import re
from datetime import datetime
import ipaddress
from collections import defaultdict



BURST_THRESHOLD = 5
LOG_FILE = "web_activity.log"
REPORT_FILE = "suspicious_activity_report.txt"


# Read the log file
def read_log_file(file_path):
    try:
        with open(LOG_FILE, "r") as file:
            log_lines = file.readlines()
    except FileNotFoundError:
        print(f"Log file {LOG_FILE} not found.")
        exit(1)
    return log_lines

# Create a list to store parsed log entries
log_entries = []
unmatched_entries = []

# Parse each log line
current_ip = None
ip_entry_pattern = re.compile(r'^(\d+\.\d+\.\d+\.\d+):')


log_lines = read_log_file(LOG_FILE)
for line in log_lines:
    ip_match = ip_entry_pattern.match(line)
    if ip_match:
        current_ip = ip_match.group(1)
        continue

    # Match the log format using regex pattern
    pattern = r'''
    (?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.000Z)
    \s+
    (?P<method>GET|POST)
    \s+
    "(?P<path>[^"]+)"
    (?:\s+\{authorizedUserId:\s+"(?P<user_id>[^"]+)"\})?
    \s+
    (?P<status>\d{3})
    '''

    match = re.search(pattern, line, re.VERBOSE)
    if match:
        entry = {
            "ip": current_ip,
            "timestamp": datetime.strptime(match.group('timestamp'), '%Y-%m-%dT%H:%M:%S.000Z'),
            "method": match.group('method'),
            "path": match.group('path'),
            "user_id": match.group('user_id'),
            "status": int(match.group('status')),
        }
        # Append the parsed entry to the log_entries list
        log_entries.append(entry)
    else:
        unmatched_entries.append(line.strip())

# # Print the parsed log entries
# for entry in log_entries:
#     print(entry)

"""
External IP Detection
This function checks for requests from external IP addresses.
"""
def is_external_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return not (ip_obj.is_private or ip_obj.is_loopback)
    except ValueError:
        return False

"""
Wild Card Query Detection
This function checks for suspicious log entries that contain wildcards(*) in the path.
"""
def detect_wildcard_query(log_entries):
    return [e for e in log_entries if '*' in e.get('path', '')]


"""
Burst Access Detection
-This function checks for burst access patterns by counting requests from the same user within a short time frame.
-This is potential use of automated scripts or brute force attacks.
"""
def detect_burst_access(entries):
    user_counts = defaultdict(int)
    burst_entries = []
    for entry in entries:
        if entry['user_id']:
            user_counts[entry['user_id']] += 1
            if user_counts[entry['user_id']] > BURST_THRESHOLD:
                burst_entries.append(entry)
    return burst_entries

"""
Factory Access Detection
-This function will check how many different factories a user has accessed.
-If a user accesses multiple factories in a short time, it may indicate suspicious activity.
-This suggests that a user is scanning the entire system. 
"""
def detect_factory_access(log_entries):
    factory_access_entries = []
    user_factory_access = {}

    for entry in log_entries:
        user_id = entry['user_id']
        if user_id:
            match = re.search(r'factory=([\w*]+)', entry['path'])
            if match:
                factory_id = match.group(1)
                if user_id not in user_factory_access:
                    user_factory_access[user_id] = set()
                user_factory_access[user_id].add(factory_id)
                if len(user_factory_access[user_id]) > 1:
                    factory_access_entries.append(entry)
    return factory_access_entries

# Run the detection functions
wildcard_suspicious = detect_wildcard_query(log_entries)
burst_suspicious = detect_burst_access(log_entries)
factory_suspicious = detect_factory_access(log_entries)

# Combine all suspicious entries
suspicious_entries = wildcard_suspicious + burst_suspicious + factory_suspicious

# Filter entries with external IPs
external_suspicious_entries = [entry for entry in suspicious_entries if is_external_ip(entry['ip'])]

# Merge and sort all unique suspicious entries
suspicious_entries = list({id(entry): entry for entry in wildcard_suspicious + burst_suspicious + factory_suspicious}.values())
suspicious_entries.sort(key=lambda e: e['timestamp'])


# Function to write a section to the report file
def write_section(report, title, entries):
    if entries:
        report.write(f"{title}:\n")
        for entry in entries:
            line = f"- {entry['timestamp']} | {entry['user_id']} | {entry['path']}\n"
            report.write(line)
        report.write("\n")

# Save the suspicious entries to a file
def save_suspicious_entries():
   with open(REPORT_FILE, "w") as report:
    report.write("Suspicious Activity Report\n")
    report.write("=" * 30 + "\n\n")

    write_section(report, "External IP Suspicious Activity", external_suspicious_entries)
    write_section(report, "Wildcard Queries", wildcard_suspicious)
    write_section(report, "Burst Access Detected", burst_suspicious)
    write_section(report, "Factory Scan Behavior", factory_suspicious)

    report.write(f"Total Unique Suspicious Requests: {len(suspicious_entries)}\n")


def write_unmatched_entries():
    with open("rejected_lines.log", "w") as f:
        f.writelines(unmatched_entries)


save_suspicious_entries()
print("Suspicious activity written to 'suspicious_activity_report.txt'")