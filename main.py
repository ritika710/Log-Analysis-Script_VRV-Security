import re
import csv
from collections import defaultdict
# Parse the log file
log_file = "sample.log"
request_counts = defaultdict(int)
endpoint_counts = defaultdict(int)
failed_logins = defaultdict(int)

FAILED_LOGIN_THRESHOLD = 10  # Configurable threshold for suspicious activity

# Regular expressions for parsing log entries
log_pattern = r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[.*?\] "(?:GET|POST|PUT|DELETE|HEAD|OPTIONS) (?P<endpoint>\/\S*) HTTP\/\d\.\d" (?P<status>\d+)'
failed_login_pattern = r'401'

# Process the log file
with open(log_file, "r") as file:
    for line in file:
        match = re.match(log_pattern, line)
        if match:
            ip = match.group("ip")
            endpoint = match.group("endpoint")
            status = match.group("status")

            # Count requests per IP
            request_counts[ip] += 1

            # Count requests per endpoint
            endpoint_counts[endpoint] += 1

            # Check for failed login attempts
            if re.search(failed_login_pattern, status):
                failed_logins[ip] += 1

# Sort and analyze the data
sorted_requests = sorted(request_counts.items(), key=lambda x: x[1], reverse=True)
most_accessed_endpoint = max(endpoint_counts.items(), key=lambda x: x[1])
suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD}

# Display the results
print("IP Address           Request Count")
for ip, count in sorted_requests:
    print(f"{ip:<20} {count}")

print(f"\nMost Frequently Accessed Endpoint: {most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

if suspicious_ips:
    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, count in suspicious_ips.items():
        print(f"{ip:<20} {count}")
else:
    print("\nNo suspicious activity detected.")

# Save the results to a CSV file
csv_file = "log_analysis_results.csv"
with open(csv_file, "w", newline="") as file:
    writer = csv.writer(file)

    # Write Requests per IP
    writer.writerow(["IP Address", "Request Count"])
    writer.writerows(sorted_requests)

    # Write Most Accessed Endpoint
    writer.writerow([])
    writer.writerow(["Most Accessed Endpoint", "Access Count"])
    writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])

    # Write Suspicious Activity
    writer.writerow([])
    writer.writerow(["IP Address", "Failed Login Count"])
    writer.writerows(suspicious_ips.items())

print(f"\nResults saved to {csv_file}")
