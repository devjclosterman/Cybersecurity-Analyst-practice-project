import re
from collections import Counter

# Load the log file
with open("access.log") as f:
    logs = f.readlines()

failed_logins = []
for line in logs:
    if "401" in line and "/login" in line:
        ip = re.match(r"(\d+\.\d+\.\d+\.\d+)", line).group(1)
        failed_logins.append(ip)

counter = Counter(failed_logins)

print("Suspicious IPs (more than 3 failed logins):")
for ip, count in counter.items():
    if count >= 3:
        print(f"{ip} -> {count} failed attempts")
