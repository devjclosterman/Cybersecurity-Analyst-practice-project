import re
from collections import Counter

def load_logs(filename="access.log"):
    with open(filename) as f:
        return f.readlines()

def detect_failed_logins(logs, threshold=3):
    failed_logins = []
    for line in logs:
        if "401" in line and "/login" in line:
            ip = re.match(r"(\d+\.\d+\.\d+\.\d+)", line).group(1)
            failed_logins.append(ip)
    counter = Counter(failed_logins)
    return {ip: count for ip, count in counter.items() if count >= threshold}

def detect_admin_access(logs):
    suspicious = []
    for line in logs:
        if "/admin" in line or "/wp-admin" in line:
            ip = re.match(r"(\d+\.\d+\.\d+\.\d+)", line).group(1)
            suspicious.append(ip)
    return set(suspicious)

def detect_external_ips(logs):
    external_ips = []
    for line in logs:
        ip = re.match(r"(\d+\.\d+\.\d+\.\d+)", line).group(1)
        if not (ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.")):
            external_ips.append(ip)
    return set(external_ips)

def save_report(brute_force, admin_hits, external_ips, filename="report.txt"):
    with open(filename, "w") as f:
        f.write("=== Security Analysis Report ===\n\n")

        f.write("Brute Force Attempts:\n")
        for ip, count in brute_force.items():
            f.write(f"{ip} -> {count} failed logins\n")
        f.write("\n")

        f.write("Admin Page Access Attempts:\n")
        for ip in admin_hits:
            f.write(f"{ip}\n")
        f.write("\n")

        f.write("External IP Access Detected:\n")
        for ip in external_ips:
            f.write(f"{ip}\n")

if __name__ == "__main__":
    logs = load_logs()

    brute_force = detect_failed_logins(logs)
    admin_hits = detect_admin_access(logs)
    external_ips = detect_external_ips(logs)

    save_report(brute_force, admin_hits, external_ips)
    print("✅ Report generated in report.txt")
