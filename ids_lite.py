from collections import defaultdict
import time

FILE_NAME = "traffic_logs.txt"

ip_counter = defaultdict(int)

THRESHOLD = 3

print("🛡️ Starting IDS Monitor...\n")
time.sleep(1)

try:
    with open(FILE_NAME, "r") as file:
        logs = file.readlines()

except FileNotFoundError:
    print("❌ Log file not found!")
    exit()

print("🔍 Analyzing traffic...\n")
time.sleep(1)

for log in logs:
    parts = log.strip().split()

    if len(parts) < 3:
        continue

    ip = parts[0]
    action = parts[1]
    endpoint = parts[2]

    ip_counter[ip] += 1

    print(f"{ip} → {action} {endpoint}")

    # كشف فوري
    if ip_counter[ip] == THRESHOLD:
        print(f"\n🚨 ALERT: Suspicious activity detected from {ip}\n")

print("\n📊 FINAL REPORT")
print("-" * 30)

for ip, count in ip_counter.items():
    if count >= THRESHOLD:
        print(f"{ip} → {count} requests ⚠️ Suspicious")
    else:
        print(f"{ip} → {count} requests OK")

print("\n✅ Monitoring finished.")
