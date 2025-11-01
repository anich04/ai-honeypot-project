import os
import requests
import json
from datetime import datetime

SUPABASE_URL = "https://strbucnktdopbypbxqji.supabase.co"
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_KEY")
TABLE_NAME = "traffic_raw"

HONEYPOT_LOG = "logs/honeypot_activity.log"


def get_suspicious_ips():
    """Fetch IPs labeled as suspicious from Supabase"""
    headers = {
        "apikey": SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}",
        "Content-Type": "application/json",
    }

    url = f"{SUPABASE_URL}/rest/v1/{TABLE_NAME}?label=eq.suspicious&select=src_ip"
    res = requests.get(url, headers=headers)

    if res.status_code != 200:
        print(f"[!] Failed to fetch suspicious IPs: {res.text}")
        return []

    data = res.json()
    return list({row["src_ip"] for row in data if row.get("src_ip")})


def engage_honeypot(ip_list):
    """Mock engagement (simulates honeypot activation)"""
    if not ip_list:
        print("[*] No suspicious IPs found to engage.")
        return

    os.makedirs("logs", exist_ok=True)
    with open(HONEYPOT_LOG, "a") as log:
        for ip in ip_list:
            log_entry = {
                "timestamp": datetime.utcnow().isoformat(),
                "honeypot_id": "cowrie-01",
                "attacker_ip": ip,
                "action": "Honeypot engaged",
            }
            log.write(json.dumps(log_entry) + "\n")
            print(f"[+] Engaged honeypot against {ip}")

    print(f"[+] Honeypot log saved → {HONEYPOT_LOG}")


def main():
    print("=== Phase 4: Honeypot Engagement ===")
    if not SUPABASE_KEY:
        print("[!] Missing Supabase service key! Export it before running.")
        return

    suspicious_ips = get_suspicious_ips()
    print(f"[*] Found {len(suspicious_ips)} suspicious IPs: {suspicious_ips}")
    engage_honeypot(suspicious_ips)


if __name__ == "__main__":
    main()
