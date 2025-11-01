# phase5_metrics.py
import os
import pandas as pd
import requests
from datetime import datetime

# === Supabase Configuration ===
SUPABASE_URL = "https://strbucnktdopbypbxqji.supabase.co"
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY")

HEADERS = {
    "apikey": SUPABASE_SERVICE_KEY,
    "Authorization": f"Bearer {SUPABASE_SERVICE_KEY}",
    "Content-Type": "application/json"
}

TRAFFIC_TABLE = "traffic_raw"
THREAT_TABLE = "threat_events"
OUTPUT_FILE = "logs/metrics_summary.csv"

def fetch_data(table):
    """Fetch table data from Supabase REST API"""
    res = requests.get(f"{SUPABASE_URL}/rest/v1/{table}?select=*", headers=HEADERS)
    if res.status_code != 200:
        print(f"[!] Failed to fetch {table}: {res.status_code} -> {res.text}")
        return pd.DataFrame()
    data = res.json()
    print(f"[+] Retrieved {len(data)} records from {table}")
    return pd.DataFrame(data)

def compute_metrics(traffic_df, threat_df):
    """Compute security analytics metrics"""
    if traffic_df.empty or threat_df.empty:
        print("[!] Missing data for metric computation.")
        return pd.DataFrame()

    # Basic aggregations
    total_requests = len(traffic_df)
    total_threats = len(threat_df)
    unique_attackers = threat_df["ip"].nunique() if "ip" in threat_df.columns else 0

    # Most frequent attacker IP
    top_attacker = (
        threat_df["ip"].value_counts().idxmax()
        if not threat_df.empty and "ip" in threat_df.columns
        else "N/A"
    )

    # Group by label (normal, suspicious, malicious)
    label_stats = (
        traffic_df["label"].value_counts().to_dict()
        if "label" in traffic_df.columns
        else {}
    )

    # Create metrics DataFrame
    metrics = {
        "timestamp": datetime.utcnow().isoformat(),
        "total_requests": total_requests,
        "total_threats": total_threats,
        "unique_attackers": unique_attackers,
        "top_attacker": top_attacker,
        "label_distribution": str(label_stats),
    }

    df_metrics = pd.DataFrame([metrics])
    print("\n=== Metrics Summary ===")
    print(df_metrics.T)
    return df_metrics

def save_metrics(df):
    """Save computed metrics locally"""
    os.makedirs("logs", exist_ok=True)
    df.to_csv(OUTPUT_FILE, index=False)
    print(f"\n[+] Metrics saved to {OUTPUT_FILE}")

def upload_metrics(df):
    """Optional: Upload metrics summary back to Supabase"""
    TABLE = "metrics"
    res = requests.post(f"{SUPABASE_URL}/rest/v1/{TABLE}", headers=HEADERS, json=df.to_dict(orient="records"))
    if res.status_code in (200, 201):
        print(f"[+] Metrics uploaded to Supabase ({TABLE}) successfully!")
    else:
        print(f"[!] Metrics upload failed: {res.status_code} -> {res.text}")

def main():
    print("=== Phase 5: Metrics & Monitoring ===")
    traffic_df = fetch_data(TRAFFIC_TABLE)
    threat_df = fetch_data(THREAT_TABLE)

    if traffic_df.empty or threat_df.empty:
        print("[!] Aborting — one or more datasets are empty.")
        return

    metrics_df = compute_metrics(traffic_df, threat_df)
    save_metrics(metrics_df)
    upload_metrics(metrics_df)

if __name__ == "__main__":
    main()
