# phase3_supabase_upload.py
import os
import pandas as pd
import requests
from datetime import datetime, timezone
import numpy as np

# === CONFIG ===
SUPABASE_URL = "https://strbucnktdopbypbxqji.supabase.co"
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY")
TABLE_NAME = "traffic_raw"
INPUT_CSV = "logs/traffic_log_labeled.csv"

def upload_to_supabase(df):
    """Upload cleaned DataFrame to Supabase"""
    headers = {
        "apikey": SUPABASE_SERVICE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_KEY}",
        "Content-Type": "application/json"
    }

    # Replace invalid values (NaN, inf, None, np.nan)
    df = df.replace([np.inf, -np.inf], None)
    df = df.fillna("")  # <--- Replace all NaN/None with empty strings (safe for JSON)
    df["uploaded_at"] = datetime.now(timezone.utc).isoformat()

    payload = df.to_dict(orient="records")

    try:
        res = requests.post(
            f"{SUPABASE_URL}/rest/v1/{TABLE_NAME}",
            headers=headers,
            json=payload
        )
        if res.status_code not in (200, 201):
            print(f"[!] Upload failed: {res.status_code}")
            print(res.text)
        else:
            print(f"[+] Uploaded {len(df)} records successfully!")
    except Exception as e:
        print(f"[!] Error during upload: {e}")

def main():
    print("=== Phase 3: Upload to Supabase ===")

    if not os.path.exists(INPUT_CSV):
        print(f"[!] Missing file: {INPUT_CSV}. Run Phase 2 first.")
        return

    df = pd.read_csv(INPUT_CSV)
    print(f"[*] Loaded {len(df)} records from {INPUT_CSV}")

    # Replace all invalid float types before upload
    df = df.replace([np.inf, -np.inf], None)
    df = df.fillna("")

    upload_to_supabase(df)

if __name__ == "__main__":
    main()
