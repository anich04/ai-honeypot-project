#!/usr/bin/env python3
"""
phase2_analyze.py
- Input: traffic_log.csv (from phase1_sniffer.py)
- Output: traffic_log_labeled.csv (adds label and cluster_id)
- Behavior:
    * If scikit-learn is installed, runs a simple KMeans clustering on numeric features.
    * Otherwise uses rule-based heuristics to mark suspicious traffic (SSH targets, many packets, large packets).
"""

import csv
import os
import sys
from datetime import datetime, timezone
from collections import Counter, defaultdict

INPUT_CSV = "logs/traffic_log.csv"            # produced by phase1_sniffer.py
OUTPUT_CSV = "logs/traffic_log_labeled.csv"   # produced by this script
USE_SKLEARN = True

# Try to import sklearn; fall back to rule-based if not present
try:
    from sklearn.preprocessing import StandardScaler
    from sklearn.cluster import KMeans
except Exception:
    USE_SKLEARN = False

def load_csv(path):
    rows = []
    if not os.path.exists(path):
        raise FileNotFoundError(f"{path} not found. Run phase1_sniffer.py first.")
    with open(path, newline='') as f:
        reader = csv.DictReader(f)
        for r in reader:
            # normalize column names that might vary
            row = {
                "timestamp": r.get("timestamp") or r.get("ts") or r.get("time"),
                "src_ip": r.get("src_ip") or r.get("src") or r.get("source"),
                "dst_ip": r.get("dst_ip") or r.get("dst") or r.get("destination"),
                "protocol": r.get("protocol") or r.get("proto") or r.get("protocol_name"),
                "packet_len": int(r.get("packet_len") or r.get("len") or 0),
                "src_port": int(r.get("src_port") or r.get("sport") or 0) if (r.get("src_port") or r.get("sport")) else 0,
                "dst_port": int(r.get("dst_port") or r.get("dport") or 0) if (r.get("dst_port") or r.get("dport")) else 0,
                "flags": r.get("flags") or r.get("tcp_flags") or ""
            }
            rows.append(row)
    return rows

def rule_based_label(rows):
    # Simple heuristics per-packet + per-src aggregation
    src_counts = Counter(r["src_ip"] for r in rows if r["src_ip"])
    labels = []
    for r in rows:
        label = "normal"
        # suspicious simple rules:
        # - packet to SSH (22)
        # - very large packet (>1200)
        # - src IP that generated many packets (>10)
        if r["dst_port"] == 22:
            label = "suspicious"
        if r["packet_len"] >= 1200:
            label = "suspicious"
        if src_counts.get(r["src_ip"], 0) > 10:
            label = "suspicious"
        labels.append({"row": r, "label": label, "cluster_id": -1})
    return labels

def sklearn_cluster_label(rows, k=3):
    # Build feature matrix: [packet_len, src_port, dst_port, proto_tcp_flag]
    X = []
    mapping_proto = {"tcp":1, "udp":0, "icmp":0, "other":0}
    for r in rows:
        proto = str(r["protocol"]).lower()
        proto_val = mapping_proto.get(proto, 0)
        X.append([r["packet_len"], r["src_port"], r["dst_port"], proto_val])
    import numpy as np
    X = np.array(X, dtype=float)
    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)
    model = KMeans(n_clusters=k, random_state=42, n_init=10)
    labels = model.fit_predict(Xs)
    # decide which clusters are suspicious: clusters with high avg packet_len or many dst_port 22 hits
    cluster_stats = {}
    for c in range(k):
        idxs = [i for i,l in enumerate(labels) if l==c]
        if not idxs:
            cluster_stats[c] = {"avg_len":0,"ssh_count":0,"size":0}
            continue
        avg_len = float(X[idxs,0].mean())
        ssh_count = int(sum(1 for i in idxs if rows[i]["dst_port"]==22))
        cluster_stats[c] = {"avg_len":avg_len,"ssh_count":ssh_count,"size":len(idxs)}
    # pick suspicious clusters: top by ssh_count then by avg_len
    sorted_clusters = sorted(cluster_stats.items(), key=lambda kv: (kv[1]["ssh_count"], kv[1]["avg_len"]), reverse=True)
    suspicious_clusters = set()
    if sorted_clusters:
        suspicious_clusters.add(sorted_clusters[0][0])  # mark top cluster suspicious
    # also mark tiny clusters as suspicious
    for c,st in cluster_stats.items():
        if st["size"] <= 2:
            suspicious_clusters.add(c)
    result = []
    for i,r in enumerate(rows):
        cl = int(labels[i])
        label = "suspicious" if cl in suspicious_clusters else "normal"
        result.append({"row": r, "label": label, "cluster_id": cl})
    return result

def save_labeled(rows_with_meta, outpath):
    # rows_with_meta: list of dict {"row":..., "label":..., "cluster_id":...}
    fieldnames = ["timestamp","src_ip","dst_ip","src_port","dst_port","protocol","packet_len","flags","label","cluster_id"]
    with open(outpath, "w", newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for item in rows_with_meta:
            r = item["row"]
            out = {
                "timestamp": r.get("timestamp") or datetime.now(timezone.utc).isoformat(),
                "src_ip": r.get("src_ip"),
                "dst_ip": r.get("dst_ip"),
                "src_port": r.get("src_port"),
                "dst_port": r.get("dst_port"),
                "protocol": r.get("protocol"),
                "packet_len": r.get("packet_len"),
                "flags": r.get("flags"),
                "label": item.get("label"),
                "cluster_id": item.get("cluster_id")
            }
            writer.writerow(out)
    print(f"[+] Saved labeled CSV -> {outpath}")

def main():
    print("\n=== Phase 2: Traffic Analysis & Labeling ===")
    rows = load_csv(INPUT_CSV)
    if not rows:
        print("[!] No rows loaded from", INPUT_CSV); return
    print(f"[*] Loaded {len(rows)} packets from {INPUT_CSV}")

    if USE_SKLEARN:
        try:
            labeled = sklearn_cluster_label(rows, k=3)
            print("[*] Used sklearn KMeans clustering for labeling")
        except Exception as e:
            print("[!] sklearn failed or not usable:", e)
            print("[*] Falling back to rule-based labeling")
            labeled = rule_based_label(rows)
    else:
        print("[*] sklearn not available — using rule-based labeling")
        labeled = rule_based_label(rows)

    save_labeled(labeled, OUTPUT_CSV)

    # print unique suspicious IPs
    suspicious = sorted({item["row"]["src_ip"] for item in labeled if item["label"] == "suspicious" and item["row"]["src_ip"]})
    if suspicious:
        print("[!] Suspicious source IPs detected:")
        for ip in suspicious:
            print("   -", ip)
    else:
        print("[*] No suspicious IPs detected in this run.")

if __name__ == "__main__":
    main()
