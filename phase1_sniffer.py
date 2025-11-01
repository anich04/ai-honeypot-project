#!/usr/bin/env python3
"""
phase1_sniffer.py

Phase 1: Lightweight packet sniffer using Scapy.

- Captures IPv4 packets (skips non-IP like ARP unless you enable)
- Writes CSV rows to logs/traffic_log.csv with columns:
    timestamp, src_ip, dst_ip, src_port, dst_port, protocol, packet_len, flags
- Also appends a JSON line for each packet to logs/traffic_log.jsonl
- Safe defaults: runs until CTRL+C; you can set --count to limit packets.

Usage:
    # create & activate venv and install scapy first
    source venv/bin/activate
    pip install scapy

    # run (use sudo)
    sudo python3 phase1_sniffer.py
    # or with args
    sudo python3 phase1_sniffer.py --iface eth0 --count 200

Notes:
- Run with sudo because raw sockets require elevated privileges.
- Output files: logs/traffic_log.csv , logs/traffic_log.jsonl
"""

import os
import csv
import json
import argparse
from datetime import datetime, timezone
from scapy.all import sniff, IP, TCP, UDP, Raw

# ---------- Configuration ----------
LOG_DIR = "logs"
CSV_FILE = os.path.join(LOG_DIR, "traffic_log.csv")
JSONL_FILE = os.path.join(LOG_DIR, "traffic_log.jsonl")
DEFAULT_IFACE = None   # set to "eth0" or "wlan0" if you want
# -----------------------------------

def ensure_logs():
    os.makedirs(LOG_DIR, exist_ok=True)
    # create CSV header if not exists
    if not os.path.exists(CSV_FILE):
        with open(CSV_FILE, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "packet_len", "flags"])

def packet_to_record(pkt):
    """Extracts a dictionary record from a scapy packet (only IP packets)."""
    # timestamp (UTC ISO)
    ts = datetime.now(timezone.utc).isoformat()
    pkt_len = len(pkt)
    flags = ""
    src_ip = None
    dst_ip = None
    src_port = None
    dst_port = None
    proto = "OTHER"

    if IP in pkt:
        ip = pkt[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        proto_num = ip.proto
        # Map protocol
        if proto_num == 6 or pkt.haslayer(TCP):
            proto = "TCP"
            tcp = pkt[TCP]
            src_port = int(tcp.sport)
            dst_port = int(tcp.dport)
            # flags string (S, A, P, R, F etc.)
            flags = str(tcp.flags)
        elif proto_num == 17 or pkt.haslayer(UDP):
            proto = "UDP"
            udp = pkt[UDP]
            src_port = int(udp.sport)
            dst_port = int(udp.dport)
        else:
            proto = str(proto_num)

    return {
        "timestamp": ts,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": proto,
        "packet_len": pkt_len,
        "flags": flags
    }

def write_record_csv(rec):
    with open(CSV_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            rec["timestamp"],
            rec["src_ip"] or "",
            rec["dst_ip"] or "",
            rec["src_port"] if rec["src_port"] is not None else "",
            rec["dst_port"] if rec["dst_port"] is not None else "",
            rec["protocol"],
            rec["packet_len"],
            rec["flags"]
        ])

def write_record_jsonl(rec):
    with open(JSONL_FILE, "a") as f:
        f.write(json.dumps(rec) + "\n")

def process_packet(pkt):
    rec = packet_to_record(pkt)
    # only log packets that have at least one IP address
    if not rec["src_ip"] and not rec["dst_ip"]:
        # skip non-IP or malformed packets
        return
    write_record_csv(rec)
    write_record_jsonl(rec)
    print(f"[+] {rec['timestamp']} {rec['src_ip']} -> {rec['dst_ip']} {rec['protocol']} len={rec['packet_len']} flags={rec['flags']}")

def main():
    parser = argparse.ArgumentParser(description="Phase 1: Scapy packet sniffer (writes CSV + JSONL)")
    parser.add_argument("--iface", "-i", default=DEFAULT_IFACE, help="Interface to sniff (e.g. eth0). Default: all interfaces")
    parser.add_argument("--count", "-c", type=int, default=0, help="Number of packets to capture (0 = unlimited)")
    parser.add_argument("--timeout", "-t", type=int, default=0, help="Timeout in seconds for sniffing (0 = none)")
    args = parser.parse_args()

    ensure_logs()
    print("=== Phase 1 sniffer ===")
    print(f"Logging CSV -> {CSV_FILE}")
    print(f"Logging JSONL -> {JSONL_FILE}")
    print(f"Interface: {args.iface or 'ALL'}  Count: {args.count or 'infinite'}  Timeout: {args.timeout or 'none'}")
    print("Press Ctrl+C to stop.\n")

    sniff_kwargs = dict(prn=process_packet, store=False) # sniff (store=False so not to keep in memory)
    if args.iface:
        sniff_kwargs["iface"] = args.iface
    if args.count and args.count > 0:
        sniff_kwargs["count"] = args.count
    if args.timeout and args.timeout > 0:
        sniff_kwargs["timeout"] = args.timeout

    try:
        sniff(**sniff_kwargs)
    except PermissionError:
        print("[ERROR] Permission denied: run with sudo to capture raw packets.")
    except KeyboardInterrupt:
        print("\n[+] Stopped by user (Ctrl+C).")
    except Exception as e:
        print("[!] Sniffer error:", e)

if __name__ == "__main__":
    main()
