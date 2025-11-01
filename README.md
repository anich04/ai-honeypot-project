# 🛡️ AI Honeypot Project — Intelligent Threat Detection System  

**Developer:** Anirudh   
**Stack:** Python • Supabase • Scapy • Pandas • Tailwind • Realtime Dashboard  

---

## 🚀 Project Overview

This project implements an **AI-powered Honeypot System** that intelligently captures, analyzes, and logs suspicious network activity in **real-time**, integrated with a **Supabase cloud backend** and visualized on a **React (Lovable/Next.js)** dashboard.

It’s designed for **cybersecurity demonstration, resume impact, and recruiter visibility** — showcasing full-stack skills across:
- Network Security
- Threat Analysis
- Cloud Databases
- Data Visualization
- Automation

---

## ⚙️ Architecture Overview

| Phase | Name | Description |
|-------|------|--------------|
| **1** | Packet Capture | Captures raw network traffic using Scapy and logs to CSV |
| **2** | Analysis & Labeling | Applies ML-style logic to label packets as *normal* or *suspicious* |
| **3** | Supabase Upload | Uploads labeled traffic logs to your cloud Supabase tables |
| **4** | Honeypot Engagement | Automatically redirects suspicious IPs to Cowrie honeypot via iptables |
| **5** | Metrics & Monitoring | Tracks attacks, visualizes data, and syncs analytics to Supabase |

---

## 🧩 Technologies Used

| Layer | Tools / Libraries |
|-------|-------------------|
| **Packet Capture** | Scapy, socket, psutil |
| **Data Analysis** | pandas, numpy |
| **Cloud Storage** | Supabase REST API |
| **Visualization** | React (Lovable / Tailwind / Recharts) |
| **Automation** | iptables, cron |
| **AI/Labeling** | Rule-based logic + extendable ML hooks |

---

## 📦 Project Setup

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/<your-username>/ai-honeypot-project.git
cd ai-honeypot-project
```

### 2️⃣ Create Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3️⃣ Install Requirements
```bash
pip install -r requirements.txt
```

---

## 🧰 requirements.txt
```
scapy
pandas
numpy
requests
python-dotenv
```

---

## 🧠 Phase-Wise Execution Guide

### 🔹 Phase 1: Packet Capture
Captures live traffic and stores it in `logs/traffic_log.csv`.

```bash
sudo python3 phase1_capture.py
```

➡️ Output: `logs/traffic_log.csv`

---

### 🔹 Phase 2: Analyze & Label
Labels packets as *normal* or *suspicious*.

```bash
python3 phase2_analyze.py
```

➡️ Output: `logs/traffic_log_labeled.csv`

---

### 🔹 Phase 3: Supabase Upload
Uploads labeled logs to your Supabase backend.

```bash
export SUPABASE_SERVICE_KEY="your_service_role_key"
python3 phase3_supabase_upload.py
```

➡️ Table: `traffic_raw` (in Supabase)  
✅ Automatically handles NaN values and timestamps  

---

### 🔹 Phase 4: Honeypot Engagement
Redirects detected suspicious IPs to honeypot port (Cowrie on port 2222).

```bash
sudo python3 phase4_honeypot_engage.py
```

➡️ Table: `threat_events`  
✅ Auto-creates iptables rules and Supabase logs

---

### 🔹 Phase 5: Metrics & Monitoring
Generates metrics and syncs analytics to Supabase.

```bash
python3 phase5_metrics.py
```

➡️ Table: `metrics`  
✅ Tracks requests, threats, attackers, and labels  
✅ Produces CSV: `logs/metrics_summary.csv`

---

## 🌐 Supabase Configuration

**Project URL:**  
```
https://xyz.supabase.co
```

**Anon Public Key (for frontend):**  
```
your anon public key
```

**Service Role Key (for backend upload):**  
```
your Service Role Key

```

---

## 🖥️ Frontend (Lovable Dashboard)

Lovable Dashboard Project Prompt:  
> **AI Honeypot Dashboard (Realtime Supabase Integration)**  
> Built using Next.js + TailwindCSS + Supabase Realtime  
> Pages: Dashboard • Traffic • Threats • Metrics  
> our project url : https://honeyflow-guard.lovable.app/?utm_source=lovable-editor
**Features:**
- Auto-refresh metrics every 30s  
- Realtime threat updates via Supabase subscriptions  
- Red-highlight suspicious IPs  
- Cybersecurity theme with neon accents  
- Recharts for visualization  

---

## 🧑‍💻 Recruiter Highlights

✅ Full-stack cybersecurity project  
✅ Realtime data + cloud integration  
✅ Automated threat detection & engagement  
✅ Visualization dashboard (Next.js + Supabase Realtime)  
✅ Resume-ready & demo-ready  

---

## 🧩 Example Use Case

1. Honeypot runs on your Kali VM  
2. It captures all inbound connections  
3. Suspicious IPs are automatically flagged and redirected  
4. Data is stored securely in Supabase  
5. Dashboard shows real-time attack stats  

---

## 🧠 Future Enhancements

- ML-based anomaly detection  
- GeoIP mapping of attackers  

---

## 🏁 Author

**Anirudh **  
Cybersecurity Specialist | Pentester | Developer  
🔗 linkdin: https://www.linkedin.com/in/anirudh0402/

---

**⚡ “Secure Systems, Smartly — The AI Honeypot Way.” ⚡**
