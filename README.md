# 🛡️ PhishGuard — Phishing URL Detection Tool

A sleek, AI-powered web app to detect phishing and malicious URLs using heuristic analysis, domain intelligence, and the VirusTotal API.

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-3.0-black?style=flat-square&logo=flask)
![VirusTotal](https://img.shields.io/badge/VirusTotal-API%20v3-blue?style=flat-square)

---

## ✨ Features

- 🔍 **Heuristic URL Analysis** — IP-as-host, excessive subdomains, `@` symbol, double-slash redirects, suspicious characters
- 🏷️ **Brand Impersonation Detection** — Detects 30+ commonly spoofed brands (PayPal, Apple, Google, etc.)
- ✂️ **URL Shortener Detection** — Identifies 30+ known shortening services
- 📅 **Domain Age Lookup** — WHOIS-based check; flags newly registered domains
- 🌐 **Suspicious TLD Detection** — Flags high-risk TLDs like `.tk`, `.xyz`, `.zip`, `.top`
- 🧬 **VirusTotal Integration** — Real-time scan with 70+ security engines via the v3 API
- 🎯 **Reputation Score** — Blended 0–100 risk score (60% heuristic + 40% VirusTotal)
- 💅 **Premium Dark UI** — Glassmorphic design with animated score ring

---

## 🚀 Getting Started

### 1. Clone the repo
```bash
git clone https://github.com/YOUR_USERNAME/phishguard.git
cd phishguard
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure your API key
Copy `.env.example` to `.env` and add your [VirusTotal API key](https://www.virustotal.com):
```bash
cp .env.example .env
```
Edit `.env`:
```
VIRUSTOTAL_API_KEY=your_api_key_here
```

### 4. Run the app
```bash
python app.py
```
Open **http://127.0.0.1:5000** in your browser.

---

## 📁 Project Structure

```
phishguard/
├── app.py                  # Flask application
├── requirements.txt        # Python dependencies
├── .env.example            # API key template
├── utils/
│   ├── url_analyzer.py     # Heuristic analysis & scoring
│   └── api_clients.py      # VirusTotal API client
├── templates/
│   └── index.html          # Web UI
└── static/
    ├── css/style.css        # Dark glassmorphic theme
    └── js/main.js           # Frontend logic
```

---

## ⚠️ Disclaimer

This tool is for **educational and research purposes only**. Do not use it as your sole security measure. Always follow safe browsing practices.

---

## 📄 License

MIT License
