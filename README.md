# PhishX - Phishing Email Analyzer (Streamlit)

A beginner-friendly yet practical phishing analyzer you can run locally or showcase on GitHub/LinkedIn.  
Upload a `.eml` file **or** paste raw headers/body and get a clean verdict with reasons, DNS checks, domain intel and a downloadable report.

## ✨ Features
- Parse common headers: `From`, `Reply-To`, `Return-Path`, `Received` chain, `Authentication-Results`.
- SPF/DKIM/DMARC status (from *Authentication-Results*) plus live DNS SPF/DMARC record lookup.
- Link extraction from HTML/text body; flags IP-URL, URL shorteners, punycode/IDN, mismatched display text, suspicious TLDs.
- Basic Whois intel (creation date, registrar). Graceful timeouts.
- Attachment heuristics: flags risky types like `.exe, .js, .scr, .vbs, .docm, .xlsm, .zip`.
- Risk scoring (0–100) with labeled rules and evidence.
- HTML report export; optional PDF export (if wkhtmltopdf available).
- Optional VirusTotal URL lookups via `VT_API_KEY` env var.

## 🏁 Quickstart
```bash
# 1) Create & activate venv
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# 2) Install deps
pip install -r requirements.txt

# 3) Run
streamlit run app.py
```

## 🧪 Try sample emails
Go to the **samples/** folder for a benign and a suspicious example EML.

## 🧠 What You’ll Learn / Showcase
- Email header analysis (SPF/DKIM/DMARC).
- IOC extraction and triage workflow like a SOC analyst.
- DNS + Whois enrichment and risk-based scoring.
- Building a small defensive security tool with Streamlit.

## 🔐 VirusTotal (optional)
Set an environment variable before running:
```bash
export VT_API_KEY="your_key_here"
```

## 📦 Project Structure
```
PhishX_Project/
  app.py                 # Streamlit UI
  src/phishx/analyzer.py # Core logic
  src/phishx/utils.py    # Helpers
  samples/*.eml          # Example emails
  requirements.txt
  README.md
  Screenshots            # Demonstration of how it works!
```


> **PDF Export (optional):** For PDF export, install wkhtmltopdf system-wide:
>
> **Debian/Kali/Ubuntu**
> ```bash
> sudo apt update && sudo apt install -y wkhtmltopdf
> ```
> The app works without this; JSON export is built-in.
