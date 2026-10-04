# VScan Web Vulnerability Scanner

VScan is an educational Flask application for authorized security testing. Users can create accounts, submit a permitted target, review common web-security checks, and download PDF reports.

> **Authorization required:** Scan only systems you own or have explicit written permission to test. Unauthorized security testing may be illegal and disruptive.

## Features

- User registration, authentication, and profiles
- Background website scanning workflow
- Checks for common web security weaknesses
- Scan history and detailed findings
- Downloadable PDF reports
- SQLite-backed local development

## Technology

- Python and Flask
- SQLite
- FPDF
- HTML, CSS, and JavaScript

## Local setup

```bash
git clone https://github.com/Nabiha-Nabz/VScan.git
cd VScan
python -m venv .venv
```

Activate the environment, then run:

```bash
pip install -r requirements.txt
copy .env.example .env
python app.py
```

On macOS or Linux, use `cp .env.example .env`. Open `http://127.0.0.1:5000` after startup.

## Safety and limitations

This is an academic project, not a replacement for a professional security assessment. Results can include false positives or false negatives. Keep scans low impact, obtain authorization, and validate findings manually.
