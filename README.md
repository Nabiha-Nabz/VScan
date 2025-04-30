# VScan
The Vulnerability Scanner WebApp is a full-stack Python-based web application designed to identify and report common web security vulnerabilities in websites. Built using the Flask framework, this tool enables users to sign up, log in, submit a target URL, and receive a detailed scan report of the site's security issues.

The scanner checks for well-known threats such as SQL Injection, Cross-Site Scripting (XSS), Cross-Site Request Forgery (CSRF), Server-Side Request Forgery (SSRF), Insecure Direct Object References (IDOR), and more. The results are compiled into a downloadable PDF report containing vulnerability descriptions, detected risks, and recommended security practices.

The system integrates:

    A user-friendly interface using Flask with HTML/CSS templates

    Real-time scanning through multithreaded background processing

    A PDF report generator for professional output

    SQLite database to manage users and scan history

This project was developed as a final-year academic project to demonstrate applied knowledge in web development, networking, cybersecurity, and secure coding practices.

    ⚠️ Disclaimer: This tool is strictly intended for educational and ethical testing purposes. Unauthorized scanning of websites is illegal.

# 🔐 Vulnerability Scanner Web Application

This is a Python Flask-based web application that allows users to scan websites for common web vulnerabilities such as SQL Injection, XSS, CSRF, IDOR, SSRF, and more. It includes user authentication, real-time scanning, and downloadable PDF reports.

---

## 📌 Features

- User Signup and Login
- Website Vulnerability Scanning
- Common security checks (XSS, SQLi, CSRF, etc.)
- PDF report generation
- SQLite database for user and scan data
- Modern frontend using HTML/CSS/JS with Flask templating

---

## 🖥️ Technologies Used

- Python 3.x
- Flask
- SQLite
- FPDF
- HTML5, CSS3, JavaScript

---

## ⚙️ Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/vulnerability-scanner-webapp.git
cd vulnerability-scanner-webapp

# Create virtual environment (optional but recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the app
python app.py

#Project Structure
vulnerability_scanner_webapp/
├── app.py
├── scanner.py
├── database.py
├── report_generator.py
├── instance/
│   └── scanner.db
├── reports/
│   └── [Generated PDFs]
├── static/
│   ├── css/
│   └── js/
├── templates/
│   └── *.html
├── requirements.txt
└── README.md


