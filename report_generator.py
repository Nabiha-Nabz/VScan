from fpdf import FPDF
from datetime import datetime
import os

class PDF(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 15)
        self.cell(0, 10, 'Vulnerability Scan Report', 0, 1, 'C')
        self.ln(10)
    
    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

def generate_pdf_report(target_url, vulnerabilities, username):
    pdf = PDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    
    # Report details
    pdf.cell(0, 10, f"Generated for: {username}", 0, 1)
    pdf.cell(0, 10, f"Target URL: {target_url}", 0, 1)
    pdf.cell(0, 10, f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 0, 1)
    pdf.ln(10)
    
    # Vulnerabilities
    pdf.set_font("Arial", 'B', 14)
    pdf.cell(0, 10, "Vulnerabilities Found:", 0, 1)
    pdf.set_font("Arial", size=12)
    
    for i, vuln in enumerate(vulnerabilities, 1):
        # Determine color based on severity
        if "SQL Injection" in vuln or "Command Injection" in vuln or "XXE" in vuln:
            pdf.set_text_color(220, 50, 50)  # Red for critical
        elif "XSS" in vuln or "SSRF" in vuln or "File Inclusion" in vuln:
            pdf.set_text_color(255, 140, 0)  # Orange for high
        elif "CSRF" in vuln or "Open Redirect" in vuln or "IDOR" in vuln:
            pdf.set_text_color(255, 215, 0)  # Gold for medium
        else:
            pdf.set_text_color(0, 0, 0)  # Black for low
        
        pdf.multi_cell(0, 10, f"{i}. {vuln}")
        pdf.ln(5)
        pdf.set_text_color(0, 0, 0)  # Reset to black
    
    # Summary
    pdf.ln(10)
    pdf.set_font("Arial", 'B', 14)
    pdf.cell(0, 10, f"Total Vulnerabilities Found: {len(vulnerabilities)}", 0, 1)
    
    # Save the PDF
    if not os.path.exists('reports'):
        os.makedirs('reports')
    
    report_path = f"reports/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    pdf.output(report_path)
    
    return report_path