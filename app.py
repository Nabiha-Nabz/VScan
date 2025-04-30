from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from database import init_db, get_db, add_user, get_user, update_user, add_scan_report, get_user_reports, get_report_details
from scanner import VulnerabilityScanner
from report_generator import generate_pdf_report
import time
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'
app.config['DATABASE'] = os.path.join(app.instance_path, 'scanner.db')

# Initialize database
init_db(app)

@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('index.html', username=session.get('username'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = get_user(username)
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['email'] = user['email']
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        
        if get_user(username):
            flash('Username already exists', 'danger')
        else:
            add_user(username, email, password)
            flash('Account created successfully! Please login.', 'success')
            return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        current_password = request.form['current_password']
        new_password = request.form.get('new_password')
        
        user = get_user(session['username'])
        if not check_password_hash(user['password'], current_password):
            flash('Current password is incorrect', 'danger')
        else:
            password = user['password']
            if new_password:
                password = generate_password_hash(new_password)
            
            update_user(session['user_id'], username, email, password)
            session['username'] = username
            session['email'] = email
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('profile'))
    
    return render_template('profile.html', 
                         username=session['username'], 
                         email=session['email'])

@app.route('/scan', methods=['POST'])
def scan():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    target_url = request.form['url']
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url
    
    scanner = VulnerabilityScanner(target_url)
    scanner.run_all_scans()
    
    # Save scan report to database
    report_id = add_scan_report(
        session['user_id'],
        target_url,
        '\n'.join(scanner.vulnerabilities),
        len(scanner.vulnerabilities)
    )
    
    return jsonify({
        'vulnerabilities': scanner.vulnerabilities,
        'report_id': report_id
    })

@app.route('/download_report/<int:report_id>')
def download_report(report_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    report = get_report_details(report_id, session['user_id'])
    if not report:
        flash('Report not found', 'danger')
        return redirect(url_for('reports'))
    
    pdf_path = generate_pdf_report(
        report['target_url'],
        report['vulnerabilities'].split('\n'),
        session['username']
    )
    
    return send_file(
        pdf_path,
        as_attachment=True,
        download_name=f"vulnerability_report_{report_id}.pdf"
    )

@app.route('/reports')
def reports():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_reports = get_user_reports(session['user_id'])
    return render_template('reports.html', reports=user_reports)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/scan_results/<int:report_id>')
def scan_results(report_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    report = get_report_details(report_id, session['user_id'])
    if not report:
        flash('Report not found', 'danger')
        return redirect(url_for('reports'))
    
    # Parse vulnerabilities and calculate severity counts
    vulnerabilities = []
    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0
    
    for vuln in report['vulnerabilities'].split('\n'):
        if not vuln.strip():
            continue
            
        # Determine severity
        if "SQL Injection" in vuln or "Command Injection" in vuln or "XXE" in vuln:
            severity = "critical"
            critical_count += 1
        elif "XSS" in vuln or "SSRF" in vuln or "File Inclusion" in vuln:
            severity = "high"
            high_count += 1
        elif "CSRF" in vuln or "Open Redirect" in vuln or "IDOR" in vuln:
            severity = "medium"
            medium_count += 1
        else:
            severity = "low"
            low_count += 1
            
        # Get vulnerability type
        vuln_type = vuln.split(' in ')[0]
        
        # Get location if available
        location = vuln.split(' in ')[1] if ' in ' in vuln else 'General'
        
        vulnerabilities.append({
            'type': vuln_type,
            'severity': severity,
            'location': location,
            'description': f"This vulnerability was detected in the {location}. It could potentially be exploited to compromise the system.",
            'recommendation': VULN_RECOMMENDATIONS.get(vuln_type, "Refer to security best practices for this type of vulnerability."),
            'payload': "Sample payload would be shown here based on the vulnerability type."
        })
    
    # Determine overall severity
    overall_severity = "low"
    if critical_count > 0:
        overall_severity = "critical"
    elif high_count > 0:
        overall_severity = "high"
    elif medium_count > 0:
        overall_severity = "medium"
    
    return render_template('scan_results.html',
        target_url=report['target_url'],
        scan_date=report['created_at'],
        scan_duration=5,  # You would calculate this based on actual scan time
        overall_severity=overall_severity,
        vulnerabilities=vulnerabilities,
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        report_id=report_id,
        share_url=f"{request.host_url}scan_results/{report_id}"
    )
    

if __name__ == '__main__':
    app.run(debug=True)