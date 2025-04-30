import sqlite3
import os
from werkzeug.security import generate_password_hash
from datetime import datetime

def init_db(app):
    if not os.path.exists(app.instance_path):
        os.makedirs(app.instance_path)
    
    conn = sqlite3.connect(app.config['DATABASE'])
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create scan_reports table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            target_url TEXT NOT NULL,
            vulnerabilities TEXT,
            vulnerability_count INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Add admin user if not exists
    admin = cursor.execute('SELECT * FROM users WHERE username = ?', ('admin',)).fetchone()
    if not admin:
        cursor.execute(
            'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
            ('admin', 'admin@example.com', generate_password_hash('admin123'))
        )
    
    conn.commit()
    conn.close()

def get_db():
    conn = sqlite3.connect('instance/scanner.db')
    conn.row_factory = sqlite3.Row
    return conn

def add_user(username, email, password):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
        (username, email, password)
    )
    conn.commit()
    conn.close()

def get_user(username):
    conn = get_db()
    cursor = conn.cursor()
    user = cursor.execute(
        'SELECT * FROM users WHERE username = ?',
        (username,)
    ).fetchone()
    conn.close()
    return user

def update_user(user_id, username, email, password):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        'UPDATE users SET username = ?, email = ?, password = ? WHERE id = ?',
        (username, email, password, user_id)
    )
    conn.commit()
    conn.close()

def add_scan_report(user_id, target_url, vulnerabilities, vulnerability_count):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO scan_reports (user_id, target_url, vulnerabilities, vulnerability_count) VALUES (?, ?, ?, ?)',
        (user_id, target_url, vulnerabilities, vulnerability_count)
    )
    report_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return report_id

def get_user_reports(user_id):
    conn = get_db()
    cursor = conn.cursor()
    reports = cursor.execute(
        'SELECT id, target_url, vulnerability_count, created_at FROM scan_reports WHERE user_id = ? ORDER BY created_at DESC',
        (user_id,)
    ).fetchall()
    conn.close()
    return reports

def get_report_details(report_id, user_id):
    conn = get_db()
    cursor = conn.cursor()
    report = cursor.execute(
        'SELECT * FROM scan_reports WHERE id = ? AND user_id = ?',
        (report_id, user_id)
    ).fetchone()
    conn.close()
    return report