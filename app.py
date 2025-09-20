
# app.py - A Flask web app

import os
import subprocess
import pickle
import base64
import sqlite3
from flask import Flask, request, render_template_string
import random
import hashlib
import requests  # Unused import to trigger code smell
from cryptography.hazmat.primitives import serialization  # Insecure usage below
from PIL import Image  # For insecure file handling

app = Flask(__name__)

# Hardcoded secrets - Vulnerability: Hardcoded credentials
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "password123"  # Plaintext password

# Insecure random usage - Weak randomness
def generate_token():
    return str(random.randint(1, 100))  # Predictable

# Unused variable - Code smell
unused_var = "This is never used"

# Complex function with high cyclomatic complexity
def complex_function(a, b, c, d, e):
    if a > 0:
        if b < 0:
            if c == 0:
                if d != 0:
                    if e > 0:
                        return a + b + c + d + e
                    else:
                        return a - b - c - d - e
                else:
                    return a * b * c
            elif c > 0:
                return a / b  # Potential division by zero
            else:
                return a % b
        elif b == 0:
            return "Zero"
        else:
            return "Positive"
    else:
        return "Negative"

# Duplicated code block - Code smell
def duplicated_code1(x):
    y = x + 1
    z = y * 2
    return z

def duplicated_code2(x):
    y = x + 1
    z = y * 2
    return z

@app.route('/')
def home():
    return "Welcome to Vulnerable App!"

# SQL Injection vulnerability
@app.route('/user')
def get_user():
    user_id = request.args.get('id')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = " + user_id  # Direct concatenation - SQL injection
    cursor.execute(query)
    result = cursor.fetchall()
    return str(result)

# Command Injection vulnerability
@app.route('/ping')
def ping():
    ip = request.args.get('ip')
    cmd = "ping -c 1 " + ip  # Direct user input in command
    output = os.system(cmd)  # Insecure os.system
    # Alternative: subprocess.call(cmd, shell=True)  # Also vulnerable
    return f"Ping output: {output}"

# Insecure deserialization
@app.route('/deserialize')
def deserialize():
    data = request.args.get('data')
    decoded = base64.b64decode(data)
    obj = pickle.loads(decoded)  # Insecure pickle from untrusted input
    return str(obj)

# Hardcoded crypto key - Vulnerability
def encrypt_data(data):
    key = b'secretkey1234567'  # Hardcoded key
    # Insecure usage of cryptography (old version may have issues)
    return hashlib.md5(data.encode() + key).hexdigest()  # Weak hash

# Insecure file upload and handling
@app.route('/upload', methods=['POST'])
def upload():
    file = request.files['file']
    filename = file.filename  # No validation
    file.save(filename)  # Save directly - Path traversal possible
    # Open with Pillow - Potential for malicious images
    img = Image.open(filename)
    img.show()  # Not practical in web, but triggers issues
    return "Uploaded!"

# XSS vulnerability
@app.route('/search')
def search():
    query = request.args.get('q')
    return render_template_string(f"<h1>Search results for {query}</h1>")  # No escaping - XSS

# Potential buffer overflow or large input issue - No input validation
@app.route('/large_input')
def large_input():
    data = request.args.get('data')
    buffer = [0] * 1000000  # Large allocation
    for i in range(len(data)):
        buffer[i] = data[i]  # Potential out-of-bounds if data too long
    return "Processed"

# Insecure external request - SSRF potential
@app.route('/fetch')
def fetch_url():
    url = request.args.get('url')
    response = requests.get(url)  # No validation - SSRF
    return response.text

# Bug: Division by zero
@app.route('/divide')
def divide():
    num = int(request.args.get('num'))
    return str(num / 0)  # Intentional bug

# More code smells: Empty block
if __name__ == '__main__':
    pass  # Empty

    app.run(debug=True)  # Debug mode enabled - Security issue in production

# Additional bug: Infinite loop potential
def infinite_loop():
    while True:
        print("Looping")  # Not called, but code smell if analyzed

