"""
Simple SSO Authentication Service
"""
from flask import Flask, jsonify, request
from flask_cors import CORS
import hashlib
import uuid
from datetime import datetime, timedelta

app = Flask(__name__)
CORS(app)

# Simple user database
USERS = {
    'admin': {'password': 'admin123', 'role': 'admin', 'display_name': 'Administrator'},
    'analyst': {'password': 'analyst123', 'role': 'analyst', 'display_name': 'Security Analyst'},
    'viewer': {'password': 'viewer123', 'role': 'viewer', 'display_name': 'Viewer'}
}

sessions = {}

@app.route('/health')
def health():
    return jsonify({'status': 'healthy', 'service': 'sso-auth'})

@app.route('/auth/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    # Check credentials
    if username in USERS and USERS[username]['password'] == password:
        session_token = hashlib.sha256(f"{username}{uuid.uuid4()}{datetime.now()}".encode()).hexdigest()
        
        sessions[session_token] = {
            'username': username,
            'role': USERS[username]['role'],
            'display_name': USERS[username]['display_name'],
            'expires': datetime.now() + timedelta(hours=8)
        }
        
        return jsonify({
            'authenticated': True,
            'session_token': session_token,
            'username': username,
            'display_name': USERS[username]['display_name'],
            'role': USERS[username]['role']
        })
    else:
        return jsonify({
            'authenticated': False,
            'error': 'Invalid username or password'
        }), 401

@app.route('/auth/verify', methods=['GET'])
def verify():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if token in sessions:
        session = sessions[token]
        if session['expires'] > datetime.now():
            return jsonify({'valid': True, 'user': session})
    return jsonify({'valid': False}), 401

@app.route('/auth/logout', methods=['POST'])
def logout():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if token in sessions:
        del sessions[token]
    return jsonify({'success': True})

@app.route('/stats')
def stats():
    return jsonify({
        'active_sessions': len(sessions),
        'total_users': len(USERS),
        'service': 'sso-auth'
    })

if __name__ == '__main__':
    print("🔐 SSO Auth Service Started on port 8018")
    app.run(host='0.0.0.0', port=8018, debug=False)
