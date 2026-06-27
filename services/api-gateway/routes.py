#!/usr/bin/env python3
"""
API Gateway - Integrated Routes for User Management
"""

from flask import Blueprint, request, jsonify, current_app
import requests
from functools import wraps

gateway_bp = Blueprint('gateway', __name__)

# Service endpoints
USER_MGMT_URL = "http://localhost:8010"
AI_UEBA_URL = "http://localhost:8001"
PIPELINE_URL = "http://localhost:8015"

def get_user_token():
    """Get token from request header"""
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        return auth_header.split(' ')[1]
    return None

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_user_token()
        if not token:
            return jsonify({'error': 'Authentication required'}), 401
        
        # Verify token with user management service
        try:
            resp = requests.get(f"{USER_MGMT_URL}/api/auth/verify", 
                               headers={'Authorization': f'Bearer {token}'},
                               timeout=5)
            if resp.status_code != 200:
                return jsonify({'error': 'Invalid or expired token'}), 401
            request.user_info = resp.json()
        except Exception as e:
            return jsonify({'error': f'Auth service error: {str(e)}'}), 503
        
        return f(*args, **kwargs)
    return decorated

@gateway_bp.route('/users', methods=['GET'])
@require_auth
def get_users():
    """Get users (proxy to user management)"""
    resp = requests.get(f"{USER_MGMT_URL}/api/users/", 
                       headers={'Authorization': request.headers.get('Authorization')},
                       params=request.args)
    return jsonify(resp.json()), resp.status_code

@gateway_bp.route('/users', methods=['POST'])
@require_auth
def create_user():
    """Create user"""
    resp = requests.post(f"{USER_MGMT_URL}/api/users/",
                        headers={'Authorization': request.headers.get('Authorization'),
                                'Content-Type': 'application/json'},
                        json=request.json)
    return jsonify(resp.json()), resp.status_code

@gateway_bp.route('/agents', methods=['GET'])
@require_auth
def get_agents():
    """Get agents"""
    resp = requests.get(f"{USER_MGMT_URL}/api/agents/",
                       headers={'Authorization': request.headers.get('Authorization')},
                       params=request.args)
    return jsonify(resp.json()), resp.status_code

@gateway_bp.route('/agents', methods=['POST'])
@require_auth
def create_agent():
    """Create agent"""
    resp = requests.post(f"{USER_MGMT_URL}/api/agents/",
                        headers={'Authorization': request.headers.get('Authorization'),
                                'Content-Type': 'application/json'},
                        json=request.json)
    return jsonify(resp.json()), resp.status_code

@gateway_bp.route('/audit', methods=['GET'])
@require_auth
def get_audit():
    """Get audit logs"""
    resp = requests.get(f"{USER_MGMT_URL}/api/audit/",
                       headers={'Authorization': request.headers.get('Authorization')},
                       params=request.args)
    return jsonify(resp.json()), resp.status_code

@gateway_bp.route('/ai/analyze', methods=['POST'])
@require_auth
def ai_analyze():
    """AI analysis proxy"""
    resp = requests.post(f"{AI_UEBA_URL}/api/ueba/analyze",
                        json=request.json)
    return jsonify(resp.json()), resp.status_code
