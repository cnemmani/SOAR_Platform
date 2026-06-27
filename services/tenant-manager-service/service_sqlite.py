#!/usr/bin/env python3
"""
ZelarSOAR Tenant Manager - SQLite Version
Port: 8029
Replaces the JSON file with proper SQLite database
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import json
import os
import hashlib
from datetime import datetime, timedelta
import secrets

app = Flask(__name__)
CORS(app)

DB_PATH = '/home/ubuntu/soar-dashboard/zelarsoar.db'

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password):
    # For demo, using simple hash. In production, use bcrypt or argon2
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password, hashed):
    return hash_password(password) == hashed

@app.route('/health')
def health():
    try:
        conn = get_db()
        cursor = conn.execute("SELECT COUNT(*) as count FROM tenants")
        tenants_count = cursor.fetchone()['count']
        conn.close()
        return jsonify({
            'status': 'healthy',
            'service': 'tenant-manager-sqlite',
            'database': 'sqlite',
            'tenants': tenants_count
        })
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)}), 500

@app.route('/tenants', methods=['GET'])
def get_tenants():
    try:
        conn = get_db()
        cursor = conn.execute("""
            SELECT t.*, 
                   (SELECT COUNT(*) FROM users u WHERE u.tenant_id = t.id) as user_count,
                   (SELECT COUNT(*) FROM data_sources ds WHERE ds.tenant_id = t.id) as data_source_count
            FROM tenants t
            ORDER BY t.created_at DESC
        """)
        tenants = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return jsonify({'tenants': tenants, 'total': len(tenants)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/tenants/<tenant_id>', methods=['GET'])
def get_tenant(tenant_id):
    try:
        conn = get_db()
        cursor = conn.execute("""
            SELECT t.*, 
                   (SELECT COUNT(*) FROM users u WHERE u.tenant_id = t.id) as user_count,
                   (SELECT json_group_array(json_object('type', ds.type, 'status', ds.status, 'config', ds.config)) 
                    FROM data_sources ds WHERE ds.tenant_id = t.id) as data_sources
            FROM tenants t
            WHERE t.id = ?
        """, (tenant_id,))
        tenant = cursor.fetchone()
        conn.close()
        if tenant:
            return jsonify(dict(tenant))
        return jsonify({'error': 'Tenant not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/tenants', methods=['POST'])
def create_tenant():
    try:
        data = request.get_json()
        tenant_id = data.get('id', '').lower().replace(' ', '_')
        name = data.get('name', tenant_id)
        description = data.get('description', '')
        tier = data.get('tier', 'business')
        settings = json.dumps(data.get('settings', {}))
        
        conn = get_db()
        conn.execute("""
            INSERT INTO tenants (id, name, description, status, tier, settings)
            VALUES (?, ?, ?, 'active', ?, ?)
        """, (tenant_id, name, description, tier, settings))
        conn.commit()
        conn.close()
        
        return jsonify({
            'status': 'created',
            'id': tenant_id,
            'message': f'Tenant {tenant_id} created successfully'
        })
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Tenant ID already exists'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/tenants/<tenant_id>', methods=['PUT'])
def update_tenant(tenant_id):
    try:
        data = request.get_json()
        updates = []
        params = []
        
        for field in ['name', 'description', 'status', 'tier']:
            if field in data:
                updates.append(f"{field} = ?")
                params.append(data[field])
        
        if 'settings' in data:
            updates.append("settings = ?")
            params.append(json.dumps(data['settings']))
        
        if 'data_source_config' in data:
            updates.append("data_source_config = ?")
            params.append(json.dumps(data['data_source_config']))
        
        if not updates:
            return jsonify({'error': 'No fields to update'}), 400
        
        updates.append("updated_at = CURRENT_TIMESTAMP")
        params.append(tenant_id)
        
        conn = get_db()
        conn.execute(f"UPDATE tenants SET {', '.join(updates)} WHERE id = ?", params)
        conn.commit()
        conn.close()
        
        return jsonify({'status': 'updated', 'id': tenant_id})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/tenants/<tenant_id>', methods=['DELETE'])
def delete_tenant(tenant_id):
    if tenant_id == 'global':
        return jsonify({'error': 'Cannot delete global tenant'}), 400
    
    try:
        conn = get_db()
        # Check if tenant has users
        cursor = conn.execute("SELECT COUNT(*) as count FROM users WHERE tenant_id = ?", (tenant_id,))
        if cursor.fetchone()['count'] > 0:
            return jsonify({'error': 'Cannot delete tenant with existing users'}), 400
        
        conn.execute("DELETE FROM tenants WHERE id = ?", (tenant_id,))
        conn.commit()
        conn.close()
        return jsonify({'status': 'deleted', 'id': tenant_id})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/users', methods=['GET'])
def get_users():
    try:
        conn = get_db()
        cursor = conn.execute("""
            SELECT u.*, t.name as tenant_name 
            FROM users u
            LEFT JOIN tenants t ON u.tenant_id = t.id
            ORDER BY u.created_at DESC
        """)
        users = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return jsonify({'users': users, 'total': len(users)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/users', methods=['POST'])
def create_user():
    try:
        data = request.get_json()
        username = data.get('username', '').lower()
        password = data.get('password', 'tenant123')
        display_name = data.get('display_name', username)
        email = data.get('email', '')
        role = data.get('role', 'viewer')
        tenant_id = data.get('tenant', 'global')
        status = data.get('status', 'active')
        
        password_hash = hash_password(password)
        
        conn = get_db()
        conn.execute("""
            INSERT INTO users (username, password_hash, display_name, email, role, tenant_id, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (username, password_hash, display_name, email, role, tenant_id, status))
        conn.commit()
        conn.close()
        
        return jsonify({
            'status': 'created',
            'username': username,
            'message': f'User {username} created successfully'
        })
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username already exists'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/users/<username>', methods=['PUT'])
def update_user(username):
    try:
        data = request.get_json()
        updates = []
        params = []
        
        if 'display_name' in data:
            updates.append("display_name = ?")
            params.append(data['display_name'])
        if 'email' in data:
            updates.append("email = ?")
            params.append(data['email'])
        if 'role' in data:
            updates.append("role = ?")
            params.append(data['role'])
        if 'tenant_id' in data:
            updates.append("tenant_id = ?")
            params.append(data['tenant_id'])
        if 'status' in data:
            updates.append("status = ?")
            params.append(data['status'])
        if 'password' in data:
            updates.append("password_hash = ?")
            params.append(hash_password(data['password']))
        
        if not updates:
            return jsonify({'error': 'No fields to update'}), 400
        
        params.append(username)
        
        conn = get_db()
        conn.execute(f"UPDATE users SET {', '.join(updates)} WHERE username = ?", params)
        conn.commit()
        conn.close()
        
        return jsonify({'status': 'updated', 'username': username})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/users/<username>', methods=['DELETE'])
def delete_user(username):
    if username == 'admin':
        return jsonify({'error': 'Cannot delete admin user'}), 400
    
    try:
        conn = get_db()
        conn.execute("DELETE FROM users WHERE username = ?", (username,))
        conn.commit()
        conn.close()
        return jsonify({'status': 'deleted', 'username': username})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/roles', methods=['GET'])
def get_roles():
    try:
        conn = get_db()
        cursor = conn.execute("SELECT * FROM roles ORDER BY level DESC")
        roles = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return jsonify({'roles': roles})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/data-sources', methods=['GET'])
def get_data_sources():
    try:
        tenant_id = request.args.get('tenant')
        conn = get_db()
        if tenant_id:
            cursor = conn.execute("SELECT * FROM data_sources WHERE tenant_id = ?", (tenant_id,))
        else:
            cursor = conn.execute("SELECT * FROM data_sources")
        sources = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return jsonify({'data_sources': sources})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/data-sources', methods=['POST'])
def create_data_source():
    try:
        data = request.get_json()
        tenant_id = data.get('tenant_id')
        ds_type = data.get('type')
        name = data.get('name', ds_type)
        config = json.dumps(data.get('config', {}))
        status = data.get('status', 'pending')
        
        conn = get_db()
        conn.execute("""
            INSERT INTO data_sources (tenant_id, type, name, status, config)
            VALUES (?, ?, ?, ?, ?)
        """, (tenant_id, ds_type, name, status, config))
        conn.commit()
        conn.close()
        
        return jsonify({'status': 'created', 'message': 'Data source created successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/audit', methods=['GET'])
def get_audit():
    try:
        tenant_id = request.args.get('tenant')
        limit = request.args.get('limit', 100)
        
        conn = get_db()
        if tenant_id:
            cursor = conn.execute("""
                SELECT * FROM audit_log 
                WHERE tenant_id = ? 
                ORDER BY timestamp DESC 
                LIMIT ?
            """, (tenant_id, limit))
        else:
            cursor = conn.execute("""
                SELECT * FROM audit_log 
                ORDER BY timestamp DESC 
                LIMIT ?
            """, (limit,))
        
        logs = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return jsonify({'audit_log': logs, 'total': len(logs)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/resolve-tenant/<agent_name>', methods=['GET'])
def resolve_tenant(agent_name):
    try:
        conn = get_db()
        cursor = conn.execute("""
            SELECT tenant_id FROM agent_mapping 
            WHERE ? LIKE agent_name
            LIMIT 1
        """, (agent_name,))
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return jsonify({'agent': agent_name, 'tenant': result['tenant_id']})
        return jsonify({'agent': agent_name, 'tenant': 'global'})
    except Exception as e:
        return jsonify({'agent': agent_name, 'tenant': 'global'})

@app.route('/audit', methods=['POST'])
def add_audit():
    try:
        data = request.get_json()
        tenant_id = data.get('tenant_id', 'global')
        user_id = data.get('user_id', 'system')
        action = data.get('action')
        details = data.get('details', '')
        ip_address = data.get('ip_address', '')
        user_agent = data.get('user_agent', '')
        
        conn = get_db()
        conn.execute("""
            INSERT INTO audit_log (tenant_id, user_id, action, details, ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (tenant_id, user_id, action, details, ip_address, user_agent))
        conn.commit()
        conn.close()
        
        return jsonify({'status': 'logged'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("🏢 ZelarSOAR Tenant Manager (SQLite) - Port 8029")
    print(f"📁 Database: {DB_PATH}")
    app.run(host='0.0.0.0', port=8029, debug=False)
