"""
Client Onboarding & Registration Service
Handles: Signup, Trial activation, Tenant provisioning, Data source setup
Port: 8065
"""
from flask import Flask, jsonify, request
import sqlite3, json, hashlib, uuid
from datetime import datetime, date, timedelta, timedelta

app = Flask(__name__)
DB = '/home/ubuntu/soar-dashboard/zelarsoar.db'

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS client_registrations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company_name TEXT NOT NULL,
            admin_email TEXT UNIQUE NOT NULL,
            admin_name TEXT,
            password_hash TEXT,
            tenant_id TEXT UNIQUE,
            status TEXT DEFAULT 'trial',
            trial_start DATE DEFAULT CURRENT_DATE,
            trial_end DATE,
            plan TEXT DEFAULT 'free_trial',
            data_source_type TEXT,
            data_source_config TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            upgraded_at TIMESTAMP,
            license_key TEXT UNIQUE
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS trial_licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT UNIQUE NOT NULL,
            tenant_id TEXT,
            status TEXT DEFAULT 'active',
            issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at DATE,
            max_users INTEGER DEFAULT 5,
            max_agents INTEGER DEFAULT 10
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# CORS
@app.after_request
def add_cors(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization,X-Tenant-ID'
    response.headers['Access-Control-Allow-Methods'] = 'GET,POST,OPTIONS'
    return response

@app.before_request
def handle_preflight():
    if request.method == 'OPTIONS':
        from flask import make_response
        r = make_response()
        r.headers['Access-Control-Allow-Origin'] = '*'
        return r, 200

@app.route('/health')
def health():
    conn = get_db()
    clients = conn.execute("SELECT COUNT(*) FROM client_registrations").fetchone()[0]
    conn.close()
    return jsonify({'status':'healthy','service':'onboarding','port':8065,'clients':clients})

# ============================================
# STEP 1: REGISTER CLIENT
# ============================================
@app.route('/register', methods=['POST'])
def register_client():
    data = request.json or {}
    company = data.get('company_name','').strip()
    email = data.get('admin_email','').strip().lower()
    name = data.get('admin_name','').strip()
    password = data.get('password','')
    
    if not company or not email or not password:
        return jsonify({'success':False,'error':'Company name, email, and password are required'}), 400
    
    # Check if email already exists
    conn = get_db()
    existing = conn.execute("SELECT id FROM client_registrations WHERE admin_email=?",(email,)).fetchone()
    if existing:
        conn.close()
        return jsonify({'success':False,'error':'Email already registered'}), 400
    
    # Create tenant ID from company name
    tenant_id = company.lower().replace(' ','_').replace('.','_')[:30]
    # Ensure unique
    existing_tenant = conn.execute("SELECT id FROM client_registrations WHERE tenant_id=?",(tenant_id,)).fetchone()
    if existing_tenant:
        tenant_id = tenant_id + '_' + uuid.uuid4().hex[:4]
    
    # Hash password
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    # Generate license key
    license_key = 'ZLR-' + uuid.uuid4().hex[:12].upper()
    
    # Set trial dates
    trial_start = date.today()
    trial_end = trial_start + timedelta(days=14)
    
    conn.execute('''
        INSERT INTO client_registrations (company_name, admin_email, admin_name, password_hash, 
                                          tenant_id, status, trial_start, trial_end, license_key)
        VALUES (?,?,?,?,?,?,?,?,?)
    ''', (company, email, name, password_hash, tenant_id, 'trial', 
          trial_start.isoformat(), trial_end.isoformat(), license_key))
    
    # Create trial license
    conn.execute('''
        INSERT INTO trial_licenses (license_key, tenant_id, status, expires_at, max_users, max_agents)
        VALUES (?,?,?,?,?,?)
    ''', (license_key, tenant_id, 'active', trial_end.isoformat(), 5, 10))
    
    # Create the actual tenant in the system
    try:
        conn.execute('''
            INSERT OR IGNORE INTO tenants (id, name, description, status, tier, settings)
            VALUES (?,?,?,?,?,?)
        ''', (tenant_id, company, f'Trial account - {company}', 'active', 'trial',
              json.dumps({'max_users':5,'max_agents':10,'trial':True,'trial_end':trial_end.isoformat()})))
        
        # Create admin user for this tenant
        conn.execute('''
            INSERT OR IGNORE INTO users (username, password_hash, display_name, role, tenant_id, status)
            VALUES (?,?,?,?,?,?)
        ''', (email.split('@')[0], password_hash, name or email.split('@')[0], 'admin', tenant_id, 'active'))
    except: pass
    
    conn.commit()
    conn.close()
    
    return jsonify({
        'success': True,
        'tenant_id': tenant_id,
        'license_key': license_key,
        'trial_end': trial_end.isoformat(),
        'trial_days_left': 14,
        'message': f'Welcome {company}! Your 14-day free trial is active.'
    })

# ============================================
# STEP 2: SELECT DATA SOURCE
# ============================================
@app.route('/onboard/data-source', methods=['POST'])
def set_data_source():
    data = request.json or {}
    tenant_id = data.get('tenant_id','')
    source_type = data.get('source_type','')
    source_config = data.get('config',{})
    
    if not tenant_id or not source_type:
        return jsonify({'success':False,'error':'Tenant ID and source type required'}), 400
    
    conn = get_db()
    conn.execute('''
        UPDATE client_registrations 
        SET data_source_type=?, data_source_config=?
        WHERE tenant_id=?
    ''', (source_type, json.dumps(source_config), tenant_id))
    
    # Also create data source entry
    try:
        conn.execute('''
            INSERT INTO data_sources (tenant_id, type, name, status, config, alerts_count)
            VALUES (?,?,?,?,?,?)
        ''', (tenant_id, source_type, f'{source_type.upper()} - {tenant_id}', 'pending', json.dumps(source_config), 0))
    except: pass
    
    conn.commit()
    conn.close()
    
    return jsonify({'success':True,'message':f'Data source {source_type} configured for {tenant_id}'})

# ============================================
# CHECK TRIAL STATUS
# ============================================
@app.route('/trial-status/<tenant_id>')
def trial_status(tenant_id):
    conn = get_db()
    client = conn.execute("SELECT * FROM client_registrations WHERE tenant_id=?",(tenant_id,)).fetchone()
    conn.close()
    
    if not client:
        return jsonify({'error':'Tenant not found'}), 404
    
    trial_end = datetime.strptime(client['trial_end'], '%Y-%m-%d').date() if client['trial_end'] else None
    days_left = (trial_end - date.today()).days if trial_end else 0
    
    return jsonify({
        'tenant_id': tenant_id,
        'company': client['company_name'],
        'status': client['status'],
        'plan': client['plan'],
        'trial_start': client['trial_start'],
        'trial_end': client['trial_end'],
        'days_left': max(0, days_left),
        'trial_active': days_left > 0,
        'data_source': client['data_source_type'],
        'upgrade_url': '/upgrade'
    })

# ============================================
# UPGRADE FROM TRIAL
# ============================================
@app.route('/upgrade', methods=['POST'])
def upgrade_plan():
    data = request.json or {}
    tenant_id = data.get('tenant_id','')
    plan = data.get('plan','business')
    
    if not tenant_id:
        return jsonify({'success':False,'error':'Tenant ID required'}), 400
    
    conn = get_db()
    conn.execute('''
        UPDATE client_registrations SET status='active', plan=?, upgraded_at=CURRENT_TIMESTAMP
        WHERE tenant_id=?
    ''', (plan, tenant_id))
    
    conn.execute('''
        UPDATE tenants SET tier=?, settings=json_set(settings,'$.trial', 'false')
        WHERE id=?
    ''', (plan, tenant_id))
    
    conn.commit()
    conn.close()
    
    plans = {
        'startup': {'price':'$99/mo','users':10,'agents':25},
        'business': {'price':'$299/mo','users':25,'agents':100},
        'enterprise': {'price':'$999/mo','users':100,'agents':500},
    }
    
    return jsonify({
        'success':True,
        'plan': plan,
        'details': plans.get(plan,{}),
        'message': f'Upgraded to {plan.upper()} plan successfully!'
    })

# ============================================
# LOGIN (with trial check)
# ============================================
@app.route('/login', methods=['POST'])
def login():
    data = request.json or {}
    email = data.get('email','').strip().lower()
    password = data.get('password','')
    
    if not email or not password:
        return jsonify({'success':False,'error':'Email and password required'}), 400
    
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    conn = get_db()
    # Check client registrations first
    client = conn.execute(
        "SELECT * FROM client_registrations WHERE admin_email=? AND password_hash=?",
        (email, password_hash)
    ).fetchone()
    
    if client:
        # Check trial status
        trial_end = datetime.strptime(client['trial_end'], '%Y-%m-%d').date() if client['trial_end'] else None
        days_left = (trial_end - date.today()).days if trial_end else 0
        
        conn.close()
        return jsonify({
            'success': True,
            'user_type': 'client_admin',
            'tenant_id': client['tenant_id'],
            'company': client['company_name'],
            'username': client['admin_name'] or email.split('@')[0],
            'role': 'admin',
            'plan': client['plan'],
            'trial_active': days_left > 0,
            'days_left': max(0, days_left),
            'data_source': client['data_source_type'],
            'token': 'demo_token_' + email.split('@')[0].replace('.','_')
        })
    
    # Also check regular users table
    user = conn.execute(
        "SELECT u.*, t.name as tenant_name FROM users u LEFT JOIN tenants t ON u.tenant_id=t.id WHERE u.username=? AND u.password_hash=?",
        (email.split('@')[0], password_hash)
    ).fetchone()
    conn.close()
    
    if user:
        return jsonify({
            'success': True,
            'user_type': 'platform_user',
            'tenant_id': user['tenant_id'],
            'username': user['username'],
            'role': user['role'],
            'token': 'demo_token_' + user['username']
        })
    
    return jsonify({'success':False,'error':'Invalid email or password'}), 401

if __name__ == '__main__':
    print("🚀 Onboarding Service - Port 8065")
    print("   POST /register - Register new client")
    print("   POST /onboard/data-source - Set data source")
    print("   GET /trial-status/:tenant - Check trial")
    print("   POST /upgrade - Upgrade plan")
    print("   POST /login - Authenticate")
    app.run(host='0.0.0.0', port=8065, debug=False)
