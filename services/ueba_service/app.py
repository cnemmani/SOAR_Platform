#!/usr/bin/env python3
"""
UEBA Microservice - IP Geolocation Service
"""

import requests
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# API key for authentication
API_KEY = "UEBA_SECRET_KEY_2024"

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'service': 'ueba-geolocation', 'port': 8004})

@app.route('/', methods=['GET'])
def index():
    """Root endpoint"""
    return jsonify({
        'service': 'UEBA IP Geolocation Service',
        'version': '1.0',
        'endpoints': {
            '/health': 'GET - Health check',
            '/ip/<ip>': 'GET - Get geolocation for IP',
            '/ip/batch': 'POST - Batch IP geolocation'
        }
    })

@app.route('/ip/<ip>', methods=['GET'])
def get_ip_location(ip):
    """Get geolocation for IP address"""
    api_key = request.args.get('api_key')
    
    if api_key != API_KEY:
        return jsonify({'error': 'Invalid API key'}), 401
    
    try:
        # Use ip-api.com for geolocation (free, no API key needed)
        response = requests.get(f'http://ip-api.com/json/{ip}', timeout=10)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                return jsonify({
                    'ip': ip,
                    'country': data.get('country', 'Unknown'),
                    'country_code': data.get('countryCode', ''),
                    'city': data.get('city', 'Unknown'),
                    'region': data.get('regionName', 'Unknown'),
                    'latitude': data.get('lat', 0),
                    'longitude': data.get('lon', 0),
                    'isp': data.get('isp', 'Unknown'),
                    'org': data.get('org', 'Unknown'),
                    'as': data.get('as', 'Unknown'),
                    'timezone': data.get('timezone', ''),
                    'google_maps_url': f"https://www.google.com/maps?q={data.get('lat', 0)},{data.get('lon', 0)}"
                })
            else:
                return jsonify({'error': 'IP not found'}), 404
        else:
            return jsonify({'error': 'Geolocation service error'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/ip/batch', methods=['POST'])
def batch_ip_location():
    """Batch IP geolocation"""
    api_key = request.args.get('api_key')
    if api_key != API_KEY:
        return jsonify({'error': 'Invalid API key'}), 401
    
    data = request.get_json()
    ips = data.get('ips', [])
    
    results = {}
    for ip in ips[:20]:
        try:
            response = requests.get(f'http://ip-api.com/json/{ip}', timeout=10)
            if response.status_code == 200:
                resp_data = response.json()
                if resp_data.get('status') == 'success':
                    results[ip] = {
                        'country': resp_data.get('country', 'Unknown'),
                        'city': resp_data.get('city', 'Unknown'),
                        'latitude': resp_data.get('lat', 0),
                        'longitude': resp_data.get('lon', 0),
                        'isp': resp_data.get('isp', 'Unknown')
                    }
                else:
                    results[ip] = {'error': 'IP not found'}
        except:
            results[ip] = {'error': 'Timeout'}
    
    return jsonify(results)

if __name__ == '__main__':
    print("=" * 60)
    print("🚀 UEBA IP Geolocation Service (Port 8004)")
    print("=" * 60)
    print(f"Health check: http://localhost:8004/health")
    print(f"IP lookup: http://localhost:8004/ip/8.8.8.8?api_key={API_KEY}")
    print("=" * 60)
    app.run(host='0.0.0.0', port=8004, debug=False)
