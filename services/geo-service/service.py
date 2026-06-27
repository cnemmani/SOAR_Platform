from flask import Flask, jsonify
from flask_cors import CORS
import requests

app = Flask(__name__)
CORS(app)

@app.route('/health')
def health():
    return jsonify({"status":"healthy","service":"geo"})

@app.route('/ip/<ip>')
@app.route('/api/geo/ip/<ip>')
def geolocate(ip):
    try:
        resp = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            return jsonify(data)
    except:
        pass
    return jsonify({
        "ip": ip, "city": "Unknown", "country": "Unknown",
        "latitude": 0, "longitude": 0, "isp": "Unknown"
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8003, debug=False)
