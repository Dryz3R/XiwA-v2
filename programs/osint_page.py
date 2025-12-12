from flask import Flask, jsonify, request, send_from_directory
import requests
import os

app = Flask(__name__, static_folder='../settings/web_osint_interfcace/static')

class OSINTBackend:
    def __init__(self):
        self.headers = {'User-Agent': 'Oxyl-OSINT/1.0'}
    
    def username_search(self, username):
        platforms = {
            'GitHub': f'https://github.com/{username}',
            'Twitter': f'https://twitter.com/{username}',
            'Instagram': f'https://instagram.com/{username}',
            'Reddit': f'https://reddit.com/user/{username}'
        }
        
        results = []
        for platform, url in platforms.items():
            try:
                response = requests.get(url, headers=self.headers, timeout=3)
                status = 'Found' if response.status_code == 200 else 'Not Found'
                results.append({'platform': platform, 'status': status, 'url': url})
            except:
                results.append({'platform': platform, 'status': 'Error', 'url': None})
        
        return {'username': username, 'results': results}
    
    def ip_lookup(self, ip):
        try:
            response = requests.get(f'http://ip-api.com/json/{ip}')
            data = response.json()
            if data.get('status') == 'success':
                return {
                    'ip': ip, 'country': data.get('country'),
                    'city': data.get('city'), 'isp': data.get('isp'),
                    'lat': data.get('lat'), 'lon': data.get('lon')
                }
            return {'error': 'IP lookup failed'}
        except:
            return {'error': 'Connection failed'}
    
    def email_analysis(self, email):
        domain = email.split('@')[-1] if '@' in email else ''
        username = email.split('@')[0] if '@' in email else ''
        valid = '@' in email and '.' in domain
        return {
            'email': email, 'domain': domain,
            'username': username, 'valid': valid
        }

backend = OSINTBackend()

@app.route('/')
def index():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/css/<path:filename>')
def css_files(filename):
    return send_from_directory(os.path.join(app.static_folder, 'css'), filename)

@app.route('/api/username', methods=['GET'])
def username_endpoint():
    username = request.args.get('query')
    if not username:
        return jsonify({'error': 'Username required'}), 400
    return jsonify(backend.username_search(username))

@app.route('/api/ip', methods=['GET'])
def ip_endpoint():
    ip = request.args.get('query')
    if not ip:
        return jsonify({'error': 'IP address required'}), 400
    return jsonify(backend.ip_lookup(ip))

@app.route('/api/email', methods=['GET'])
def email_endpoint():
    email = request.args.get('query')
    if not email:
        return jsonify({'error': 'Email required'}), 400
    return jsonify(backend.email_analysis(email))

@app.route('/test')
def test():
    return jsonify({'status': 'OK', 'message': 'Server is running'})

def run_server():
    print("Oxyl OSINT Server starting on http://localhost:8080")
    app.run(host='0.0.0.0', port=8080, debug=False)

if __name__ == '__main__':
    run_server()