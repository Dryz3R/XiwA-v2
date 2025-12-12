import sys
import os
import json
import webbrowser
import subprocess
import time
from pystyle import Colors, Colorate, Write, System, Anime

class Oxyl:
    def __init__(self):
        self.settings = {}
        self.bde_data = {}
        if not os.path.exists('json'):
            os.makedirs('json')
        self.load_settings()
        self.load_bde()
    
    def load_settings(self):
        try:
            with open('json/settings.json', 'r') as f:
                content = f.read()
                if content.strip():
                    self.settings = json.loads(content)
                else:
                    self.settings = {"web_port": 8080}
        except:
            self.settings = {"web_port": 8080}
            with open('json/settings.json', 'w') as f:
                json.dump({"web_port": 8080}, f, indent=4)
    
    def load_bde(self):
        try:
            with open('json/bde.json', 'r') as f:
                content = f.read()
                if content.strip():
                    self.bde_data = json.loads(content)
                else:
                    self.bde_data = {}
        except:
            self.bde_data = {}
            with open('json/bde.json', 'w') as f:
                json.dump({}, f, indent=4)
    
    def display_menu(self):
        System.Clear()
        title = """
╔══════════════════════════════════════════════════════╗
║   ██████╗ ██╗  ██╗██╗   ██╗██╗      ██████╗ ███████╗║
║  ██╔═══██╗╚██╗██╔╝╚██╗ ██╔╝██║     ██╔═══██╗██╔════╝║
║  ██║   ██║ ╚███╔╝  ╚████╔╝ ██║     ██║   ██║███████╗║
║  ██║▄▄ ██║ ██╔██╗   ╚██╔╝  ██║     ██║   ██║╚════██║║
║  ╚██████╔╝██╔╝ ██╗   ██║   ███████╗╚██████╔╝███████║║
║   ╚══▀▀═╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝ ╚══════╝║
╚══════════════════════════════════════════════════════╝
        """
        print(Colorate.Horizontal(Colors.purple_to_blue, title, 1))
        menu_items = ["1. OSINT Web Interface", "2. SQL Injection Scanner", "3. Exit"]
        for item in menu_items:
            print(Colorate.Horizontal(Colors.cyan_to_blue, f"   {item}", 1))
        print(Colorate.Horizontal(Colors.purple_to_blue, "═" * 55, 1))
    
    def run(self):
        print(Colorate.Horizontal(Colors.purple_to_blue, "Loading Oxyl Framework...", 1))
        time.sleep(1)
        
        while True:
            self.display_menu()
            choice = Write.Input("\n[?] Select an option -> ", Colors.purple_to_blue, interval=0.005)
            
            if choice == "1":
                self.open_osint_web()
            elif choice == "2":
                os.system('python programs/SQLi_penetration.py')
            elif choice == "3":
                Write.Print("\n[!] Exiting Oxyl Framework...\n", Colors.red_to_yellow, interval=0.02)
                sys.exit(0)
            else:
                Write.Print("[!] Invalid option!", Colors.red_to_purple, interval=0.01)
                input("\nPress Enter to continue...")
    
    def open_osint_web(self):
        Write.Print("\n[+] Starting OSINT Web Server...", Colors.cyan_to_green, interval=0.01)
        
        server_process = subprocess.Popen(
            ['python', 'programs/osint_page.py'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        time.sleep(2)
        webbrowser.open('http://localhost:8080')
        Write.Print("[✓] Web interface running on http://localhost:8080", Colors.green_to_cyan, interval=0.01)
        Write.Print("\n[!] Server running in background", Colors.yellow_to_red, interval=0.01)
        input("\nPress Enter to return to menu...")

if __name__ == "__main__":
    tool = Oxyl()
    tool.run()