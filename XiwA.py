from pystyle import Colors, Colorate, Center
import os
import time

def Clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def Title(title):
    if os.name == 'nt':
        os.system(f"title {title}")

white, red, reset = Colors.white, Colors.red, Colors.reset
version_tool = "v3.0"
os_name = "Windows" if os.name == 'nt' else "Linux"
username_pc = os.getenv('USERNAME') or os.getenv('USER') or "user"

menu_num = 1

banner = ''' █████ █████  ███                    █████████  
▒▒███ ▒▒███  ▒▒▒                    ███▒▒▒▒▒███ 
 ▒▒███ ███   ████  █████ ███ █████ ▒███    ▒███ 
  ▒▒█████   ▒▒███ ▒▒███ ▒███▒▒███  ▒███████████ 
   ███▒███   ▒███  ▒███ ▒███ ▒███  ▒███▒▒▒▒▒███ 
  ███ ▒▒███  ▒███  ▒▒███████████   ▒███    ▒███ 
 █████ █████ █████  ▒▒████▒████    █████   █████
▒▒▒▒▒ ▒▒▒▒▒ ▒▒▒▒▒    ▒▒▒▒ ▒▒▒▒    ▒▒▒▒▒   ▒▒▒▒▒'''

menu1 = Colorate.Diagonal(Colors.cyan_to_blue, banner, 2) + Colorate.Diagonal(Colors.cyan_to_blue, f'''
                             {version_tool}
─────────────────────────────────────────────────
                 PENETRATION TESTING
─────────────────────────────────────────────────
01. Penetration Test         06. Website PhpInfo Finder
02. Website Whois            07. Website SQLi
03. Website Short URL        08. Phishing Attack (past HTML)
04. IP Localisater (approx)  09. Google Phishing Attack
05. IP Port Scanner

                 OSINT & LOOKUP
─────────────────────────────────────────────────
10. Image To Exif            13. Email Lookup
11. Search Username          14. IP Lookup
12. Phone Lookup

[N] Next Menu  •  [Q] Exit
''', 1)

menu2 = Colorate.Diagonal(Colors.cyan_to_blue, banner, 2) + Colorate.Diagonal(Colors.cyan_to_blue, f'''
                             {version_tool}
─────────────────────────────────────────────────
           OBFUSCATORS/CONVERTERS
─────────────────────────────────────────────────
15. Python Obfuscator        18. JSX To HTML
16. Javascript Obfuscator    19. Python To JS
17. TSX To HTML

                  UTILITIES
─────────────────────────────────────────────────
20. Proxy Scraper            22. RAT Virus
21. Virus Builder

[N] Next Menu  •  [B] Back Menu • [Q] Exit
''', 1)

menu3 = Colorate.Diagonal(Colors.cyan_to_blue, banner, 2) + Colorate.Diagonal(Colors.cyan_to_blue, f'''
                             {version_tool}
─────────────────────────────────────────────────
                DISCORD TOOLS
─────────────────────────────────────────────────
23. TokenGrab Only           28. Token Block All
24. Token Login              29. Token Leave All
25. Token To Info            30. Token Realese Nitro
26. Token Nuker              31. Server Nuker
27. Token Delete All         32. Self Bot

[B] Back Menu  •  [Q] Exit
''', 1)

def Menu():
    global menu_num
    if menu_num == 1:
        return menu1, "1"
    elif menu_num == 2:
        return menu2, "2"
    elif menu_num == 3:
        return menu3, "3"
    else:
        return menu1, "1"

options_all = {
    '01': "PenetrationTest", '02': "WebsiteWhois", '03': "WebsiteShortURL", 
    '04': "IPLocalisater", '05': "IPPortScanner", '06': "WebsitePhpInfoFinder",
    '07': "WebsiteSQLi", '08': "PhishingAttack", '09': "GooglePhishingAttack",
    '10': "ImageToExif", '11': "SearchUsername", '12': "PhoneLookup", 
    '13': "EmailLookup", '14': "IPLookup", '15': "PythonObfuscator",
    '16': "JavascriptObfuscator", '17': "TSXToHTML", '18': "JSXToHTML",
    '19': "PythonToJS", '20': "ProxyScraper", '21': "VirusBuilder", 
    '22': "RATVirus", '23': "TokenGrabOnly", '24': "TokenLogin",
    '25': "TokenToInfo", '26': "TokenNuker", '27': "TokenDeleteAll",
    '28': "TokenBlockAll", '29': "TokenLeaveAll", '30': "TokenRealeseNitro",
    '31': "ServerNuker", '32': "SelfBot"
}

menu_ranges = {
    1: list(range(1, 15)),  
    2: list(range(15, 23)),
    3: list(range(23, 33)) 
}

def StartProgram(name):
    try:
        program_path = f"programs/{name}.py"
        if os.path.exists(program_path):
            os.system(f'python "{program_path}"')
        else:
            print(Colorate.Diagonal(Colors.red_to_white, f"\n[!] Module '{name}' not found in programs/!", 2))
            print(Colorate.Diagonal(Colors.cyan_to_blue, f"[i] Create file: programs/{name}.py", 1))
            time.sleep(3)
    except Exception as e:
        print(Colorate.Diagonal(Colors.red_to_white, f"\n[!] Error: {e}", 2))
        time.sleep(2)

while True:
    try:
        Clear()
        banner_display, menu_number = Menu()
        # Title(f"Tool {version_tool} | Menu {menu_number}")
        
        print(banner_display)
        
        from colorama import Fore, Style
        prompt = (
            f"{Fore.CYAN}┌──({Fore.WHITE}{username_pc}@{os_name}{Fore.CYAN})-[{Fore.WHITE}~/Menu-{menu_number}{Fore.CYAN}]\n"
            f"{Fore.CYAN}└─{Fore.WHITE}$ {Style.RESET_ALL}"
        )
        
        choice = input(prompt).strip()
        
        if choice.upper() in ['N', 'NEXT']:
            menu_num = min(menu_num + 1, 3)
            continue
        elif choice.upper() in ['B', 'BACK']:
            menu_num = max(menu_num - 1, 1)
            continue
        elif choice.upper() in ['Q', 'EXIT', 'QUIT']:
            print(Colorate.Diagonal(Colors.cyan_to_blue, "\n[+] Exiting... Goodbye!", 2))
            break
        elif choice == '':
            continue
        
        if len(choice) == 1 and choice.isdigit():
            choice = f"0{choice}"
        
        choice_num = int(choice) if choice.isdigit() else 0
        current_range = menu_ranges.get(menu_num, [])
        
        if choice in options_all:
            option_num = int(choice)
            if any(option_num in range(r, r+10) for r in current_range):
                StartProgram(options_all[choice])
            else:
                print(Colorate.Diagonal(Colors.red_to_white, f"\n[!] Option '{choice}' is in another menu!", 2))
                print(Colorate.Diagonal(Colors.cyan_to_blue, f"[i] Current menu: {menu_num} | Use N/B to navigate", 1))
                time.sleep(2)
        elif choice.upper() in options_all.values():
            StartProgram(choice.upper())
        else:
            print(Colorate.Diagonal(Colors.red_to_white, "\n[!] Invalid choice!", 2))
            print(Colorate.Diagonal(Colors.cyan_to_blue, "[i] Valid options:", 1))
            
            valid_options = []
            for num in current_range:
                key = f"{num:02d}"
                if key in options_all:
                    valid_options.append(f"{key}. {options_all[key]}")
            
            if valid_options:
                for opt in valid_options:
                    print(Colorate.Diagonal(Colors.cyan_to_blue, f"    {opt}", 1))
            
            time.sleep(3)
            
    except KeyboardInterrupt:
        print(Colorate.Diagonal(Colors.cyan_to_blue, "\n\n[!] Exiting...", 2))
        break
    except Exception as e:
        print(Colorate.Diagonal(Colors.red_to_white, f"\n[!] Error: {e}", 2))
        time.sleep(2)