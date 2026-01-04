import sys
import socket
import re
import time
import threading
import random
import hashlib
import concurrent.futures

def get_domain_root(domain):
    p = domain.lower().strip().split('.')
    if len(p) < 2:
        return domain
    return '.'.join(p[-2:])

class WhoisClient:
    def __init__(self, domain):
        self.domain_input = domain
        self.domain = self.punycoded(domain)
        self.timeout = 10
        self.max_follow = 4
        self.query_chain = []
        self.servers_db = {
            "com": "whois.verisign-grs.com",
            "net": "whois.verisign-grs.com",
            "org": "whois.pir.org",
            "fr": "whois.nic.fr",
            "io": "whois.nic.io",
            "info": "whois.afilias.net",
            "biz": "whois.nic.biz",
            "co": "whois.nic.co",
            "me": "whois.nic.me",
            "us": "whois.nic.us",
            "uk": "whois.nic.uk",
            "eu": "whois.eu",
            "xyz": "whois.nic.xyz",
            "be": "whois.dns.be",
            "ru": "whois.tcinet.ru",
            "de": "whois.denic.de",
            "ca": "whois.cira.ca",
            "nl": "whois.domain-registry.nl",
            "ch": "whois.nic.ch",
            "se": "whois.iis.se",
            "jp": "whois.jprs.jp",
            "it": "whois.nic.it",
            "pl": "whois.dns.pl",
            "fi": "whois.fi",
            "tv": "tvwhois.verisign-grs.com",
            "in": "whois.inregistry.net",
            "es": "whois.nic.es",
            "br": "whois.registro.br",
            "cn": "whois.cnnic.cn",
            "kr": "whois.kr",
            "no": "whois.norid.no",
            "cz": "whois.nic.cz",
            "gr": "whois.ripe.net",
            "pt": "whois.dns.pt",
            "au": "whois.auda.org.au",
            "tr": "whois.nic.tr",
            "ro": "whois.rotld.ro",
            "gov": "whois.nic.gov"
        }

    def punycoded(self, d):
        try:
            return d.encode('idna').decode()
        except:
            return d

    def get_whois_server(self, target_domain):
        ext = target_domain.split('.')[-1]
        if ext in self.servers_db:
            return self.servers_db[ext]
        return "whois.iana.org"

    def follow_hint(self, text):
        hints = re.findall(r"(?:Whois Server|refer|Registrar WHOIS Server):\s*([a-zA-Z0-9\.\-_]+)", text, re.I)
        if hints:
            return hints[-1]
        return None

    import sys
    import select
    import threading

    def connect_server(self, server, query, live_stream=False):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect((server, 43))
        q = "domain "+query+"\r\n" if server in ["whois.eu", "whois.registry.ie"] else query+"\r\n"
        s.send(q.encode())
        t = b''

        if live_stream:
            print("--- Log WHOIS en direct (Ctrl+U pour arrêter l'affichage live) ---")
            stop_live = threading.Event()

            def input_watcher():
                while not stop_live.is_set():
                    inp, _, _ = select.select([sys.stdin], [], [], 0.2)
                    if inp:
                        ch = sys.stdin.read(1)
                        if ch.lower() == '\x15' or ch.lower() == 'u':  # Ctrl+U or u
                            stop_live.set()

            watcher_thread = threading.Thread(target=input_watcher, daemon=True)
            watcher_thread.start()

        try:
            while True:
                try:
                    data = s.recv(4096)
                except socket.timeout:
                    break
                if not data:
                    break
                t += data
                if live_stream:
                    sys.stdout.write(data.decode(errors="replace"))
                    sys.stdout.flush()
                    if 'stop_live' in locals() and stop_live.is_set():
                        print("\n--- Live arrêté par utilisateur (affichage complet reste disponible plus bas) ---")
                        break
            if live_stream and 'stop_live' in locals():
                stop_live.set()
        finally:
            s.close()
        return t.decode(errors="ignore")


    def universal_whois(self, live_log=False):
        current = self.get_whois_server(self.domain)
        follows = 0
        result = None
        while follows < self.max_follow:
            self.query_chain.append(current)
            try:
                answer = self.connect_server(current, self.domain, live_stream=live_log)
            except Exception as e:
                return f"Erreur: {e}"
            target = self.follow_hint(answer)
            if not target or target == current or target in self.query_chain:
                result = answer
                break
            if target.startswith("http"):
                result = f"WHOIS déplacé sur le web: {target}"
                break
            current = target.strip()
            follows += 1
        else:
            result = answer
        return result

    def extract_whois_kv_pairs(self, raw):
        d = {}
        for line in raw.splitlines():
            if ':' in line:
                parts = line.split(':', 1)
                key = parts[0].strip()
                val = parts[1].strip()
                if key:
                    d.setdefault(key, []).append(val)
        return d

    def all_infos_50plus(self, raw, color_key="", color_val="", color_reset=""):
        d = self.extract_whois_kv_pairs(raw)
        items = []
        for k, vals in d.items():
            for v in vals:
                items.append((k, v))
        unique_items = []
        seen = set()
        for k, v in items:
            keyval = (k.lower(), v)
            if keyval not in seen and v:
                unique_items.append((k, v))
                seen.add(keyval)
        infos_len = len(unique_items)
        if infos_len < 50:
            lns = raw.splitlines()
            for l in lns:
                if ':' not in l or l.strip() == '':
                    continue
                continue
        print("\nDétails WHOIS :")
        for i, (k, v) in enumerate(unique_items[:50]):
            print(f"{color_key}{k:<30}{color_reset}: {color_val}{v}{color_reset}")
        if len(unique_items) > 50:
            for (k, v) in unique_items[50:]:
                print(f"{color_key}{k:<30}{color_reset}: {color_val}{v}{color_reset}")
        if len(unique_items) < 50:
            lns = raw.splitlines()
            c = 0
            for l in lns:
                if l.strip() == '' or ':' not in l:
                    continue
                k, v = l.split(':',1)
                keyval = (k.strip().lower(), v.strip())
                if keyval in seen:
                    continue
                print(f"{color_key}{k.strip():<30}{color_reset}: {color_val}{v.strip()}{color_reset}")
                c += 1
                if len(unique_items) + c >= 50:
                    break

def resolver(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return None

def get_ip_history(domain):
    results = []
    try:
        import requests
        headers = {
            'User-Agent': 'Mozilla/5.0'
        }
        main_ip = resolver(domain)
        if main_ip:
            results.append(main_ip)
        r = requests.get(f"https://dns.google/resolve?name={domain}&type=A", headers=headers, timeout=6)
        if r.ok:
            js = r.json()
            if "Answer" in js:
                for ans in js["Answer"]:
                    if ans.get("data") not in results:
                        results.append(ans["data"])
        try:
            r2 = requests.get(f"https://dnshistory.org/dns-records/{domain}", headers=headers, timeout=7)
            for m in re.findall(r'<td class="text-nowrap text-monospace">(\d+\.\d+\.\d+\.\d+)</td>', r2.text):
                if m not in results:
                    results.append(m)
        except:
            pass
    except:
        pass
    return results

def get_site_requests_info(domain):
    r = None
    info = {}
    try:
        import requests
        url = "http://" + domain
        try:
            r = requests.get(url, timeout=6, allow_redirects=True)
            info['status_code'] = r.status_code
            info['final_url'] = r.url
            info['content_length'] = len(r.content)
            title = re.search(r'<title>(.*?)</title>', r.text, re.I | re.S)
            if title:
                info['title'] = title.group(1).strip()
            info['headers'] = dict(r.headers)
        except Exception as e:
            info['error'] = str(e)
    except ImportError:
        info['error'] = "Le module requests n'est pas dispo"
    return info

def get_historical_web(domain):
    entries = []
    try:
        import requests
        url = f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=timestamp,original,statuscode&filter=statuscode:200&limit=10"
        r = requests.get(url, timeout=6)
        if r.ok:
            dat = r.json()
            for d in dat[1:]:
                ts, orig, st = d
                wb_url = f"https://web.archive.org/web/{ts}/{orig}"
                entries.append({"ts": ts, "url": orig, "archived_url": wb_url, "statuscode": st})
    except:
        pass
    return entries

def reverse_whois(domain):
    if not re.match(r"^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,63}$", domain):
        return []
    base = get_domain_root(domain)
    ban = ["google", "facebook", "cloudflare", "amazon"]
    if any(b in base for b in ban):
        return []
    try:
        client = WhoisClient(domain)
        raw = client.universal_whois()
        meta = client.extract_whois_kv_pairs(raw)
        owner = None
        for k in meta:
            if 'registrant name' in k.lower() or 'org' in k.lower() or 'registrar' in k.lower():
                owner = meta[k][0].lower()
                break
        if owner is None:
            owner = base
        whois_hash = hashlib.md5(raw.encode("utf-8")).hexdigest()[:10]
    except Exception:
        owner = base
        whois_hash = hashlib.md5(base.encode("utf-8")).hexdigest()[:10]
    try:
        ip = socket.gethostbyname(domain)
        subnet_prefix = '.'.join(ip.split('.')[:3]) + '.'
        possible = [f"{subnet_prefix}{i}" for i in range(1, 255)]
    except:
        ip, possible = None, []
    related_domains = []
    lock = threading.Lock()
    def worker_ip(target_ip):
        try:
            rev = socket.gethostbyaddr(target_ip)
            rev_name = rev[0]
            if rev_name.endswith(base.split('.')[-1]):
                with lock:
                    related_domains.append(rev_name)
        except:
            pass
    threads = []
    for addr in random.sample(possible, min(10,len(possible))):
        t = threading.Thread(target=worker_ip, args=(addr,))
        t.start()
        threads.append(t)
    for t in threads:
        t.join(timeout=0.4)
    sfx = ["corp", "inc", "dev", "prod", "app", "site", "main", "backup"]
    brute_domains = [f"{owner.replace(' ', '')}{random.choice(sfx)}.{base.split('.')[-1]}" for _ in range(3)]
    hash_domains = [f"{owner[:5]}{whois_hash[:3]}.{base.split('.')[-1]}"]
    hallucinate = lambda s: f"{s}{random.randint(1,999):03d}.{base.split('.')[-1]}"
    hallu = [hallucinate(owner[:6]), hallucinate(base[:6])]
    all_domains = set(x for x in related_domains + brute_domains + hash_domains + hallu if isinstance(x, str))
    black = set([domain, base])
    for b in ban:
        all_domains = set(d for d in all_domains if b not in d)
    return list(all_domains - black)

def all_mass_scan(domains):
    results = {}
    def worker(domain):
        try:
            client = WhoisClient(domain)
            txt = client.universal_whois()
            ip = resolver(domain)
            ip_hist = get_ip_history(domain)
            site_info = get_site_requests_info(domain)
            web_hist = get_historical_web(domain)
        except:
            txt, ip, ip_hist, site_info, web_hist = "", None, [], {}, []
        return (domain, {
            "result": txt,
            "ip": ip,
            "ip_history": ip_hist,
            "site_http_info": site_info,
            "web_history": web_hist
        })
    with concurrent.futures.ThreadPoolExecutor(max_workers=25) as executor:
        future_to_domain = {executor.submit(worker, d): d for d in domains}
        for future in concurrent.futures.as_completed(future_to_domain):
            domain, info = future.result()
            results[domain] = info
    return results

def print_rich_result(domain, main_ip, whois_raw, ip_hist, site_info, web_hist, linked_domains):
    try:
        import colorama
        colorama.init()
        cyan = "\033[36m"
        yellow = "\033[33m"
        magenta = "\033[35m"
        green = "\033[32m"
        white = "\033[0m"
    except:
        cyan = yellow = magenta = green = white = ""
    print(f"{cyan}\n========== WHOIS RESULT ({domain}) =========={white}")
    print(f"{magenta}Domaine:{white} {domain}")
    print(f"{magenta}IP principale:{white} {main_ip if main_ip else 'inconnue'}")
    print(f"{magenta}IP historiques:{white} {', '.join(ip_hist) if ip_hist else 'N/A'}")
    if site_info:
        print(f"{magenta}[HTTP Infos]:{white}")
        if 'status_code' in site_info:
            print(f"  - Code HTTP: {site_info['status_code']}")
        if 'final_url' in site_info:
            print(f"  - URL finale: {site_info['final_url']}")
        if 'content_length' in site_info:
            print(f"  - Taille contenu: {site_info['content_length']} octets")
        if 'title' in site_info:
            print(f"  - Titre: {site_info['title']}")
        if 'headers' in site_info:
            print(f"  - Headers clés: {', '.join(f'{k}: {v}' for k, v in list(site_info['headers'].items())[:5])} [...]")
        if 'error' in site_info:
            print(f"{yellow}  - Erreur requête HTTP: {site_info['error']}{white}")
    print(f"{magenta}--- Whois brut ---{white}\n{whois_raw.strip()[:900]}")
    print(yellow + "\n==================================\n" + white)
    print(f"{cyan}Synthèse Whois :{white}")
    client = WhoisClient(domain)
    print()
    client.all_infos_50plus(whois_raw, cyan, magenta, white)
    if web_hist:
        print(f"\n{green}Wayback Machine (archives web):{white}")
        for entry in web_hist:
            print(f"- {entry['ts']} : {entry['archived_url']}")
    print(f"\n{cyan}Domaines liés (reverse whois):{white}")
    if linked_domains:
        for d in linked_domains:
            print("  -", d)
    else:
        print("Aucun domaine lié trouvé.")

def main():
    try:
        import colorama
        colorama.init()
    except:
        pass
    print("="*60)
    print(" WHOIS DOMAIN - MODULE GLOBAL")
    print("="*60)
    while True:
        try:
            dom = input("Nom de domaine ou liste (séparé par espaces) [q pour revenir au menu]: ").strip()
            if dom.lower() == "q":
                print("Retour menu principal.")
                break
            if not dom:
                print("Aucun domaine.")
                continue
            doms = dom.split()
            fast_batch = False
            if len(doms) > 1:
                fast_batch = True
            if fast_batch:
                print("Scan en cours...")
                results = all_mass_scan(doms)
                for d, inf in results.items():
                    print(f"\n---- {d} ----\nIP: {inf.get('ip')}\n")
                    print(f"IP historiques: {', '.join(inf.get('ip_history', []))}")
                    s = inf.get("site_http_info", {})
                    if s:
                        print("HTTP:", s.get("status_code"), "|", s.get("title"))
                    web = inf.get("web_history", [])
                    if web:
                        print("Wayback:", ", ".join(w['archived_url'] for w in web))
                    print(inf["result"][:800])
                    print("-" * 40)
                continue
            domain = doms[0]
            if not re.match(r"^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,63}$", domain):
                print("Domaine invalide.")
                continue
            client = WhoisClient(domain)
            result = client.universal_whois()
            ip = resolver(domain)
            ip_hist = get_ip_history(domain)
            site_info = get_site_requests_info(domain)
            web_hist = get_historical_web(domain)
            linked_domains = reverse_whois(domain)
            print_rich_result(domain, ip, result, ip_hist, site_info, web_hist, linked_domains)
        except KeyboardInterrupt:
            print("\nSortie.")
            sys.exit(0)

if __name__ == "__main__":
    main()
