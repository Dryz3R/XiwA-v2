import socket
import re
import time
import random
import threading

class IPLocalisater:
    def __init__(self):
        self.ip_pattern = re.compile(
            r"^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$"
        )
        self.ipv6_pattern = re.compile(
            r"^([\da-fA-F]{1,4}:){7}[\da-fA-F]{1,4}$|^::1$"  # simplify IPv6 matching
        )
        self.services = [
            ("ipapi.co", self.api_ipapi),
            ("ipinfo.io", self.api_ipinfo),
            ("ipgeolocation.io", self.api_ipgeolocation),
            ("db-ip.com", self.api_dbip),
            ("ip-api.com", self.api_ipapicom),
            ("ipdata.co", self.api_ipdata),
            ("ipwhois.app", self.api_ipwhois),
            ("ipregistry.co", self.api_ipregistry),
            ("ipstack.com", self.api_ipstack),
        ]
        self.lock = threading.Lock()

    def is_valid_ipv4(self, ip):
        return bool(self.ip_pattern.fullmatch(ip.strip()))

    def is_valid_ipv6(self, ip):
        return bool(self.ipv6_pattern.fullmatch(ip.strip()))

    def resolve_hostname(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return None

    def resolve_ip_from_hostname(self, hostname):
        try:
            return socket.gethostbyname(hostname)
        except Exception:
            return None

    def reverse_dns_lookup(self, ip):
        try:
            name, _, _ = socket.gethostbyaddr(ip)
            return name
        except Exception:
            return None

    def whois_lookup(self, ip):
        try:
            import ipwhois
            obj = ipwhois.IPWhois(ip)
            res = obj.lookup_rdap(depth=2)
            return res
        except Exception:
            return {}

    def is_private_ip(self, ip):
        p = list(map(int, ip.split('.')))
        if p[0] == 10:
            return True
        if p[0] == 172 and 16 <= p[1] <= 31:
            return True
        if p[0] == 192 and p[1] == 168:
            return True
        return False

    def _get_from_service(self, api_name, func, ip, result_dict):
        try:
            data = func(ip)
            with self.lock:
                result_dict[api_name] = data
        except Exception as e:
            with self.lock:
                result_dict[api_name] = {"error": str(e)}

    def gather_all_services(self, ip):
        results = {}
        threads = []
        for name, svc in self.services:
            t = threading.Thread(target=self._get_from_service, args=(name, svc, ip, results))
            t.start()
            threads.append(t)
        for t in threads:
            t.join(timeout=7)
        return results

    def api_ipapi(self, ip):
        import requests
        r = requests.get(f"https://ipapi.co/{ip}/json", timeout=5)
        return r.json() if r.ok else {}

    def api_ipinfo(self, ip):
        import requests
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        return r.json() if r.ok else {}

    def api_ipgeolocation(self, ip):
        import requests
        key = "demo"
        r = requests.get(f"https://api.ipgeolocation.io/ipgeo?apiKey={key}&ip={ip}", timeout=5)
        return r.json() if r.ok else {}

    def api_dbip(self, ip):
        import requests
        r = requests.get(f"https://api.db-ip.com/v2/free/{ip}", timeout=5)
        return r.json() if r.ok else {}

    def api_ipapicom(self, ip):
        import requests
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        return r.json() if r.ok else {}

    def api_ipdata(self, ip):
        import requests
        key = "test"
        r = requests.get(f"https://api.ipdata.co/{ip}?api-key={key}", timeout=5)
        return r.json() if r.ok else {}

    def api_ipwhois(self, ip):
        import requests
        r = requests.get(f"https://ipwhois.app/json/{ip}", timeout=5)
        return r.json() if r.ok else {}

    def api_ipregistry(self, ip):
        import requests
        key = "tryout"
        r = requests.get(f"https://api.ipregistry.co/{ip}?key={key}", timeout=5)
        return r.json() if r.ok else {}

    def api_ipstack(self, ip):
        import requests
        key = "demo"
        r = requests.get(f"http://api.ipstack.com/{ip}?access_key={key}", timeout=5)
        return r.json() if r.ok else {}

    def as_lookup(self, ip):
        try:
            import requests
            r = requests.get(f"https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}", timeout=6)
            return r.json() if r.ok else {}
        except Exception:
            return {}

    def port_scan(self, ip, ports=None, timeout=1):
        if ports is None:
            ports = [80, 443, 22, 21, 25, 110, 445, 3389, 8080, 8443]
        open_ports = []
        def scan_port(port):
            try:
                s = socket.socket()
                s.settimeout(timeout)
                s.connect((ip, port))
                s.close()
                open_ports.append(port)
            except Exception:
                pass
        threads = []
        for port in ports:
            t = threading.Thread(target=scan_port, args=(port,))
            t.start()
            threads.append(t)
        for t in threads:
            t.join(timeout=timeout+0.5)
        return open_ports

    def traceroute(self, ip, max_hops=18):
        import platform
        hops = []
        if platform.system() == "Windows":
            import subprocess
            cmd = ["tracert", "-d", "-h", str(max_hops), ip]
            try:
                p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                for line in p.stdout:
                    line = line.strip()
                    if re.match(r"^\d+\s", line):
                        hops.append(line)
            except Exception:
                return hops
        else:
            import subprocess
            cmd = ["traceroute", "-n", "-m", str(max_hops), ip]
            try:
                p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                for line in p.stdout:
                    if line[0].isdigit():
                        hops.append(line.strip())
            except Exception:
                return hops
        return hops

    def get_reverse_whois_domains(self, ip):
        try:
            import requests
            url = f"https://reverse-whois.whoisxmlapi.com/api/v2?ip={ip}&apiKey=demokey"
            r = requests.get(url, timeout=8)
            if r.ok:
                return r.json()
        except Exception:
            pass
        return {}

    def google_ip_intel(self, ip):
        try:
            import requests
            r = requests.get(f"https://transparencyreport.google.com/transparency_report/api/v3/ip/{ip}", timeout=6)
            return r.json() if r.ok else {}
        except Exception:
            return {}

    def maxmind_db_lookup(self, ip):
        try:
            import geoip2.database
            reader = geoip2.database.Reader('GeoLite2-City.mmdb')
            response = reader.city(ip)
            return {
                'city': response.city.name,
                'country': response.country.name,
                'latitude': response.location.latitude,
                'longitude': response.location.longitude,
                'timezone': response.location.time_zone
            }
        except Exception:
            return {}

    def bgpview_as_lookup(self, ip):
        try:
            import requests
            r = requests.get(f"https://api.bgpview.io/ip/{ip}", timeout=5)
            if r.ok:
                return r.json()
        except Exception:
            pass
        return {}

    def multi_ping(self, ip, n=5):
        import platform, subprocess
        timeout = 2
        times = []
        cmd = []
        if platform.system() == "Windows":
            cmd = ["ping", "-n", str(n), "-w", str(timeout*1000), ip]
        else:
            cmd = ["ping", "-c", str(n), "-W", str(timeout), ip]
        try:
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            for line in p.stdout:
                if 'time=' in line:
                    m = re.search(r"time[=<]\s*([\d\.]+)", line)
                    if m:
                        times.append(float(m.group(1)))
        except Exception:
            pass
        return times

    def dnsbl_lookup(self, ip):
        dnsbls = [
            "zen.spamhaus.org",
            "bl.spamcop.net",
            "dnsbl.sorbs.net",
            "b.barracudacentral.org",
            "psbl.surriel.com"
        ]
        res = {}
        reversed_ip = ".".join(ip.split(".")[::-1])
        for bl in dnsbls:
            try:
                socket.gethostbyname(f"{reversed_ip}.{bl}")
                res[bl] = True
            except Exception:
                res[bl] = False
        return res

    def shodan_search(self, ip, key=None):
        try:
            import requests
            apikey = key or "demo"
            r = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={apikey}", timeout=8)
            if r.ok:
                return r.json()
        except Exception:
            pass
        return {}

    def virustotal_search(self, ip, key=None):
        try:
            import requests
            apikey = key or "demokey"
            headers = {"x-apikey": apikey}
            r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers=headers, timeout=8)
            if r.ok:
                return r.json()
        except Exception:
            pass
        return {}

    def hybrid_analysis(self, ip):
        try:
            import requests
            headers = {"api-key": "state"}
            r = requests.get(f"https://www.hybrid-analysis.com/api/v2/quick-scan/url", params={"url":ip}, headers=headers, timeout=6)
            if r.ok:
                return r.json()
        except Exception:
            pass
        return {}

    def tor_check(self, ip):
        try:
            import requests
            r = requests.get(f"https://check.torproject.org/torbulkexitlist", timeout=7)
            if r.ok:
                return ip in r.text
        except Exception:
            pass
        return False

    def threat_intel_aggregated(self, ip):
        sources = [
            lambda i: self.shodan_search(i),
            lambda i: self.virustotal_search(i),
            lambda i: self.hybrid_analysis(i),
            lambda i: self.bgpfraud_check(i),
        ]
        out = {}
        for src in sources:
            try:
                d = src(ip)
                out.update({src.__name__: d})
            except Exception:
                pass
        return out

    def bgpfraud_check(self, ip):
        try:
            import requests
            r = requests.get(f"https://bgpfraud.net/api/search?ip={ip}", timeout=7)
            if r.ok:
                return r.json()
        except Exception:
            pass
        return {}

    def onion_scan(self, ip):
        try:
            import requests
            r = requests.get(f"https://onionoo.torproject.org/details?search={ip}", timeout=9)
            if r.ok:
                return r.json()
        except Exception:
            pass
        return {}

    def reverse_ip_domains(self, ip):
        try:
            import requests
            r = requests.get(f"https://reverseip.domaintools.com/api/{ip}/", timeout=7)
            if r.ok:
                return r.json()
        except Exception:
            pass
        return {}

    def subnet_neighbours(self, ip):
        base = ".".join(ip.split(".")[:3])
        neigh_ips = [f"{base}.{i}" for i in range(1, 255) if f"{base}.{i}" != ip]
        active = []

        def ping(nip):
            try:
                import platform, subprocess
                cmd = []
                if platform.system() == "Windows":
                    cmd = ["ping", "-n", "1", "-w", "650", nip]
                else:
                    cmd = ["ping", "-c", "1", "-W", "1", nip]
                p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                p.communicate(timeout=2)
                if p.returncode == 0:
                    with self.lock:
                        active.append(nip)
            except Exception:
                pass

        threads = []
        for nip in random.sample(neigh_ips, 15):
            t = threading.Thread(target=ping, args=(nip,))
            t.start()
            threads.append(t)
        for t in threads:
            t.join(timeout=2.5)
        return active

    def aggregate_ip_profile(self, ip):
        profile = {}
        if self.is_valid_ipv4(ip) or self.is_valid_ipv6(ip):
            try:
                name = self.reverse_dns_lookup(ip)
                profile['hostname'] = name
            except Exception:
                profile['hostname'] = None
            profile['private'] = self.is_private_ip(ip)
            profile['ports'] = self.port_scan(ip)
            geo_all = self.gather_all_services(ip)
            for src, g in geo_all.items():
                for k, v in (g.items() if isinstance(g, dict) else []):
                    if k not in profile or not profile[k]:
                        profile[k] = v
            whois = self.whois_lookup(ip)
            if whois:
                profile['whois'] = whois
            try:
                profile['as_info'] = self.as_lookup(ip)
            except Exception:
                profile['as_info'] = None
            try:
                profile['bgpview'] = self.bgpview_as_lookup(ip)
            except Exception:
                profile['bgpview'] = None
            threats = self.threat_intel_aggregated(ip)
            profile['threats'] = threats
            try:
                profile['dnsbl'] = self.dnsbl_lookup(ip)
            except Exception:
                profile['dnsbl'] = None
            try:
                profile['tor_exit'] = self.tor_check(ip)
            except Exception:
                profile['tor_exit'] = None
            try:
                profile['onion'] = self.onion_scan(ip)
            except Exception:
                profile['onion'] = None
            try:
                profile['reverse_ip_domains'] = self.reverse_ip_domains(ip)
            except Exception:
                profile['reverse_ip_domains'] = None
            try:
                profile['subnet_neighbours'] = self.subnet_neighbours(ip)
            except Exception:
                profile['subnet_neighbours'] = None
            profile['times'] = self.multi_ping(ip)
            try:
                profile['traceroute'] = self.traceroute(ip)
            except Exception:
                profile['traceroute'] = None
        else:
            profile['error'] = "IP format non reconnu"
        return profile

    def beautify_profile(self, profile, width=60):
        line = "-"*width
        out = []
        for k, v in profile.items():
            if isinstance(v, (str, int, float, type(None))):
                out.append(f"{k:<25}: {v}")
            elif isinstance(v, list):
                out.append(f"{k:<25}: {', '.join(str(x) for x in v[:10])}{'...' if len(v)>10 else ''}")
            elif isinstance(v, dict):
                out.append(f"{k:<25}:")
                for k2, v2 in v.items():
                    if isinstance(v2, list):
                        val = ', '.join(str(x) for x in v2[:5])
                    elif isinstance(v2, dict):
                        val = ' '.join(f"{x}:{y}" for x,y in v2.items())
                    else:
                        val = v2
                    out.append(f"   {k2:<21}: {val}")
            else:
                out.append(f"{k:<25}: {str(v)[:50]}")
        return line + "\n" + "\n".join(out) + f"\n{line}"

def main():
    locator = IPLocalisater()
    while True:
        ip = input("IP ou host à profiler (q pour quitter): ").strip()
        if ip.lower() == "q":
            break
        if locator.is_valid_ipv4(ip) or locator.is_valid_ipv6(ip):
            addr = ip
        else:
            addr = locator.resolve_ip_from_hostname(ip)
            if not addr:
                print("Host inconnu.")
                continue
        print("Analyse en cours (cela peut prendre jusqu'à 1 minute)...")
        profile = locator.aggregate_ip_profile(addr)
        print(locator.beautify_profile(profile, width=80))
        time.sleep(1)

if __name__ == "__main__":
    main()


