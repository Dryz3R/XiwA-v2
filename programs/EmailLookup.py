import requests
import re
import json
import time
import random
import string
import os
import socket
import sys

class EmailLookup:
    def __init__(self):
        self.session = requests.Session()
        self.proxies = None
        self.headers_default = [{"User-Agent": f"Mozilla/5.0 (Windows NT 10.{x}; rv:10.{y}) Gecko/20{1900+x+y} Firefox/10.{x+y}"}
                                for x in range(10) for y in range(10)]
        self.domains_check = [
            "twitter.com", "facebook.com", "github.com", "linkedin.com", "instagram.com", "dropbox.com", "twitch.tv",
            "stackoverflow.com", "reddit.com", "medium.com", "wordpress.com", "tumblr.com", "flickr.com", "gravatar.com",
            "pinterest.com", "vimeo.com", "soundcloud.com", "slack.com", "paypal.com", "skype.com", "amazon.com", "apple.com",
            "netflix.com", "ebay.com", "adobe.com", "yahoo.com", "live.com", "microsoft.com", "discord.com", "telegram.org"
        ]
        self.social_patterns = {
            "twitter.com": ["/i/user/signup", "/account/begin_password_reset.json"],
            "facebook.com": ["/login/identify/"],
            "instagram.com": ["/accounts/account_recovery_send_ajax/"],
            "github.com": ["/password_reset"],
            "linkedin.com": ["/uas/request-password-reset"],
            "dropbox.com": ["/ajax_send_reset_password_link"],
            "pinterest.com": ["/password/reset/"],
            "gravatar.com": ["/ajax/users/exists.json"],
            "yahoo.com": ["/ws/mail/v1/usernames"],
            "apple.com": ["/account/recovery"],
            "paypal.com": ["/auth/validateemail"]
        }
        self.custom_config = {}

    def random_headers(self):
        return random.choice(self.headers_default)

    def email_format(self, email):
        e = email.lower().strip()
        if "<" in e and ">" in e: e = e.split("<")[1].split(">")[0]
        return e

    def test_mx_lookup(self, email):
        domain = email.split("@")[-1]
        try:
            import dns.resolver
        except:
            return []
        try:
            mx_records = []
            answers = dns.resolver.resolve(domain, "MX", lifetime=3)
            for r in answers:
                mx_records.append(str(r.exchange).rstrip("."))
            return mx_records
        except:
            return []

    def google_images(self, email):
        q = f'"{email}"'
        url = f"https://www.google.com/search?tbm=isch&q={requests.utils.quote(q)}"
        headers = self.random_headers()
        res = self.session.get(url, headers=headers)
        imgs = []
        try:
            imgs = re.findall(r'"ou":"([^"]+)"', res.text)
        except:
            pass
        imgs = list(dict.fromkeys(imgs))
        return imgs

    def duckduckgo_images(self, email):
        q = f'"{email}"'
        url = f"https://duckduckgo.com/?q={requests.utils.quote(q)}&iax=images&ia=images"
        headers = self.random_headers()
        result = []
        try:
            r = self.session.get(url, headers=headers)
            imgs = re.findall(r'"image":"([^"]+)"', r.text)
            for img in imgs:
                result.append(img.replace("\\u002F", "/"))
        except: pass
        return result

    def yandex_images(self, email):
        q = f'"{email}"'
        url = f"https://yandex.com/images/search?text={requests.utils.quote(q)}"
        headers = self.random_headers()
        r = self.session.get(url, headers=headers)
        imgs = re.findall(r'"url":"([^"]+)"', r.text)
        return list(dict.fromkeys(imgs))

    def bing_images(self, email):
        q = f'"{email}"'
        url = f"https://www.bing.com/images/search?q={requests.utils.quote(q)}"
        headers = self.random_headers()
        res = self.session.get(url, headers=headers)
        imgs = re.findall(r'"murl":"([^"]+)"', res.text)
        return list(dict.fromkeys(imgs))

    def gravatar_image(self, email):
        import hashlib
        e = email.strip().lower().encode()
        d = hashlib.md5(e).hexdigest()
        gravurl = f"https://www.gravatar.com/avatar/{d}?s=200"
        return gravurl

    def find_archives(self, email):
        q = f'"{email}"'
        url = f"https://web.archive.org/cdx/search/cdx?url=*&output=json&limit=20&filter=statuscode:200&fl=original&collapse=urlkey&q={requests.utils.quote(q)}"
        res = self.session.get(url)
        if res.status_code != 200:
            return []
        try:
            data = res.json()
            return [x[0] for x in data[1:]] if len(data) > 1 else []
        except:
            return []

    def wayback_scrapes(self, email):
        results = []
        url = "https://web.archive.org/save"
        for base in ["https://", "http://"]:
            baseurl = f"{base}{email.split('@')[-1]}/"
            try:
                x = self.session.get(f"https://web.archive.org/web/*/{baseurl}*").text
                out = re.findall(r'https://web.archive.org/(web/[0-9]+/[^"]+)', x)
                for o in out:
                    if baseurl in o:
                        results.append("https://web.archive.org/" + o)
            except: pass
        return list(set(results))

    def github_email_search(self, email):
        found = []
        user = email.split("@")[0]
        url = f"https://github.com/search?q={requests.utils.quote(email)}&type=Users"
        r = self.session.get(url, headers=self.random_headers())
        xs = re.findall(r'/([a-zA-Z0-9\-]+)/" class="mr-1"', r.text)
        for x in xs:
            found.append("https://github.com/" + x)
        return list(set(found))

    def search_leakpeek(self, email):
        url = "https://leakpeek.com/api/search"
        headers = self.random_headers()
        data = {"query": email}
        try:
            res = self.session.post(url, data=data, headers=headers)
            if "data" in res.text:
                d = res.json()
                results = []
                for row in d.get('data', []):
                    results.append(row)
                return results
        except Exception:
            pass
        return []

    def search_dehashed(self, email):
        url = "https://www.dehashed.com/search"
        results = []
        try:
            params = {"query": email}
            headers = self.random_headers()
            res = self.session.get(url, params=params, headers=headers)
            for match in re.findall(r'<tr.*?>\s*<td[^>]*>([^<]+)</td>\s*<td[^>]*>([^<]+)</td>\s*<td[^>]*>([^<]+)</td>', res.text):
                results.append(match)
        except: pass
        return results

    def skymem_search(self, email):
        q = f'"{email}"'
        url = f"https://www.skymem.info/srch?q={requests.utils.quote(q)}"
        results = []
        try:
            res = self.session.get(url, headers=self.random_headers())
            for m in re.findall(r'(mailto:[^"]+)', res.text):
                if email in m:
                    results.append(m)
        except: pass
        return list(set(results))

    def search_breached_co(self, email):
        url = f"https://breached.co/search?search={requests.utils.quote(email)}"
        found = []
        try:
            r = self.session.get(url, headers=self.random_headers())
            for x in re.findall(r'>([a-z0-9._%-]+@[a-z0-9.-]+\.[a-z]{2,})<', r.text, re.IGNORECASE):
                if email in x:
                    found.append(x)
        except: pass
        return found

    def search_leakfr(self, email):
        url = "https://leak-lookup.com/api/search"
        results = []
        try:
            apikey = ""
            headers = {"Authorization": apikey}
            res = self.session.post(url, data={"query": email}, headers=headers)
            if res.status_code == 200:
                d = res.json()
                results = d.get("found", [])
        except: pass
        return results

    def info_packet(self, email):
        data = {}
        data["length"] = len(email)
        data["has_plus"] = "+" in email.split("@")[0]
        data["has_dot"] = "." in email.split("@")[0]
        data["domain"] = email.split("@")[-1]
        data["name"] = email.split("@")[0]
        return data

    def possible_usernames(self, email):
        name = email.split("@")[0]
        result = []
        result.append(name)
        if "." in name:
            parts = [x for x in name.split(".") if x]
            if len(parts) >= 2:
                result.append(parts[0])
                result.append(parts[1])
                result.append("".join(parts))
        if "_" in name:
            result.append(name.replace("_", ""))
        return list(set(result))

    def domain_found_year(self, email):
        import whois
        d = email.split("@")[-1]
        try:
            w = whois.whois(d)
            return str(w.creation_date)
        except:
            return ""

    def social_presence(self, email):
        pres = {}
        for site in self.domains_check:
            test_url = f"https://{site}/"
            try:
                r = self.session.get(test_url, timeout=2, headers=self.random_headers())
                pres[site] = r.status_code
            except: pres[site] = None
        return pres

    def username_social_profiles(self, email):
        name = email.split("@")[0]
        urls = []
        bases = [
            "https://github.com/{user}",
            "https://twitter.com/{user}",
            "https://linkedin.com/in/{user}",
            "https://reddit.com/user/{user}",
            "https://instagram.com/{user}",
            "https://facebook.com/{user}",
            "https://medium.com/@{user}",
            "https://t.me/{user}",
            "https://keybase.io/{user}",
            "https://soundcloud.com/{user}",
        ]
        names = [name]
        if "." in name: names.append(name.replace(".", ""))
        if "_" in name: names.append(name.replace("_", ""))
        for n in set(names):
            for base in bases:
                urls.append(base.replace("{user}", n))
        existing = []
        for u in urls:
            try:
                r = self.session.get(u, timeout=2, headers=self.random_headers())
                if r.status_code == 200:
                    existing.append(u)
            except: continue
        return existing

    def check_disposable(self, email):
        blacklist = ["tempmail", "yopmail", "guerrillamail", "10minutemail", "mailinator", "trashmail", "maildrop", "dispostable", "fakeinbox", "mailnesia"]
        dom = email.split("@")[-1].lower()
        for b in blacklist:
            if b in dom:
                return True
        return False

    def search_possible_passwords(self, email):
        import itertools
        import datetime

        base = email.split("@")[0]
        domain = email.split("@")[1].split(".")[0] if "@" in email else ""
        parts = re.split(r'[\._\-]', base)
        simple_words = list(set([base] + parts + [domain]))
        now = datetime.datetime.now()
        years = [str(year) for year in range(1980, now.year + 2)]
        months = [f"{m:02d}" for m in range(1, 13)]
        days = [f"{d:02d}" for d in range(1, 32)]
        specials = ["", "!", "@", "#", "$", "%", "&", "*", ".", "-", "_"]
        prefixes = ["", "the", "mon", "my", "your", "super", "ultra", "admin", "root", "user", "pro"]
        suffixes = ["", "1", "01", "001", "12", "123", "1234", "007", "69", "666", "777", "999", "2020", "2021", "2022", "2023", "2024", "password"]
        keyboard_walks = ["qwerty", "azerty", "123456", "qazwsx", "asdfgh", "987654"]
        reversed_words = [w[::-1] for w in simple_words if len(w) > 3]
        leet_table = str.maketrans("aAeEiIoOsStT", "443311005577")
        leet_words = [w.translate(leet_table) for w in simple_words]
        combos = set()
        for w in simple_words + reversed_words + leet_words + keyboard_walks:
            for y in years:
                for m in months:
                    for d in days:
                        for suf in suffixes:
                            for sp in specials:
                                combos.add(f"{w}{suf}{sp}")
                                combos.add(f"{w}{y}{sp}")
                                combos.add(f"{w}{m}{sp}")
                                combos.add(f"{w}{m}{y}{sp}")
                                combos.add(f"{w}{d}{m}{y}{sp}")
                                combos.add(f"{w}{d}{sp}")
                                combos.add(f"{y}{w}{sp}")
                                combos.add(f"{d}{m}{w}{sp}")
                                combos.add(f"{w}{m}{d}{sp}")
                                combos.add(f"{w}{m}{d}{y}{sp}")
                                combos.add(f"{w}{d}{m}{sp}")
                                combos.add(f"{w}{suf}{y}{sp}")
        for pre in prefixes:
            for suf in suffixes:
                for sp in specials:
                    for w in simple_words + reversed_words + leet_words:
                        combos.add(f"{pre}{w}{suf}{sp}")
                        combos.add(f"{pre}{w}{sp}{suf}")
                        combos.add(f"{pre}{w}{domain}{suf}{sp}")
                        combos.add(f"{w}{pre}{suf}{sp}")
        for w1, w2 in itertools.permutations(simple_words, 2):
            for suf in suffixes:
                for sp in specials:
                    combos.add(f"{w1}{w2}{suf}{sp}")
                    combos.add(f"{w2}{w1}{suf}{sp}")
        if email:
            e = email.replace("@", "").replace(".", "").replace("_", "")
            combos.add(e)
            combos.add(e[::-1])
        combos = {c for c in combos if len(c) >= 6 and not c.isspace()}
        if base.isdigit():
            combos.add(base)
        list_pw = sorted(combos)
        top100 = [
            "password", "123456", "123456789", "azerty", "qwerty", "111111", "abc123", "password1",
            "admin", "letmein", "welcome", "monkey", "iloveyou", "dragon", "sunshine", "football"
        ]
        list_pw = top100 + list_pw
        return list_pw[:3000]

    def search_public_pastes(self, email):
        found = []
        url = f"https://pastebin.com/u/{email.split('@')[0]}"
        try:
            r = self.session.get(url, timeout=3, headers=self.random_headers())
            for x in re.findall(r'/[A-Za-z0-9]{8}', r.text):
                found.append("https://pastebin.com" + x)
        except: pass
        return found

    def mailtester_validation(self, email):
        url = f"https://mailtester.com/testmail.php"
        headers = self.random_headers()
        try:
            res = self.session.post(url, data={"email": email}, headers=headers)
            valid = "E-mail address is valid" in res.text or "E-mail address exists" in res.text
            return valid
        except: return None

    def emailrep_validation(self, email):
        url = f"https://emailrep.io/{email}"
        try:
            r = self.session.get(url, headers=self.random_headers())
            if r.status_code == 200:
                return r.json()
        except:
            return {}
        return {}

    def reverse_avatar_images(self, email):
        res = []
        try:
            q = email.split("@")[0]
            url = f"https://avatars.dicebear.com/api/identicon/{q}.svg"
            res.append(url)
            url2 = f"https://ui-avatars.com/api/?name={q}&background=random"
            res.append(url2)
            res.append(self.gravatar_image(email))
        except Exception:
            pass
        return res

    def accounts_lookup(self, email):
        results = {}
        url = f"https://api.ivelt.me/v3/email/{email}"
        try:
            r = self.session.get(url)
            if r.status_code == 200:
                data = r.json()
                for k, v in data.items():
                    if isinstance(v, dict) and v.get("exists"):
                        results[k] = v
        except Exception:
            pass
        return results

    def full_email_brute(self, email):
        domain = email.split("@")[-1]
        users = []
        chars = string.ascii_lowercase + string.digits
        for n in range(1,3):
            for comb in range(100):
                trial = ''.join(random.choices(chars, k=n))
                addr = f"{trial}@{domain}"
                try:
                    if self.mailtester_validation(addr):
                        users.append(addr)
                except: pass
        return users

    def hunter_search(self, email):
        apikey = ""
        domain = email.split("@")[-1]
        url = f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={apikey}"
        try:
            res = self.session.get(url)
            if res.status_code == 200:
                return res.json()
        except: pass
        return {}

    def clearbit_profile(self, email):
        apikey = ""
        url = f"https://person.clearbit.com/v2/people/find?email={email}"
        headers = {"Authorization": f"Bearer {apikey}"}
        try:
            res = self.session.get(url, headers=headers)
            if res.status_code == 200:
                return res.json()
        except: pass
        return {}

    def mx_mx(self, domain):
        try:
            import dns.resolver
            answers = dns.resolver.resolve(domain, "MX", lifetime=2)
            return [str(x.exchange) for x in answers]
        except: return []

    def dmarc_txt(self, domain):
        try:
            import dns.resolver
            answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=1)
            return [x.strings[0].decode() for x in answers]
        except: return []

    def spf_txt(self, domain):
        try:
            import dns.resolver
            answers = dns.resolver.resolve(domain, "TXT", lifetime=1)
            texts = [b''.join(x.strings).decode(errors="ignore") for x in answers]
            return [t for t in texts if "spf" in t]
        except: return []

    def check_email_deliverability(self, email):
        domain = email.split("@")[-1]
        mxs = self.mx_mx(domain)
        spf = self.spf_txt(domain)
        dmarc = self.dmarc_txt(domain)
        return {"mx": mxs, "spf": spf, "dmarc": dmarc}

    def get_dns_a(self, domain):
        try:
            import dns.resolver
            result = [x.address for x in dns.resolver.resolve(domain, "A", lifetime=1)]
            return result
        except: return []

    def run(self):
        print("\n" + "="*70 + "\nEmail Lookup\n" + "="*70 + "\n")
        email = input("Email à rechercher : ").strip()
        if not email or "@" not in email:
            print("Email invalide.")
            return
        print("\nInfo email:")
        ep = self.info_packet(email)
        for k in sorted(ep): print(f"{k}: {ep[k]}")
        print("\nMX Records:", self.mx_mx(ep['domain']))
        print("SPF:", self.spf_txt(ep['domain']))
        print("DMARC:", self.dmarc_txt(ep["domain"]))
        print("\nAdresse temporaire possible?:", "OUI" if self.check_disposable(email) else "NON")
        print("\nFormat usernames dérivés:")
        for username in self.possible_usernames(email): print(username)
        print("\nAnnée de creation du domaine (if possible):", self.domain_found_year(email))
        print("\nPrésence sur Réseaux Sociaux (test direct):")
        social = self.username_social_profiles(email)
        for s in social:
            print(s)
        print("\nRecherche d'images associées (Google):")
        images = self.google_images(email)
        if images:
            print(f"Trouvé: {len(images)} images ; premiers liens :")
        for img in images[:8]:
            print(img)
        ddgimg = self.duckduckgo_images(email)
        if ddgimg:
            print("\nDuckDuckGo Images:", len(ddgimg))
            for img in ddgimg[:5]: print(img)
        yaimg = self.yandex_images(email)
        if yaimg:
            print("\nYandex Images:", len(yaimg))
            for img in yaimg[:5]: print(img)
        bingimg = self.bing_images(email)
        if bingimg:
            print("\nBing Images:", len(bingimg))
            for img in bingimg[:5]: print(img)
        print("\nReverse Avatars probables (gravatar etc) :")
        for url in self.reverse_avatar_images(email):
            print(url)
        print("\nPastes et archives publiques trouvées:")
        archives = self.find_archives(email)
        for a in archives: print(a)
        for a in self.public_archive_email(email): print(a)
        for a in self.wayback_scrapes(email): print(a)
        print("\nRecherche leaks publics (skymem, dehashed, paste, breached):")
        for t in [self.skymem_search(email), self.search_dehashed(email), self.search_breached_co(email), self.search_leakpeek(email), self.search_leakfr(email)]:
            for l in t: print(l)
        print("\nPastes publics (pastebin):")
        for p in self.search_public_pastes(email):
            print(p)
        print("\nProfils GitHub possiblement associés:")
        for g in self.github_email_search(email): print(g)
        print("\nComptes trouvés (services externes):")
        accs = self.accounts_lookup(email)
        for site, info in accs.items(): print(f"{site}: {info}")
        print("\nValidation mailtester:")
        vmt = self.mailtester_validation(email)
        print("✓" if vmt else "✗")
        print("\nEmailRep info :")
        print(json.dumps(self.emailrep_validation(email), ensure_ascii=False, indent=2))
        print("\nTests de livraison/sécurité MX/SPF/DMARC:")
        print(json.dumps(self.check_email_deliverability(email), ensure_ascii=False, indent=2))
        print("\nBruteforce potentielles sur le domaine:")
        for user in self.full_email_brute(email): print(user)
        print("\nSuggestions mot de passe récurrents pour email :")
        for pwd in self.search_possible_passwords(email):
            print(pwd)

    def public_archive_email(self, email):
        found = []
        name = email.split("@")[0]
        domain = email.split("@")[1]
        urls = [
            f"https://webcache.googleusercontent.com/search?q=cache:{email}",
            f"https://archive.org/search.php?query={requests.utils.quote(email)}",
            f"https://web.archive.org/web/{domain}/*",
            f"https://web.archive.org/web/*/mailto:{email}"
        ]
        for u in urls:
            try:
                r = self.session.get(u, headers=self.random_headers(), timeout=5)
                if email in r.text:
                    found.append(u)
            except: continue
        return found

if __name__ == "__main__":
    EmailLookup().run()
