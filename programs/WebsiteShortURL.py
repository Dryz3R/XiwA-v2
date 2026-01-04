import re
import requests

class URLShortener:
    def __init__(self):
        self.services = [
            ("is.gd", lambda u: f"https://is.gd/create.php?format=simple&url={u}"),
            ("tinyurl", lambda u: f"https://tinyurl.com/api-create.php?url={u}"),
            ("v.gd", lambda u: f"https://v.gd/create.php?format=simple&url={u}"),
            ("clck.ru", lambda u: f"https://clck.ru/--?url={u}")
        ]

    def is_valid_url(self, url):
        return bool(re.match(r"^https?://", url))

    def shorten(self, url):
        if not self.is_valid_url(url):
            raise ValueError("URL invalide")
        results = {}
        for name, api in self.services:
            try:
                resp = requests.get(api(url), timeout=5)
                if resp.ok:
                    link = resp.text.strip()
                    if re.match(r"^https?://", link):
                        results[name] = link
            except Exception:
                continue
        return results

def main():
    shortener = URLShortener()
    url = input("Entrez l'URL complète à raccourcir: ").strip()
    if not shortener.is_valid_url(url):
        print("URL invalide")
        return
    short_links = shortener.shorten(url)
    if not short_links:
        print("Aucun service n'a répondu.")
        return
    for name, short_url in short_links.items():
        print(f"{name:8}: {short_url}")
        input("Continuer...")

if __name__ == "__main__":
    main()
