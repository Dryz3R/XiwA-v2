import os
import re
import json
import threading
import traceback
import html as html_mod
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from bs4 import BeautifulSoup

class SecretScanner:
    API_KEY_PATTERNS = [
        r'AKIA[0-9A-Z]{16}',
        r'AIza[0-9A-Za-z-_]{35}',
        r'xox[baprs]-([0-9a-zA-Z]{10,48})?',
        r'sk_live_[0-9a-zA-Z]{24}',
        r'gh[opusr]_[A-Za-z0-9_]{36,255}',
        r'eyJ[A-Za-z0-9\.\-_]{20,1000}',
        r'EAACEdEose0cBA[0-9A-Za-z]+',
        r'[hH]eroku[a-zA-Z0-9]{20,}',
        r'key-[0-9a-zA-Z]{32}',
        r'SK[0-9a-fA-F]{32}',
        r'Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*',
        r'[A-Za-z0-9]{32,45}'
    ]
    
    SECRET_PATTERNS = [
        r'api[_\-]?key\s*[:=]\s*["\']?([A-Za-z0-9_\-\.]{10,})["\']',
        r'secret[_\-]?key\s*[:=]\s*["\']?([A-Za-z0-9_\-\.]{10,})["\']',
        r'access[_\-]?token\s*[:=]\s*["\']?([A-Za-z0-9_\-\.]{10,})["\']',
        r'token\s*[:=]\s*["\']?([A-Za-z0-9_\-\.]{10,})["\']',
        r'client[_\-]?id\s*[:=]\s*["\']?([A-Za-z0-9_\-\.]{10,})["\']',
        r'(?:password|passwd)\s*[:=]\s*["\']?(.{4,})["\']'
    ]
    
    @classmethod
    def extract_api_keys(cls, text):
        found = set()
        for pattern in cls.API_KEY_PATTERNS:
            found.update(re.findall(pattern, text))
        return list(found)
    
    @classmethod
    def scan(cls, code):
        results = []
        for pattern in cls.SECRET_PATTERNS:
            results.extend(re.findall(pattern, code, re.IGNORECASE))
        results.extend(cls.extract_api_keys(code))
        return list(set(results))

class CodeAnalyzer:
    @staticmethod
    def extract_php_vars(text):
        vars_found = re.findall(r'\$_(GET|POST|SESSION|COOKIE|SERVER|REQUEST)\s*\[\s*[\'"](\w+)[\'"]\s*\]', text)
        return [{'superglobal': match[0], 'key': match[1]} for match in vars_found]
    
    @staticmethod
    def extract_jsx_tsx_vars(code):
        attrs = re.findall(r'(\w+)\s*=\s*[{"]([^"}]+)[}"]', code)
        hooks = re.findall(r'use(State|Effect|Context|Reducer|Ref|Callback|Memo|LayoutEffect)\s*\(', code)
        return {'attributes': attrs, 'hooks': hooks}
    
    @staticmethod
    def extract_imports(code):
        python_imports = re.findall(r'^\s*import\s+([\w\.]+)', code, re.MULTILINE)
        python_from = re.findall(r'^\s*from\s+([\w\.]+)\s+import', code, re.MULTILINE)
        js_imports = re.findall(r'import\s+.*from\s+[\'"]([^\'"]+)[\'"]', code)
        require_imports = re.findall(r'require\([\'"]([^\'"]+)[\'"]\)', code)
        php_includes = re.findall(r'(include|require)(_once)?\s*\(?\s*[\'"]([^\'"]+)[\'"]\)?;', code)
        
        return {
            'python': list(set(python_imports + python_from)),
            'javascript': list(set(js_imports)),
            'require': list(set(require_imports)),
            'php': list(set([i[2] for i in php_includes]))
        }
    
    @staticmethod
    def extract_env(text):
        envs = re.findall(r'([A-Z_][A-Z0-9_]+)\s*=\s*["\']?([^\s"\']+)', text)
        return dict(envs)

class AssetFetcher:
    def __init__(self, timeout=10, max_workers=5):
        self.timeout = timeout
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.session = requests.Session()
    
    def fetch(self, url, base_url):
        try:
            if not url.startswith('http'):
                url = urljoin(base_url, url)
            response = self.session.get(url, timeout=self.timeout)
            if response.status_code == 200:
                return response.text
        except Exception:
            pass
        return ''
    
    def fetch_multiple(self, urls_with_base):
        futures = {}
        for url, base in urls_with_base:
            future = self.executor.submit(self.fetch, url, base)
            futures[future] = (url, base)
        
        results = {}
        for future in as_completed(futures):
            url, base = futures[future]
            results[url] = future.result()
        
        return results
    
    def close(self):
        self.executor.shutdown(wait=True)
        self.session.close()

class WebScraper:
    SENSITIVE_PATHS = [
        '/.env', '/robots.txt', '/.git/config', '/.gitignore', '/.htaccess',
        '/.well-known/security.txt', '/package.json', '/composer.json',
        '/config.php', '/wp-config.php', '/web.config', '/config.json',
        '/settings.php', '/database.yml', '/docker-compose.yml', '/.aws/credentials'
    ]
    
    def __init__(self, site_url):
        self.site_url = site_url
        self.soup = None
        self.data = {}
        self.fetcher = AssetFetcher()
    
    def scrape(self):
        response = requests.get(self.site_url, timeout=15)
        self.soup = BeautifulSoup(response.text, 'html.parser')
        self._extract_basic_info()
        self._extract_scripts()
        self._extract_links()
        self._extract_stylesheets()
        self._check_sensitive_files()
        self._extract_code_blocks()
        return response.text, self.data
    
    def _extract_basic_info(self):
        self.data['title'] = self.soup.title.text.strip() if self.soup.title else ''
        self.data['meta'] = {}
        for i, meta in enumerate(self.soup.find_all('meta')):
            key = meta.get('name') or meta.get('property') or meta.get('http-equiv') or f"meta_{i}"
            self.data['meta'][key] = meta.get('content', '')
        
        self.data['comments'] = [str(c) for c in self.soup.find_all(
            string=lambda text: isinstance(text, type(self.soup.comment))
        ) if c]
        self.data['env'] = {}
        self.data['scripts'] = []
    
    def _extract_scripts(self):
        for script in self.soup.find_all('script'):
            src = script.get('src')
            code = script.string or script.get_text() or ''
            
            if src:
                fetched_code = self.fetcher.fetch(src, self.site_url)[:10000]
                if fetched_code:
                    code = fetched_code
            
            script_data = {
                'src': src,
                'code_snip': code[:1000],
                'apis': SecretScanner.scan(code),
                'imports': CodeAnalyzer.extract_imports(code),
                'jsx_tsx': CodeAnalyzer.extract_jsx_tsx_vars(code)
            }
            self.data['scripts'].append(script_data)
            self.data['env'].update(CodeAnalyzer.extract_env(code))
    
    def _extract_links(self):
        self.data['links'] = [link['href'] for link in self.soup.find_all('a', href=True)]
    
    def _extract_stylesheets(self):
        self.data['stylesheet_code'] = []
        for css in self.soup.find_all('link', href=True):
            if css.get('rel') and 'stylesheet' in css.get('rel', []):
                css_code = self.fetcher.fetch(css['href'], self.site_url)[:10000]
                if css_code:
                    self.data['stylesheet_code'].append({
                        'href': css['href'],
                        'code_snip': css_code[:1500]
                    })
    
    def _check_sensitive_files(self):
        self.data['sensitive_files'] = {}
        urls_to_fetch = [(urljoin(self.site_url, path), self.site_url) for path in self.SENSITIVE_PATHS]
        results = self.fetcher.fetch_multiple(urls_to_fetch)
        
        for full_url, content in results.items():
            if content and not content.lower().startswith('<!doctype'):
                path = full_url.replace(self.site_url, '')
                self.data['sensitive_files'][path] = content[:4000]
                self.data['env'].update(CodeAnalyzer.extract_env(content))
                
                if path.endswith('.php'):
                    self.data['php_vars'] = CodeAnalyzer.extract_php_vars(content)
                elif path.endswith('.json'):
                    try:
                        parsed = json.loads(content)
                        self.data.setdefault('json_config', {})[path] = parsed
                    except json.JSONDecodeError:
                        continue
    
    def _extract_code_blocks(self):
        code_text_blocks = ''
        for tag in list(self.soup.find_all('code')) + list(self.soup.find_all('pre')):
            text = tag.text.strip()
            if text:
                code_text_blocks += text + '\n'
        
        self.data['code_block_findings'] = {
            'secrets': SecretScanner.scan(code_text_blocks),
            'imports': CodeAnalyzer.extract_imports(code_text_blocks),
            'jsxtsx': CodeAnalyzer.extract_jsx_tsx_vars(code_text_blocks),
            'php_vars': CodeAnalyzer.extract_php_vars(code_text_blocks),
            'env': CodeAnalyzer.extract_env(code_text_blocks)
        }
    
    def __del__(self):
        self.fetcher.close()

class ReportRenderer:
    @staticmethod
    def format_block(title, obj):
        if not obj:
            return ""
        
        if isinstance(obj, dict):
            items = "".join(
                f"<li><b>{html_mod.escape(str(k))}</b>: {html_mod.escape(str(v))}</li>"
                for k, v in obj.items()
            )
            return f"<div class='block'><h3>{title}</h3><ul>{items}</ul></div>"
        elif isinstance(obj, list):
            items = "".join(f"<li>{html_mod.escape(str(x))}</li>" for x in obj)
            return f"<div class='block'><h3>{title}</h3><ul>{items}</ul></div>"
        else:
            return f"<div class='block'><h3>{title}</h3><pre>{html_mod.escape(str(obj))}</pre></div>"
    
    @staticmethod
    def format_code_list(title, codedict_list):
        html = f"<div class='block'><h3>{title}</h3><ul>"
        for d in codedict_list:
            html += f"<li><b>Src:</b> {html_mod.escape(str(d.get('src', 'RAW')))}<ul>"
            for k, v in d.items():
                if k == 'src':
                    continue
                if isinstance(v, (list, dict)):
                    if not v:
                        continue
                    html += f"<li><b>{k}</b>:<br><pre>{html_mod.escape(str(v))}</pre></li>"
                else:
                    html += f"<li><b>{k}</b>: {html_mod.escape(str(v))}</li>"
            html += "</ul></li>"
        html += "</ul></div>"
        return html
    
    @classmethod
    def render(cls, site_name, web_html, data_dict):
        html = f"""<html>
<head>
    <title>Pentest Result: {html_mod.escape(site_name)}</title>
    <style>
        body {{ font-family: monospace, sans-serif; margin: 20px; background: #0d1117; color: #c9d1d9; }}
        .block {{ margin-bottom: 2em; padding: 15px; background: #161b22; border: 1px solid #30363d; border-radius: 6px; }}
        h1 {{ color: #58a6ff; border-bottom: 2px solid #30363d; padding-bottom: 10px; }}
        h3 {{ color: #8b949e; margin-top: 0; }}
        ul {{ padding-left: 20px; }}
        li {{ margin: 5px 0; }}
        pre {{ background: #0d1117; padding: 10px; border: 1px solid #30363d; border-radius: 4px; overflow-x: auto; }}
        code {{ background: #0d1117; padding: 2px 4px; border-radius: 3px; color: #79c0ff; }}
        a {{ color: #58a6ff; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        .danger {{ color: #f85149; }}
        .warning {{ color: #d29922; }}
        .success {{ color: #3fb950; }}
    </style>
</head>
<body>
    <h1>Pentest Report: {html_mod.escape(site_name)}</h1>
"""
        
        html += cls.format_block("Page Title", data_dict.get('title'))
        html += cls.format_block("Meta Tags", data_dict.get('meta'))
        html += cls.format_block("HTML Comments", data_dict.get('comments'))
        html += cls.format_code_list("JavaScript Scripts", data_dict.get('scripts', []))
        html += cls.format_block("Extracted Environment Variables", data_dict.get('env'))
        html += cls.format_block("Discovered Links", data_dict.get('links'))
        html += cls.format_code_list("External CSS", data_dict.get('stylesheet_code', []))
        
        if 'sensitive_files' in data_dict and data_dict['sensitive_files']:
            sensitive_html = "<div class='block'><h3 class='danger'>Sensitive Files Found</h3><ul>"
            for path, content in data_dict['sensitive_files'].items():
                sensitive_html += f"<li><b>{html_mod.escape(path)}</b>:<br><pre>{html_mod.escape(content[:500])}</pre></li>"
            sensitive_html += "</ul></div>"
            html += sensitive_html
        
        if 'json_config' in data_dict:
            html += cls.format_block("JSON Configuration Files", data_dict['json_config'])
        
        if 'php_vars' in data_dict:
            html += cls.format_block("PHP Variables", data_dict['php_vars'])
        
        html += cls.format_block("Code Block Analysis", data_dict.get('code_block_findings'))
        
        secrets_found = []
        for script in data_dict.get('scripts', []):
            secrets_found.extend(script.get('apis', []))
        
        if secrets_found:
            html += f"""<div class='block'>
                <h3 class='danger'>CRITICAL: Secrets Discovered</h3>
                <ul>"""
            for secret in set(secrets_found):
                html += f"<li class='danger'>{html_mod.escape(secret)}</li>"
            html += "</ul></div>"
        
        html += """
    <div class='block'>
        <h3>Scan Summary</h3>
        <p><strong>Total Scripts Analyzed:</strong> """ + str(len(data_dict.get('scripts', []))) + """</p>
        <p><strong>Total Links Found:</strong> """ + str(len(data_dict.get('links', []))) + """</p>
        <p><strong>Sensitive Files Found:</strong> """ + str(len(data_dict.get('sensitive_files', {}))) + """</p>
        <p><strong>Secrets Discovered:</strong> """ + str(len(set(secrets_found))) + """</p>
    </div>
</body>
</html>"""
        
        return html

class ResultsManager:
    def __init__(self, base_output_dir="output/Penetration Test"):
        self.base_output_dir = base_output_dir
        os.makedirs(self.base_output_dir, exist_ok=True)
    
    def save_results(self, site_name, web_html, data_dict):
        site_dir = os.path.join(self.base_output_dir, site_name)
        os.makedirs(site_dir, exist_ok=True)
        
        with open(os.path.join(site_dir, 'raw_page.html'), 'w', encoding='utf-8') as f:
            f.write(web_html)
        
        with open(os.path.join(site_dir, 'report.html'), 'w', encoding='utf-8') as f:
            report_html = ReportRenderer.render(site_name, web_html, data_dict)
            f.write(report_html)
        
        with open(os.path.join(site_dir, 'data.json'), 'w', encoding='utf-8') as f:
            json.dump(data_dict, f, indent=2, ensure_ascii=False)
        
        return site_dir

class PentestOrchestrator:
    def __init__(self, max_concurrent_scans=3):
        self.max_concurrent_scans = max_concurrent_scans
        self.results_manager = ResultsManager()
        self.summary = []
        self.exceptions = []
    
    def test_single_site(self, site_url, idx=None):
        try:
            site_name = site_url.replace("http://", "").replace("https://", "").split("/")[0]
            
            if idx:
                print(f"[{idx}] Scanning: {site_name}")
            
            scraper = WebScraper(site_url)
            web_html, scan_data = scraper.scrape()
            
            output_dir = self.results_manager.save_results(site_name, web_html, scan_data)
            
            result = {
                'url': site_url,
                'status': 'success',
                'site_name': site_name,
                'output_dir': output_dir,
                'secrets_found': len([s for script in scan_data.get('scripts', []) for s in script.get('apis', [])]),
                'sensitive_files': len(scan_data.get('sensitive_files', {}))
            }
            
            if idx:
                print(f"[{idx}] Completed: {site_name} - Found {result['secrets_found']} secrets, {result['sensitive_files']} sensitive files")
            
            self.summary.append(result)
            return result
            
        except Exception as e:
            error_msg = f"Error scanning {site_url}: {str(e)}"
            error_details = traceback.format_exc()
            
            result = {
                'url': site_url,
                'status': 'error',
                'error': str(e)
            }
            
            self.summary.append(result)
            self.exceptions.append(f"{error_msg}\n{error_details}")
            
            if idx:
                print(f"[{idx}] Failed: {site_url} - {str(e)}")
            
            return result
    
    def test_multiple_sites(self, site_urls):
        print(f"Starting penetration test for {len(site_urls)} sites")
        print("-" * 60)
        
        with ThreadPoolExecutor(max_workers=self.max_concurrent_scans) as executor:
            futures = {}
            for idx, url in enumerate(site_urls, 1):
                future = executor.submit(self.test_single_site, url, idx)
                futures[future] = url
            
            for future in as_completed(futures):
                pass
        
        self._generate_batch_report(site_urls)
    
    def _generate_batch_report(self, site_urls):
        batch_dir = os.path.join(self.results_manager.base_output_dir, "Batch_Report")
        os.makedirs(batch_dir, exist_ok=True)
        
        successful = [s for s in self.summary if s['status'] == 'success']
        failed = [s for s in self.summary if s['status'] == 'error']
        
        report_html = f"""<html>
<head>
    <title>Batch Pentest Report</title>
    <style>
        body {{ font-family: monospace, sans-serif; margin: 20px; background: #0d1117; color: #c9d1d9; }}
        h1 {{ color: #58a6ff; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #30363d; }}
        th {{ background: #161b22; color: #8b949e; }}
        .success {{ color: #3fb950; }}
        .error {{ color: #f85149; }}
        .stats {{ display: flex; justify-content: space-between; margin: 20px 0; }}
        .stat-box {{ background: #161b22; padding: 15px; border-radius: 6px; flex: 1; margin: 0 10px; }}
    </style>
</head>
<body>
    <h1>Batch Penetration Test Report</h1>
    
    <div class='stats'>
        <div class='stat-box'>
            <h3>Total Sites</h3>
            <p>{len(site_urls)}</p>
        </div>
        <div class='stat-box'>
            <h3>Successful</h3>
            <p class='success'>{len(successful)}</p>
        </div>
        <div class='stat-box'>
            <h3>Failed</h3>
            <p class='error'>{len(failed)}</p>
        </div>
    </div>
    
    <h2>Detailed Results</h2>
    <table>
        <tr>
            <th>URL</th>
            <th>Status</th>
            <th>Secrets Found</th>
            <th>Sensitive Files</th>
            <th>Report</th>
        </tr>"""
        
        for result in self.summary:
            if result['status'] == 'success':
                report_path = os.path.join(result['output_dir'], 'report.html')
                report_link = f"<a href='file://{os.path.abspath(report_path)}'>View Report</a>"
                report_html += f"""
        <tr>
            <td>{html_mod.escape(result['url'])}</td>
            <td class='success'>Success</td>
            <td>{result['secrets_found']}</td>
            <td>{result['sensitive_files']}</td>
            <td>{report_link}</td>
        </tr>"""
            else:
                report_html += f"""
        <tr>
            <td>{html_mod.escape(result['url'])}</td>
            <td class='error'>Error: {html_mod.escape(result['error'])}</td>
            <td>N/A</td>
            <td>N/A</td>
            <td>N/A</td>
        </tr>"""
        
        report_html += """
    </table>
    
    <h2>Secrets Summary</h2>
    <ul>"""
        
        all_secrets = []
        for result in successful:
            site_dir = result['output_dir']
            data_file = os.path.join(site_dir, 'data.json')
            if os.path.exists(data_file):
                with open(data_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    for script in data.get('scripts', []):
                        all_secrets.extend(script.get('apis', []))
        
        for secret in set(all_secrets):
            report_html += f"<li>{html_mod.escape(secret)}</li>"
        
        report_html += """
    </ul>
</body>
</html>"""
        
        report_path = os.path.join(batch_dir, "batch_report.html")
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report_html)
        
        print("\n" + "=" * 60)
        print("BATCH TEST COMPLETE")
        print("=" * 60)
        print(f"Successful scans: {len(successful)}")
        print(f"Failed scans: {len(failed)}")
        print(f"Total secrets found: {len(set(all_secrets))}")
        print(f"Batch report saved to: {os.path.abspath(report_path)}")
        
        if self.exceptions:
            print("\nExceptions encountered:")
            for exc in self.exceptions:
                print(f"- {exc.splitlines()[0]}")

class PentestCLI:
    @staticmethod
    def get_urls_from_input():
        print("=" * 60)
        print("PENETRATION TESTING TOOL")
        print("=" * 60)
        print("Enter target URLs (one per line). Leave empty to start scan.")
        print("Enter 'file:<path>' to load URLs from a file.")
        print("=" * 60)
        
        urls = []
        while True:
            user_input = input(f"URL [{len(urls)+1}]: ").strip()
            
            if not user_input:
                if urls:
                    break
                print("At least one URL is required.")
                continue
            
            if user_input.lower().startswith('file:'):
                file_path = user_input[5:].strip()
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        file_urls = [line.strip() for line in f if line.strip()]
                        urls.extend(file_urls)
                    print(f"Loaded {len(file_urls)} URLs from {file_path}")
                except Exception as e:
                    print(f"Error reading file: {e}")
                continue
            
            if not (user_input.startswith("http://") or user_input.startswith("https://")):
                user_input = "http://" + user_input
            
            urls.append(user_input)
        
        return urls
    
    @staticmethod
    def run():
        urls = PentestCLI.get_urls_from_input()
        
        if not urls:
            print("No URLs provided. Exiting.")
            return
        
        print(f"\nStarting analysis of {len(urls)} target(s)...")
        
        orchestrator = PentestOrchestrator(max_concurrent_scans=5)
        orchestrator.test_multiple_sites(urls)

if __name__ == "__main__":
    PentestCLI.run()