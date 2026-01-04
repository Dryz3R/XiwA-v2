import sys
import re
import json
import socket
import requests
import threading
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

class PHPInfoUltimateScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0'
        })
        self.results = {}
        self.found_paths = []
        self.vulnerabilities = []
        self.extracted_data = {}
        
    def get_common_paths(self):
        return [
            '/phpinfo.php', '/info.php', '/test.php', '/php.php', '/admin/phpinfo.php', 
            '/admin/info.php', '/admin/test.php', '/admin/php.php', '/public/phpinfo.php', 
            '/public/info.php', '/public/test.php', '/public/php.php', '/includes/phpinfo.php', 
            '/includes/info.php', '/includes/test.php', '/includes/php.php', '/assets/phpinfo.php', 
            '/assets/info.php', '/assets/test.php', '/assets/php.php', '/scripts/phpinfo.php', 
            '/scripts/info.php', '/scripts/test.php', '/scripts/php.php', '/cgi-bin/phpinfo.php', 
            '/cgi-bin/info.php', '/cgi-bin/test.php', '/cgi-bin/php.php', '/php/phpinfo.php', 
            '/php/info.php', '/php/test.php', '/php/php.php', '/system/phpinfo.php', '/system/info.php', 
            '/system/test.php', '/system/php.php', '/tmp/phpinfo.php', '/tmp/info.php', '/tmp/test.php', 
            '/tmp/php.php', '/uploads/phpinfo.php', '/uploads/info.php', '/uploads/test.php', 
            '/uploads/php.php', '/backup/phpinfo.php', '/backup/info.php', '/backup/test.php', 
            '/backup/php.php', '/old/phpinfo.php', '/old/info.php', '/old/test.php', '/old/php.php', 
            '/new/phpinfo.php', '/new/info.php', '/new/test.php', '/new/php.php', '/dev/phpinfo.php', 
            '/dev/info.php', '/dev/test.php', '/dev/php.php', '/staging/phpinfo.php', '/staging/info.php', 
            '/staging/test.php', '/staging/php.php', '/production/phpinfo.php', '/production/info.php', 
            '/production/test.php', '/production/php.php', '/live/phpinfo.php', '/live/info.php', 
            '/live/test.php', '/live/php.php', '/web/phpinfo.php', '/web/info.php', '/web/test.php', 
            '/web/php.php', '/www/phpinfo.php', '/www/info.php', '/www/test.php', '/www/php.php', 
            '/html/phpinfo.php', '/html/info.php', '/html/test.php', '/html/php.php', '/htdocs/phpinfo.php', 
            '/htdocs/info.php', '/htdocs/test.php', '/htdocs/php.php', '/var/www/phpinfo.php', 
            '/var/www/info.php', '/var/www/test.php', '/var/www/php.php', '/home/phpinfo.php', 
            '/home/info.php', '/home/test.php', '/home/php.php', '/data/phpinfo.php', '/data/info.php', 
            '/data/test.php', '/data/php.php', '/app/phpinfo.php', '/app/info.php', '/app/test.php', 
            '/app/php.php', '/api/phpinfo.php', '/api/info.php', '/api/test.php', '/api/php.php', 
            '/v1/phpinfo.php', '/v1/info.php', '/v1/test.php', '/v1/php.php', '/v2/phpinfo.php', 
            '/v2/info.php', '/v2/test.php', '/v2/php.php', '/adminer.php', '/pma.php', '/myadmin.php', 
            '/dbadmin.php', '/sql.php', '/mysql.php', '/database.php', '/phpMyAdmin.php', '/admin.php', 
            '/administrator.php', '/wp-admin/phpinfo.php', '/wp-admin/info.php', '/wp-admin/test.php', 
            '/wp-admin/php.php', '/wordpress/phpinfo.php', '/wordpress/info.php', '/wordpress/test.php', 
            '/wordpress/php.php', '/joomla/phpinfo.php', '/joomla/info.php', '/joomla/test.php', 
            '/joomla/php.php', '/drupal/phpinfo.php', '/drupal/info.php', '/drupal/test.php', 
            '/drupal/php.php', '/magento/phpinfo.php', '/magento/info.php', '/magento/test.php', 
            '/magento/php.php', '/prestashop/phpinfo.php', '/prestashop/info.php', '/prestashop/test.php', 
            '/prestashop/php.php', '/opencart/phpinfo.php', '/opencart/info.php', '/opencart/test.php', 
            '/opencart/php.php', '/config.php', '/configuration.php', '/settings.php', '/setup.php', 
            '/install.php', '/update.php', '/upgrade.php', '/maintenance.php', '/debug.php', 
            '/error.php', '/errors.php', '/log.php', '/logs.php', '/status.php', '/server-status', 
            '/server-info', '/.env', '/env.php', '/environment.php', '/local.php', '/development.php', 
            '/staging.php', '/production.php', '/live.php', '/demo.php', '/test123.php', '/123.php', 
            '/aaa.php', '/xyz.php', '/asdf.php', '/qwerty.php', '/temp.php', '/temporary.php', 
            '/backdoor.php', '/shell.php', '/cmd.php', '/c99.php', '/r57.php', '/wso.php', '/b374k.php'
        ]
    
    def get_file_extensions(self):
        return [
            '.php', '.php3', '.php4', '.php5', '.php7', '.phps', '.phtml', 
            '.phar', '.inc', '.module', '.plugin', '.cgi', '.fcgi', '.pl', 
            '.py', '.rb', '.asp', '.aspx', '.jsp', '.do', '.action'
        ]
    
    def get_common_parameters(self):
        return [
            '?phpinfo=1', '?info=1', '?test=1', '?debug=1', '?admin=1', 
            '?mode=phpinfo', '?action=phpinfo', '?page=phpinfo', '?view=phpinfo', 
            '?show=phpinfo', '?display=phpinfo', '?do=phpinfo', '?cmd=phpinfo', 
            '?exec=phpinfo', '?run=phpinfo', '?phpinfo', '?info', '?test', 
            '?PHPSESSID=phpinfo', '?lang=phpinfo', '?theme=phpinfo', '?template=phpinfo'
        ]
    
    def get_subdomains(self):
        return [
            'phpinfo', 'info', 'test', 'admin', 'dev', 'staging', 'development', 
            'debug', 'server', 'status', 'monitor', 'stats', 'panel', 'control', 
            'manage', 'web', 'www', 'secure', 'api', 'internal', 'private', 
            'hidden', 'secret', 'backup', 'old', 'new', 'temp', 'temporary'
        ]
    
    def detect_phpinfo_advanced(self, html_content, url):
        detection_score = 0
        indicators = []
        
        phpinfo_patterns = [
            r'<h1 class="p">PHP Version (\d+\.\d+\.\d+)</h1>',
            r'<tr><td class="e">System </td><td class="v">([^<]+)</td></tr>',
            r'<title>phpinfo\(\)</title>',
            r'phpinfo\(\)',
            r'PHP Version',
            r'System</td>',
            r'Build Date</td>',
            r'Configure Command</td>',
            r'Server API</td>',
            r'Virtual Directory Support</td>',
            r'Configuration File \(php\.ini\) Path</td>',
            r'Loaded Configuration File</td>',
            r'PHP API</td>',
            r'PHP Extension</td>',
            r'Zend Extension</td>',
            r'Zend Engine</td>',
            r'This program makes use of the Zend Scripting Language Engine',
            r'<table.*?class="h".*?>.*?phpinfo.*?</table>',
            r'<body bgcolor="#ffffff" text="#000000">',
            r'<tr><td class="e">disable_functions</td><td class="v">([^<]+)</td></tr>',
            r'<tr><td class="e">disable_classes</td><td class="v">([^<]+)</td></tr>',
            r'<tr><td class="e">allow_url_fopen</td><td class="v">([^<]+)</td></tr>',
            r'<tr><td class="e">allow_url_include</td><td class="v">([^<]+)</td></tr>'
        ]
        
        for pattern in phpinfo_patterns:
            if re.search(pattern, html_content, re.IGNORECASE):
                detection_score += 10
                indicators.append(pattern[:50])
        
        if 'PHP Version' in html_content and 'System' in html_content:
            detection_score += 30
            indicators.append('PHP Version + System present')
        
        tables_count = html_content.count('<table')
        if tables_count > 5:
            detection_score += 20
            indicators.append(f'Multiple tables ({tables_count})')
        
        if html_content.count('class="e"') > 10 and html_content.count('class="v"') > 10:
            detection_score += 40
            indicators.append('PHP info table structure detected')
        
        return detection_score >= 50, detection_score, indicators
    
    def extract_phpinfo_details(self, html_content):
        extracted = {}
        
        patterns = {
            'version': r'PHP Version\s*([\d\.]+)',
            'system': r'System\s*</td><td[^>]*>([^<]+)',
            'build_date': r'Build Date\s*</td><td[^>]*>([^<]+)',
            'configure_command': r'Configure Command\s*</td><td[^>]*>\'([^\']+)',
            'server_api': r'Server API\s*</td><td[^>]*>([^<]+)',
            'config_path': r'Configuration File \(php\.ini\) Path\s*</td><td[^>]*>([^<]+)',
            'loaded_config': r'Loaded Configuration File\s*</td><td[^>]*>([^<]+)',
            'document_root': r'DOCUMENT_ROOT\s*</td><td[^>]*>([^<]+)',
            'server_ip': r'SERVER_ADDR\s*</td><td[^>]*>([^<]+)',
            'server_software': r'SERVER_SOFTWARE\s*</td><td[^>]*>([^<]+)',
            'script_filename': r'SCRIPT_FILENAME\s*</td><td[^>]*>([^<]+)',
            'remote_addr': r'REMOTE_ADDR\s*</td><td[^>]*>([^<]+)',
            'server_name': r'SERVER_NAME\s*</td><td[^>]*>([^<]+)',
            'request_method': r'REQUEST_METHOD\s*</td><td[^>]*>([^<]+)',
            'request_time': r'REQUEST_TIME\s*</td><td[^>]*>([^<]+)',
            'http_host': r'HTTP_HOST\s*</td><td[^>]*>([^<]+)',
            'http_user_agent': r'HTTP_USER_AGENT\s*</td><td[^>]*>([^<]+)',
            'disable_functions': r'disable_functions\s*</td><td[^>]*>([^<]+)',
            'disable_classes': r'disable_classes\s*</td><td[^>]*>([^<]+)',
            'allow_url_fopen': r'allow_url_fopen\s*</td><td[^>]*>([^<]+)',
            'allow_url_include': r'allow_url_include\s*</td><td[^>]*>([^<]+)',
            'display_errors': r'display_errors\s*</td><td[^>]*>([^<]+)',
            'error_reporting': r'error_reporting\s*</td><td[^>]*>([^<]+)',
            'expose_php': r'expose_php\s*</td><td[^>]*>([^<]+)',
            'max_execution_time': r'max_execution_time\s*</td><td[^>]*>([^<]+)',
            'memory_limit': r'memory_limit\s*</td><td[^>]*>([^<]+)',
            'post_max_size': r'post_max_size\s*</td><td[^>]*>([^<]+)',
            'upload_max_filesize': r'upload_max_filesize\s*</td><td[^>]*>([^<]+)',
            'max_file_uploads': r'max_file_uploads\s*</td><td[^>]*>([^<]+)',
            'open_basedir': r'open_basedir\s*</td><td[^>]*>([^<]+)'
        }
        
        for key, pattern in patterns.items():
            match = re.search(pattern, html_content, re.IGNORECASE)
            if match:
                extracted[key] = match.group(1).strip()
        
        extensions = re.findall(r'<td class="e">([^<]+)\s*</td><td[^>]*>enabled', html_content)
        if extensions:
            extracted['enabled_extensions'] = extensions
        
        variables = re.findall(r'<tr><td class="e">(\$\w+)</td><td class="v">([^<]+)</td></tr>', html_content)
        if variables:
            extracted['environment_variables'] = dict(variables)
        
        return extracted
    
    def analyze_vulnerabilities_advanced(self, extracted_data):
        vulnerabilities = []
        
        if 'version' in extracted_data:
            version = extracted_data['version']
            
            critical_versions = ['4.', '5.0', '5.1', '5.2', '5.3', '5.4', '5.5', '5.6']
            high_versions = ['7.0', '7.1', '7.2', '7.3']
            medium_versions = ['7.4', '8.0']
            
            if any(version.startswith(v) for v in critical_versions):
                vulnerabilities.append(('CRITICAL', f'Extremely outdated PHP version: {version}'))
            elif any(version.startswith(v) for v in high_versions):
                vulnerabilities.append(('HIGH', f'Outdated PHP version: {version}'))
            elif any(version.startswith(v) for v in medium_versions):
                vulnerabilities.append(('MEDIUM', f'Older PHP version: {version}'))
        
        insecure_settings = {
            'display_errors': ['On', '1', 'true'],
            'expose_php': ['On', '1', 'true'],
            'allow_url_fopen': ['On', '1', 'true'],
            'allow_url_include': ['On', '1', 'true'],
            'register_globals': ['On', '1', 'true'],
            'magic_quotes_gpc': ['On', '1', 'true'],
            'safe_mode': ['Off', '0', 'false']
        }
        
        for setting, dangerous_values in insecure_settings.items():
            if setting in extracted_data:
                value = extracted_data[setting]
                if str(value).strip() in dangerous_values:
                    vulnerabilities.append(('HIGH', f'{setting} is dangerously set to: {value}'))
        
        if 'disable_functions' in extracted_data:
            disabled = extracted_data['disable_functions']
            critical_funcs = ['system', 'exec', 'passthru', 'shell_exec', 'proc_open', 'popen']
            enabled_critical = []
            
            for func in critical_funcs:
                if func not in disabled.lower():
                    enabled_critical.append(func)
            
            if enabled_critical:
                vulnerabilities.append(('CRITICAL', f'Dangerous functions enabled: {", ".join(enabled_critical)}'))
        
        if 'document_root' in extracted_data:
            vulnerabilities.append(('MEDIUM', f'Document root path disclosed: {extracted_data["document_root"]}'))
        
        if 'server_ip' in extracted_data:
            vulnerabilities.append(('LOW', f'Server IP address disclosed: {extracted_data["server_ip"]}'))
        
        if 'script_filename' in extracted_data:
            vulnerabilities.append(('MEDIUM', f'Script filename disclosed: {extracted_data["script_filename"]}'))
        
        if 'configure_command' in extracted_data:
            vulnerabilities.append(('MEDIUM', f'Configure command disclosed: {extracted_data["configure_command"][:100]}...'))
        
        if 'loaded_config' in extracted_data:
            vulnerabilities.append(('HIGH', f'php.ini location disclosed: {extracted_data["loaded_config"]}'))
        
        return vulnerabilities
    
    def scan_url(self, url):
        try:
            response = self.session.get(url, timeout=15, allow_redirects=True)
            
            if response.status_code == 200:
                found, score, indicators = self.detect_phpinfo_advanced(response.text, url)
                
                if found:
                    extracted = self.extract_phpinfo_details(response.text)
                    vulnerabilities = self.analyze_vulnerabilities_advanced(extracted)
                    
                    self.found_paths.append({
                        'url': url,
                        'score': score,
                        'indicators': indicators,
                        'extracted': extracted,
                        'vulnerabilities': vulnerabilities
                    })
                    
                    if url not in self.extracted_data:
                        self.extracted_data[url] = extracted
                    
                    self.vulnerabilities.extend(vulnerabilities)
                    
                    return True, score, extracted, vulnerabilities
                
                return False, score, {}, []
            
            return False, 0, {}, []
            
        except Exception as e:
            return False, 0, {}, []
    
    def brute_force_paths(self, base_url):
        paths = self.get_common_paths()
        urls_to_scan = [urljoin(base_url, path) for path in paths]
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(self.scan_url, url): url for url in urls_to_scan}
            
            for future in as_completed(futures):
                url = futures[future]
                try:
                    found, score, extracted, vulns = future.result()
                except Exception:
                    pass
    
    def brute_force_with_parameters(self, base_url):
        paths = self.get_common_paths()[:50]
        params = self.get_common_parameters()
        
        urls_to_scan = []
        for path in paths:
            for param in params:
                urls_to_scan.append(urljoin(base_url, path + param))
        
        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = {executor.submit(self.scan_url, url): url for url in urls_to_scan}
            
            for future in as_completed(futures):
                url = futures[future]
                try:
                    found, score, extracted, vulns = future.result()
                except Exception:
                    pass
    
    def brute_force_file_extensions(self, base_url):
        base_paths = ['/phpinfo', '/info', '/test', '/debug', '/admin']
        extensions = self.get_file_extensions()
        
        urls_to_scan = []
        for path in base_paths:
            for ext in extensions:
                urls_to_scan.append(urljoin(base_url, path + ext))
        
        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = {executor.submit(self.scan_url, url): url for url in urls_to_scan}
            
            for future in as_completed(futures):
                url = futures[future]
                try:
                    found, score, extracted, vulns = future.result()
                except Exception:
                    pass
    
    def check_subdomains(self, domain):
        subdomains = self.get_subdomains()
        
        urls_to_scan = []
        for sub in subdomains:
            urls_to_scan.append(f"http://{sub}.{domain}")
            urls_to_scan.append(f"https://{sub}.{domain}")
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(self.scan_url, url): url for url in urls_to_scan}
            
            for future in as_completed(futures):
                url = futures[future]
                try:
                    found, score, extracted, vulns = future.result()
                except Exception:
                    pass
    
    def check_port_variations(self, domain):
        common_ports = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000]
        
        urls_to_scan = []
        for port in common_ports:
            urls_to_scan.append(f"http://{domain}:{port}")
            urls_to_scan.append(f"https://{domain}:{port}")
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(self.scan_url, url): url for url in urls_to_scan}
            
            for future in as_completed(futures):
                url = futures[future]
                try:
                    found, score, extracted, vulns = future.result()
                except Exception:
                    pass
    
    def check_common_backups(self, base_url):
        backup_patterns = [
            '/phpinfo.php.bak', '/phpinfo.php.backup', '/phpinfo.php.old', '/phpinfo.php.orig',
            '/info.php.bak', '/info.php.backup', '/info.php.old', '/info.php.orig',
            '/test.php.bak', '/test.php.backup', '/test.php.old', '/test.php.orig',
            '/php.php.bak', '/php.php.backup', '/php.php.old', '/php.php.orig',
            '/phpinfo.bak', '/info.bak', '/test.bak', '/php.bak',
            '/phpinfo.php~', '/info.php~', '/test.php~', '/php.php~',
            '/phpinfo.php.save', '/info.php.save', '/test.php.save', '/php.php.save',
            '/phpinfo.php.copy', '/info.php.copy', '/test.php.copy', '/php.php.copy',
            '/phpinfo.php.tmp', '/info.php.tmp', '/test.php.tmp', '/php.php.tmp',
            '/phpinfo.php.temp', '/info.php.temp', '/test.php.temp', '/php.php.temp'
        ]
        
        urls_to_scan = [urljoin(base_url, path) for path in backup_patterns]
        
        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = {executor.submit(self.scan_url, url): url for url in urls_to_scan}
            
            for future in as_completed(futures):
                url = futures[future]
                try:
                    found, score, extracted, vulns = future.result()
                except Exception:
                    pass
    
    def check_common_vulnerable_files(self, base_url):
        vulnerable_files = [
            '/adminer.php', '/phpMyAdmin/phpinfo.php', '/pma/phpinfo.php', 
            '/myadmin/phpinfo.php', '/dbadmin/phpinfo.php', '/sql/phpinfo.php',
            '/mysql/phpinfo.php', '/database/phpinfo.php', '/webmail/phpinfo.php',
            '/mail/phpinfo.php', '/cpanel/phpinfo.php', '/whm/phpinfo.php',
            '/plesk/phpinfo.php', '/directadmin/phpinfo.php', '/hestia/phpinfo.php',
            '/vesta/phpinfo.php', '/virtualmin/phpinfo.php', '/webmin/phpinfo.php',
            '/roundcube/phpinfo.php', '/squirrelmail/phpinfo.php', '/horde/phpinfo.php',
            '/wordpress/wp-admin/phpinfo.php', '/joomla/administrator/phpinfo.php',
            '/drupal/admin/phpinfo.php', '/magento/admin/phpinfo.php',
            '/prestashop/admin/phpinfo.php', '/opencart/admin/phpinfo.php',
            '/laravel/admin/phpinfo.php', '/symfony/admin/phpinfo.php',
            '/yii/admin/phpinfo.php', '/cakephp/admin/phpinfo.php',
            '/codeigniter/admin/phpinfo.php', '/zend/admin/phpinfo.php'
        ]
        
        urls_to_scan = [urljoin(base_url, path) for path in vulnerable_files]
        
        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = {executor.submit(self.scan_url, url): url for url in urls_to_scan}
            
            for future in as_completed(futures):
                url = futures[future]
                try:
                    found, score, extracted, vulns = future.result()
                except Exception:
                    pass
    
    def scan_comprehensive(self, target):
        print(f"Starting comprehensive scan of: {target}")
        print("=" * 80)
        
        parsed = urlparse(target if target.startswith('http') else f'http://{target}')
        domain = parsed.netloc if parsed.netloc else target.split('/')[0]
        base_url = f"{parsed.scheme}://{domain}" if parsed.scheme else f"http://{domain}"
        
        print("[1/8] Scanning main URL...")
        main_found, main_score, main_extracted, main_vulns = self.scan_url(base_url)
        
        print("[2/8] Brute forcing common paths...")
        self.brute_force_paths(base_url)
        
        print("[3/8] Testing with parameters...")
        self.brute_force_with_parameters(base_url)
        
        print("[4/8] Testing file extensions...")
        self.brute_force_file_extensions(base_url)
        
        print("[5/8] Checking backup files...")
        self.check_common_backups(base_url)
        
        print("[6/8] Scanning vulnerable admin files...")
        self.check_common_vulnerable_files(base_url)
        
        print("[7/8] Testing subdomains...")
        self.check_subdomains(domain)
        
        print("[8/8] Checking alternate ports...")
        self.check_port_variations(domain)
        
        return self.generate_report(base_url)
    
    def generate_report(self, base_url):
        report_lines = []
        report_lines.append("=" * 80)
        report_lines.append(f"COMPREHENSIVE PHP INFO SCAN REPORT")
        report_lines.append(f"Target: {base_url}")
        report_lines.append(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append("=" * 80)
        
        if not self.found_paths:
            report_lines.append("\n[RESULT] No phpinfo files found.")
            report_lines.append("[STATUS] Target appears secure from phpinfo disclosure.")
            return "\n".join(report_lines)
        
        report_lines.append(f"\n[RESULT] Found {len(self.found_paths)} phpinfo files!")
        report_lines.append("[STATUS] CRITICAL SECURITY ISSUE DETECTED!")
        report_lines.append("=" * 80)
        
        for i, found in enumerate(self.found_paths, 1):
            report_lines.append(f"\n[{i}] PHPINFO FILE FOUND:")
            report_lines.append(f"    URL: {found['url']}")
            report_lines.append(f"    Detection Score: {found['score']}/100")
            
            if found['extracted']:
                report_lines.append(f"    PHP Version: {found['extracted'].get('version', 'Unknown')}")
                report_lines.append(f"    System: {found['extracted'].get('system', 'Unknown')}")
            
            if found['vulnerabilities']:
                report_lines.append("    Vulnerabilities:")
                for severity, desc in found['vulnerabilities']:
                    report_lines.append(f"      [{severity}] {desc}")
        
        if self.vulnerabilities:
            report_lines.append("\n" + "=" * 80)
            report_lines.append("TOTAL VULNERABILITIES FOUND:")
            
            critical = sum(1 for s, _ in self.vulnerabilities if s == 'CRITICAL')
            high = sum(1 for s, _ in self.vulnerabilities if s == 'HIGH')
            medium = sum(1 for s, _ in self.vulnerabilities if s == 'MEDIUM')
            low = sum(1 for s, _ in self.vulnerabilities if s == 'LOW')
            
            report_lines.append(f"    CRITICAL: {critical}")
            report_lines.append(f"    HIGH: {high}")
            report_lines.append(f"    MEDIUM: {medium}")
            report_lines.append(f"    LOW: {low}")
            
        
        report_lines.append("\n" + "=" * 80)
        report_lines.append("SCAN COMPLETE")
        report_lines.append("=" * 80)
        
        return "\n".join(report_lines)

def main():
    if len(sys.argv) < 2:
        url = input("Enter target URL or domain: ").strip()
    else:
        url = sys.argv[1]
    
    if not url:
        print("No target specified.")
        sys.exit(1)
    
    scanner = PHPInfoUltimateScanner()
    report = scanner.scan_comprehensive(url)
    
    print(report)
    
    if scanner.found_paths:
        input("\nPress Enter to continue...")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())