import socket
import threading
import queue
import time

class IPPortScanner:
    def __init__(self, ip, ports=None, threads=200, timeout=0.8):
        self.ip = ip
        self.ports = ports if ports is not None else list(range(1, 1025))
        self.threads_count = threads
        self.timeout = timeout
        self.result = {}
        self.q = queue.Queue()
        self.banner_grab = True

    def scan_port(self, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        try:
            r = s.connect_ex((self.ip, port))
            if r == 0:
                self.result[port] = {'state': 'open'}
                if self.banner_grab:
                    try:
                        s.sendall(b'Hello\r\n')
                        banner = s.recv(256)
                        self.result[port]['banner'] = banner.decode(errors='replace').strip()
                    except Exception:
                        self.result[port]['banner'] = ''
                s.close()
            else:
                self.result[port] = {'state': 'closed'}
        except Exception:
            self.result[port] = {'state': 'error'}
            s.close()

    def worker(self):
        while True:
            try:
                port = self.q.get(timeout=0.5)
            except queue.Empty:
                break
            self.scan_port(port)
            self.q.task_done()

    def run_scan(self):
        for p in self.ports:
            self.q.put(p)
        threads = []
        for _ in range(min(self.threads_count, len(self.ports))):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
            threads.append(t)
        self.q.join()
        for t in threads:
            t.join(timeout=1)
        return {p: inf for p, inf in self.result.items() if inf['state'] == 'open'}

    def exploit_port(self, port):
        vuln_payloads = {21: b'USER anonymous\r\n', 22: b'\r\n', 23: b'\r\n', 80: b'GET / HTTP/1.0\r\n\r\n', 443: b'HEAD / HTTP/1.0\r\n\r\n'}
        if port not in vuln_payloads:
            return
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.5)
            s.connect((self.ip, port))
            s.sendall(vuln_payloads[port])
            resp = s.recv(512)
            self.result[port]['exploit'] = resp.decode(errors='replace').strip()
            s.close()
        except Exception:
            self.result[port]['exploit'] = ''

    def run_exploit(self, target_ports=None):
        targets = target_ports if target_ports else [p for p, v in self.result.items() if v.get('state') == 'open']
        for port in targets:
            self.exploit_port(port)

    def pretty_print(self):
        open_ports = sorted([p for p,v in self.result.items() if v.get('state') == 'open'])
        print(f'Scan sur {self.ip} ports {self.ports[0]}-{self.ports[-1]} :')
        for port in open_ports:
            info = self.result[port]
            out = f'Port {port:<5} [OUVERT]'
            if 'banner' in info and info['banner']:
                out += f' | Banner: {info["banner"][:40]}'
            if 'exploit' in info and info['exploit']:
                out += f' | Exploit: {info["exploit"][:40]}'
            print(out)
        if not open_ports:
            print('Aucun port ouvert trouvé.')

def main():
    ip = input("Entrez l'adresse IP à scanner : ").strip()
    ports = list(range(1, 1025))
    scanner = IPPortScanner(ip, ports)
    t0 = time.time()
    print("Scan en cours...")
    open_ports = scanner.run_scan()
    scanner.run_exploit()
    scanner.pretty_print()
    print("Fini en %.2fs" % (time.time()-t0))
    input("Continuer...")

if __name__ == '__main__':
    main()
