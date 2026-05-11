import threading
from dataclasses import dataclass
import socket
import argparse
import queue
from concurrent.futures import ThreadPoolExecutor
import time

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8080, 8443, 8888, 9090, 9200, 27017,
    20, 69, 79, 88, 119, 123, 137, 138, 161, 162, 179, 194, 389, 427,
    465, 500, 514, 515, 543, 544, 548, 554, 587, 631, 636, 646, 873,
    990, 992, 994, 1080, 1194, 1433, 1434, 1521, 1701, 1812, 1813,
    2049, 2082, 2083, 2181, 2222, 2375, 2376, 2483, 2484, 3000, 3001,
    3128, 3268, 3269, 3307, 3690, 4000, 4040, 4444, 4500, 4848, 5000,
    5001, 5432, 5433, 5555, 5601, 5672, 5900, 5984, 6000, 6379, 6443,
    6514, 7000, 7001, 7080, 7443, 7474, 8000, 8001, 8008, 8009, 8069,
    8081, 8086, 8087, 8161, 8500, 8983, 9000, 9001, 9042, 9092, 9300,
    9418, 9999, 10000, 11211, 15672, 16379, 27018, 27019, 28017, 50000
]

class PortScanner:

    def __init__(self, target, timeout=0.5):
        self.timeout = timeout
        try:
            self.target = socket.gethostbyname(target)
        except socket.gaierror:
            raise ValueError(f"Invalid target: {target} is not a valid IP or hostname")

    def scan_port(self, port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(self.timeout)
            result = s.connect_ex((self.target, port))
            if result == 0:
                banner = self.grab_banner(port)
                is_open = True
            else:
                banner = None
                is_open = False
        return (port, is_open, banner)

    def grab_banner(self, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((self.target, port))
                banner_data = s.recv(1024)
                return banner_data.decode().strip()
        except Exception:
            return None

    def scan_range(self, start, end):
        open_ports = []

        for port in range(start, end + 1):
            result = self.scan_port(port)
            is_open = result[1]
            if is_open:
                open_ports.append(result)

        return open_ports

    def __str__(self):
        return f"PortScanner | target: {self.target} | timeout: {self.timeout}"

@dataclass
class ScanResult:
    port: int
    is_open: bool
    banner: str | None
    scan_time: float

class ThreadedPortScanner(PortScanner):
    def __init__(self, target, max_workers=100, timeout=0.5):
        super().__init__(target, timeout)
        self.max_workers = max_workers
        self.queue = queue.Queue()



    def scan_port(self, port) -> ScanResult:
        start = time.perf_counter()
        port, is_open, banner = super().scan_port(port)
        elapsed_time = time.perf_counter() - start
        result = ScanResult(port, is_open, banner, elapsed_time)
        self.queue.put(result)
        return result


    def scan_range(self, start, end) -> list[ScanResult]:
        with ThreadPoolExecutor(self.max_workers) as ex:
            results = list(ex.map(self.scan_port, range(start, end + 1)))
        return results

    def scan_common(self) -> list[ScanResult]:
        with ThreadPoolExecutor(self.max_workers) as ex:
            results = list(ex.map(self.scan_port, COMMON_PORTS))
        return results

def compare_speed(target="localhost"):
    sequential = PortScanner(target, timeout=0.1)
    threaded = ThreadedPortScanner(target, timeout=0.1)

    start = time.perf_counter()
    sequential.scan_range(1, 100)
    seq_time = time.perf_counter() - start

    start = time.perf_counter()
    threaded.scan_range(1, 100)
    thr_time = time.perf_counter() - start

    print(f"sequential: {seq_time:.3f}s  threaded: {thr_time:.3f}s  speedup: {seq_time/thr_time:.1f}x")

def main():
    parser = argparse.ArgumentParser(description="PortScanner")
    parser.add_argument("--target",required=True, help="One IP addresse to look up")
    parser.add_argument("--start", type=int, help="Start of port range")
    parser.add_argument("--end", type=int, help="End of port range")
    args = parser.parse_args()

    compare_speed(args.target)

    scanner = PortScanner(args.target)
    print(scanner)

    if args.start and args.end:
        open_ports = scanner.scan_range(args.start, args.end)
        print(f"{'PORT':<10}{'STATUS':<10}{'BANNER'}")
        print(f"{'-'*10}{'-'*10}{'-'*20}")
        for port, is_open, banner in open_ports:
            status = "open" if is_open else "closed"
            print(f"{port:<10}{status:<10}{banner or 'N/A'}")
    else:
        print(f"\nscanning common ports on {args.target}...")
        results = ThreadedPortScanner(args.target).scan_common()
        open_ports = [r for r in results if r.is_open]
        for r in open_ports:
            print(f"port {r.port} open  banner: {r.banner or 'N/A'}  scan_time: {r.scan_time:.3f}s")

if __name__ == "__main__":
    main()