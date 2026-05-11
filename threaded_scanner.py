"""
threaded_scanner.py
Sequential and threaded TCP port scanner with banner grabbing.
WARNING: Only use on hosts you own or have explicit written permission to scan.
Unauthorized port scanning is illegal in most jurisdictions.
"""

import socket
import queue
import time
import logging
import re
import argparse
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

MAX_WORKERS  = 50
MAX_PORT     = 65535
MIN_PORT     = 1
BANNER_CHARS = re.compile(r"[^\x20-\x7E]")  # printable ASCII only

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

HOSTNAME_PATTERN = re.compile(
    r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
    r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
)
IP_PATTERN = re.compile(
    r'^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$'
)


def _validate_target(target: str) -> str:
    """Validate target is a safe hostname or IPv4 — return resolved IP."""
    if not isinstance(target, str) or not target.strip():
        raise ValueError("Target must be a non-empty string.")
    if not (IP_PATTERN.match(target) or HOSTNAME_PATTERN.match(target)):
        raise ValueError("Invalid target — must be a valid IP or hostname.")
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        raise ValueError("Could not resolve target.")


def _validate_port_range(start: int, end: int) -> None:
    """Reject out-of-range or inverted port ranges."""
    if not all(isinstance(p, int) for p in (start, end)):
        raise ValueError("Port values must be integers.")
    if not (MIN_PORT <= start <= MAX_PORT and MIN_PORT <= end <= MAX_PORT):
        raise ValueError(f"Ports must be between {MIN_PORT} and {MAX_PORT}.")
    if start > end:
        raise ValueError("Start port must be less than or equal to end port.")


def _sanitise_banner(raw: bytes) -> str | None:
    """Strip non-printable bytes from banner — prevents log injection."""
    if not raw:
        return None
    try:
        decoded = raw.decode("utf-8", errors="ignore").strip()
        return BANNER_CHARS.sub("", decoded)[:256]  # cap at 256 chars
    except Exception:
        return None


@dataclass
class ScanResult:
    port: int
    is_open: bool
    banner: str | None
    scan_time: float


class PortScanner:

    def __init__(self, target: str, timeout: float = 0.5):
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("Timeout must be a positive number.")
        self.timeout = timeout
        self.target  = _validate_target(target)

    def scan_port(self, port: int) -> tuple:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                result = s.connect_ex((self.target, port))
                if result == 0:
                    banner   = self.grab_banner(port)
                    is_open  = True
                else:
                    banner   = None
                    is_open  = False
            return (port, is_open, banner)
        except OSError:
            return (port, False, None)

    def grab_banner(self, port: int) -> str | None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((self.target, port))
                raw = s.recv(1024)
                return _sanitise_banner(raw)
        except Exception:
            return None

    def scan_range(self, start: int, end: int) -> list:
        _validate_port_range(start, end)
        open_ports = []
        for port in range(start, end + 1):
            result = self.scan_port(port)
            if result[1]:
                open_ports.append(result)
        return open_ports

    def __str__(self) -> str:
        return f"PortScanner | target: {self.target} | timeout: {self.timeout}"


class ThreadedPortScanner(PortScanner):

    def __init__(self, target: str, max_workers: int = 20, timeout: float = 0.5):
        super().__init__(target, timeout)
        if not isinstance(max_workers, int) or not (1 <= max_workers <= MAX_WORKERS):
            raise ValueError(f"max_workers must be between 1 and {MAX_WORKERS}.")
        self.max_workers = max_workers
        self.queue       = queue.Queue()

    def scan_port(self, port: int) -> ScanResult:
        start            = time.perf_counter()
        port, is_open, banner = super().scan_port(port)
        elapsed          = time.perf_counter() - start
        result           = ScanResult(port, is_open, banner, elapsed)
        self.queue.put(result)
        return result

    def scan_range(self, start: int, end: int) -> list[ScanResult]:
        _validate_port_range(start, end)
        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            results = list(ex.map(self.scan_port, range(start, end + 1)))
        return results

    def scan_common(self) -> list[ScanResult]:
        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            results = list(ex.map(self.scan_port, COMMON_PORTS))
        return results


def compare_speed(target: str = "localhost") -> None:
    """Benchmark sequential vs threaded scan — call explicitly, not automatically."""
    sequential = PortScanner(target, timeout=0.1)
    threaded   = ThreadedPortScanner(target, timeout=0.1)

    start    = time.perf_counter()
    sequential.scan_range(1, 100)
    seq_time = time.perf_counter() - start

    start    = time.perf_counter()
    threaded.scan_range(1, 100)
    thr_time = time.perf_counter() - start

    log.info(f"Sequential: {seq_time:.3f}s | Threaded: {thr_time:.3f}s | Speedup: {seq_time/thr_time:.1f}x")


def main() -> None:
    parser = argparse.ArgumentParser(description="Port Scanner")
    parser.add_argument("--target",        required=True, help="IP or hostname to scan")
    parser.add_argument("--start",         type=int,      help="Start of port range")
    parser.add_argument("--end",           type=int,      help="End of port range")
    parser.add_argument("--workers",       type=int,      default=20, help=f"Thread workers (max {MAX_WORKERS})")
    parser.add_argument("--compare-speed", action="store_true",       help="Benchmark sequential vs threaded")
    args = parser.parse_args()

    try:
        if args.compare_speed:
            compare_speed(args.target)

        scanner = PortScanner(args.target)
        log.info(scanner)

        if args.start and args.end:
            open_ports = scanner.scan_range(args.start, args.end)
            print(f"{'PORT':<10}{'STATUS':<10}{'BANNER'}")
            print(f"{'-'*40}")
            for port, is_open, banner in open_ports:
                status = "open" if is_open else "closed"
                print(f"{port:<10}{status:<10}{banner or 'N/A'}")
        else:
            log.info(f"Scanning common ports on {args.target}...")
            results    = ThreadedPortScanner(args.target, max_workers=args.workers).scan_common()
            open_ports = [r for r in results if r.is_open]
            for r in open_ports:
                print(f"port {r.port:<6} banner: {r.banner or 'N/A':<30} scan_time: {r.scan_time:.3f}s")

    except ValueError as e:
        log.error(f"Configuration error: {e}")
    except Exception:
        log.error("Unexpected error — check configuration.")


if __name__ == "__main__":
    main()