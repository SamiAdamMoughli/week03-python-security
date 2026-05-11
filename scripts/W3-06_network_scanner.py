"""
network_scanner.py
CIDR network ping sweep and port scanner.
WARNING: Only use on networks you own or have explicit written permission to scan.
Unauthorized scanning is illegal in most jurisdictions.
Tested on: localhost, home lab (192.168.x.x/24)
"""

import ipaddress
import argparse
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from subprocess_tool import SafeShell
from threaded_scanner import ThreadedPortScanner

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

MAX_WORKERS = 20      # hard cap — never unbounded
DEFAULT_PORTS = [22, 80, 443, 8080]


class NetworkScanner:

    def __init__(self, network: str, max_workers: int = 10):
        self.shell = SafeShell()
        try:
            self.network = ipaddress.ip_network(network, strict=False)
        except ValueError:
            # don't echo raw input back — may contain garbage
            raise ValueError("Invalid CIDR format. Example: 192.168.1.0/24")
        if not isinstance(max_workers, int) or not (1 <= max_workers <= MAX_WORKERS):
            raise ValueError(f"max_workers must be between 1 and {MAX_WORKERS}.")
        self.max_workers = max_workers

    def ping_host(self, ip: str) -> bool:
        return self.shell.ping(ip)

    def sweep(self) -> list[str]:
        """Ping all hosts in the network; return list of live IPs."""
        ips = [str(ip) for ip in self.network.hosts()]
        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            results = list(ex.map(self.ping_host, ips))
        return [ip for ip, alive in zip(ips, results) if alive]

    def full_scan(self, ports: list = None) -> dict:
        """Sweep then port-scan each live host; return {ip: [open_ports]}."""
        if ports is None:
            ports = DEFAULT_PORTS
        if not isinstance(ports, list) or not all(isinstance(p, int) and 1 <= p <= 65535 for p in ports):
            raise ValueError("ports must be a list of integers between 1 and 65535.")

        live_hosts = self.sweep()
        results = {}
        for host in live_hosts:
            scanner = ThreadedPortScanner(host)
            with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
                scan_results = list(ex.map(scanner.scan_port, ports))
            results[host] = [r.port for r in scan_results if r.is_open]
        return results


def compare_speed(network: str) -> None:
    """Benchmark sweep at 1 vs max workers — call explicitly, not automatically."""
    log.info("Running speed comparison...")
    slow = NetworkScanner(network, max_workers=1)
    start = time.perf_counter()
    slow.sweep()
    slow_time = time.perf_counter() - start

    fast = NetworkScanner(network, max_workers=MAX_WORKERS)
    start = time.perf_counter()
    fast.sweep()
    fast_time = time.perf_counter() - start

    if fast_time > 0:
        log.info(f"1 worker: {slow_time:.3f}s | {MAX_WORKERS} workers: {fast_time:.3f}s | speedup: {slow_time/fast_time:.1f}x")


def main() -> None:
    parser = argparse.ArgumentParser(description="Network Scanner")
    parser.add_argument("--network", required=True, help="CIDR range e.g. 192.168.1.0/24")
    parser.add_argument("--sweep", action="store_true", help="Ping sweep only")
    parser.add_argument("--full-scan", action="store_true", help="Sweep + port scan")
    parser.add_argument("--compare-speed", action="store_true", help="Benchmark sweep workers")
    parser.add_argument("--workers", type=int, default=10, help=f"Thread workers (max {MAX_WORKERS})")
    args = parser.parse_args()

    try:
        scanner = NetworkScanner(args.network, max_workers=args.workers)
    except ValueError as e:
        log.error(f"Configuration error: {e}")
        return

    if args.compare_speed:
        compare_speed(args.network)

    if args.sweep:
        results = scanner.sweep()
        log.info(f"{len(results)} live hosts found.")
        for ip in results:
            print(f"  {ip}")

    elif args.full_scan:
        results = scanner.full_scan()
        print(f"\n{'IP':<20} {'OPEN PORTS'}")
        print("-" * 40)
        for host, ports in results.items():
            port_str = ", ".join(str(p) for p in ports) if ports else "none"
            print(f"{host:<20} {port_str}")


if __name__ == "__main__":
    main()
