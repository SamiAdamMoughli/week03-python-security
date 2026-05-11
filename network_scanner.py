import ipaddress
from subprocess_tool import SafeShell
from concurrent.futures import ThreadPoolExecutor
from threaded_scanner import ThreadedPortScanner
import argparse
import time

# network_scanner.py
# WARNING: Only use on networks you own or have explicit permission to scan.
# Unauthorized network scanning is illegal in most jurisdictions.
# Tested on: localhost, home network (192.168.0.0/24)

class NetworkScanner:

    def __init__(self, network: str):
        self.shell = SafeShell()
        try:
            self.network = ipaddress.ip_network(network, strict=False)
        except ValueError as e:
            raise ValueError(f"Invalid CIDR format: {network}") from e

    def ping_host(self, ip: str) -> bool:
        return self.shell.ping(ip)

    def sweep(self, max_workers=50) -> list[str]:
        with ThreadPoolExecutor(max_workers) as ex:
            ips = [str(ip) for ip in self.network]
            results = list(ex.map(self.ping_host, ips))
            return [ip for ip, alive in zip(ips, results) if alive]

    def get_live_hosts(self) -> list[str]:
        return self.sweep()

    def full_scan(self, ports=[22, 80, 443, 8080]) -> dict:
        live_hosts = self.get_live_hosts()
        results = {}
        for host in live_hosts:
            scanner = ThreadedPortScanner(host)
            with ThreadPoolExecutor() as ex:
                scan_results = list(ex.map(scanner.scan_port, ports))
            results[host] = [r.port for r in scan_results if r.is_open]
        return results

def compare_speed(network):
    scanner = NetworkScanner(network)

    start = time.perf_counter()
    scanner.sweep(max_workers=1)
    slow_time = time.perf_counter() - start

    start = time.perf_counter()
    scanner.sweep(max_workers=50)
    fast_time = time.perf_counter() - start

    print(f"1 worker: {slow_time:.3f}s  50 workers: {fast_time:.3f}s  speedup: {slow_time/fast_time:.1f}x")

def main():
    parser = argparse.ArgumentParser(description="NetworkScanner")
    parser.add_argument("--network", required=True, help="CDIR network e.g. 192.168.1.0/24")
    parser.add_argument("--sweep", action="store_true", help="Ping sweep")
    parser.add_argument("--full-scan", action="store_true", help="Full port scan")
    args = parser.parse_args()

    scanner = NetworkScanner(args.network)
    compare_speed(args.network)

    if args.sweep:
        results = scanner.sweep()
        print(f"\n{len(results)} live hosts found:")
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



