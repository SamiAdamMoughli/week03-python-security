"""
security_toolkit.py
Unified security toolkit CLI — educational use only.
All operations require explicit authorization on target systems.
Unauthorized scanning, cracking, or interception is illegal.

Usage: python security_toolkit.py <command> --help
Requires: sudo for scan/sweep (raw sockets)
Config:   .env file with DEMO_PASSWORD set
"""

import argparse
import logging
import os
import sys
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


class SecureLogger:
    """Structured logger — never logs sensitive values."""

    def __init__(self, name: str):
        self._log = logging.getLogger(name)

    def info(self, msg: str)    -> None: self._log.info(msg)
    def warning(self, msg: str) -> None: self._log.warning(msg)
    def error(self, msg: str)   -> None: self._log.error(msg)


log = SecureLogger(__name__)

ETHICAL_WARNING = """
=============================================================
        AUTHORIZED USE ONLY — EDUCATIONAL TOOL
 Only use against systems you own or have permission to scan
      Unauthorized scanning or cracking is illegal
=============================================================
"""

def cmd_integrity(args: argparse.Namespace) -> None:
    from file_integrity_checker import FileIntegrityChecker
    checker = FileIntegrityChecker()

    if args.baseline:
        log.info(f"Creating baseline for: {args.baseline}")
        checker.create_baseline(args.baseline, args.output or "baseline.json")
        log.info("Baseline saved.")

    elif args.verify:
        if not args.baseline_file:
            log.error("--baseline-file required with --verify")
            sys.exit(1)
        log.info(f"Verifying: {args.verify}")
        report = checker.verify(args.verify, args.baseline_file)
        if report:
            print(report)
        else:
            log.error("Verification failed.")


def cmd_scan(args: argparse.Namespace) -> None:
    from threaded_scanner import ThreadedPortScanner
    log.info(f"Scanning {args.host}...")
    try:
        scanner = ThreadedPortScanner(args.host, max_workers=args.workers)
        results = scanner.scan_common()
        open_ports = [r for r in results if r.is_open]
        if not open_ports:
            log.info("No open ports found.")
            return
        print(f"\n{'PORT':<10}{'BANNER'}")
        print("-" * 40)
        for r in open_ports:
            print(f"{r.port:<10}{r.banner or 'N/A'}")
    except ValueError as e:
        log.error(f"Scan error: {e}")


def cmd_sweep(args: argparse.Namespace) -> None:
    from network_scanner import NetworkScanner
    log.info(f"Sweeping network: {args.network}")
    try:
        scanner = NetworkScanner(args.network, max_workers=args.workers)
        live = scanner.sweep()
        log.info(f"{len(live)} live hosts found.")
        for ip in live:
            print(f"  {ip}")
    except ValueError as e:
        log.error(f"Sweep error: {e}")


def cmd_hash(args: argparse.Namespace) -> None:
    from file_integrity_checker import FileHasher
    log.info(f"Hashing: {args.file}")
    try:
        hasher = FileHasher()
        result = hasher.hash_file(args.file, algorithm="sha256")
        if result:
            print(f"SHA-256: {result}")
        else:
            log.error("Hashing failed.")
    except Exception:
        log.error("Could not hash file.")


def cmd_crack(args: argparse.Namespace) -> None:
    from brute_force_demo import HashCracker
    wordlist = args.wordlist or "wordlist.txt"
    log.info(f"Attempting crack on hash: {args.hash[:8]}...")
    try:
        cracker = HashCracker(algorithm=args.algorithm)
        result  = cracker.crack(args.hash, wordlist)
        if result:
            log.info(f"Cracked — length {len(result)} chars.")
        else:
            log.info("Hash not found in wordlist.")
    except ValueError as e:
        log.error(f"Crack error: {e}")


def cmd_audit(args: argparse.Namespace) -> None:
    from file_integrity_checker import FileHasher
    from pathlib import Path
    log.info(f"Auditing directory: {args.dir}")
    try:
        hasher  = FileHasher()
        results = hasher.hash_directory(args.dir)
        if not results:
            log.error("Audit failed or directory empty.")
            return
        total    = len(results)
        failed   = sum(1 for v in results.values() if v is None)
        ok       = total - failed
        print(f"\nDirectory audit: {args.dir}")
        print(f"  Total files : {total}")
        print(f"  Hashed OK   : {ok}")
        print(f"  Failed      : {failed}")
    except Exception:
        log.error("Audit failed.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="security_toolkit",
        description="Unified security toolkit — authorized use only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", metavar="command")
    sub.required = True

    # integrity
    p_int = sub.add_parser("integrity", help="File integrity baseline and verification")
    p_int.add_argument("--baseline",      metavar="DIR",  help="Create baseline from directory")
    p_int.add_argument("--verify",        metavar="DIR",  help="Verify directory against baseline")
    p_int.add_argument("--output",        metavar="FILE", help="Output file for baseline (default: baseline.json)")
    p_int.add_argument("--baseline-file", metavar="FILE", help="Baseline JSON to verify against")

    # scan
    p_scan = sub.add_parser("scan", help="Port scan a host")
    p_scan.add_argument("--host",    required=True, metavar="IP",   help="Target IP or hostname")
    p_scan.add_argument("--workers", type=int, default=20,          help="Thread workers (default: 20)")

    # sweep
    p_sweep = sub.add_parser("sweep", help="Ping sweep a network")
    p_sweep.add_argument("--network", required=True, metavar="CIDR", help="Target network e.g. 192.168.1.0/24")
    p_sweep.add_argument("--workers", type=int, default=10,           help="Thread workers (default: 10)")

    # hash
    p_hash = sub.add_parser("hash", help="Hash a file with SHA-256")
    p_hash.add_argument("--file", required=True, metavar="PATH", help="File to hash")

    # crack
    p_crack = sub.add_parser("crack", help="Attempt wordlist crack against a hash (demo)")
    p_crack.add_argument("--hash",      required=True, metavar="HASH",     help="Target hash string")
    p_crack.add_argument("--wordlist",  metavar="FILE",                    help="Wordlist path (default: wordlist.txt)")
    p_crack.add_argument("--algorithm", default="md5", choices=["md5", "sha1"], help="Hash algorithm")

    # audit
    p_audit = sub.add_parser("audit", help="Audit and hash all files in a directory")
    p_audit.add_argument("--dir", required=True, metavar="DIR", help="Directory to audit")

    return parser


def main() -> None:
    print(ETHICAL_WARNING)

    parser = build_parser()
    args   = parser.parse_args()

    dispatch = {
        "integrity": cmd_integrity,
        "scan":      cmd_scan,
        "sweep":     cmd_sweep,
        "hash":      cmd_hash,
        "crack":     cmd_crack,
        "audit":     cmd_audit,
    }

    handler = dispatch.get(args.command)
    if handler:
        handler(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()