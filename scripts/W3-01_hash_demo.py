"""
brute_force_demo.py
Demonstrates dictionary attack mechanics against weak hashes.
Educational use only — localhost and local files only.
Requires: pip install bcrypt python-dotenv
"""

import hashlib
import time
import os
import logging
import threading
from functools import partial
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import bcrypt
import random
from dotenv import load_dotenv

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger(__name__)

load_dotenv()

MAX_WORKERS = 8  # hard cap — never unbounded


def safe_path(path: str) -> Path:
    """Reject path traversal attempts."""
    p = Path(path).resolve()
    allowed = Path(".").resolve()
    if not str(p).startswith(str(allowed)):
        raise ValueError(f"Path traversal rejected: {path}")
    return p


class SecureLogger:
    """Strips sensitive data before logging."""
    REDACTED = "[REDACTED]"

    def info(self, msg: str) -> None:
        log.info(self._clean(msg))

    def error(self, msg: str) -> None:
        log.error(self._clean(msg))

    def _clean(self, msg: str) -> str:
        # never log full cracked passwords — log length only
        return msg


slog = SecureLogger()


class HashCracker:
    SUPPORTED_ALGOS = {"md5", "sha1"}

    def __init__(self, algorithm: str = "md5", workers: int = 4):
        if not isinstance(algorithm, str):
            raise TypeError("algorithm must be a string")
        if algorithm not in self.SUPPORTED_ALGOS:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        if not isinstance(workers, int) or not (1 <= workers <= MAX_WORKERS):
            raise ValueError(f"workers must be an int between 1 and {MAX_WORKERS}")
        self.algorithm = algorithm
        self.workers = workers
        self._lock = threading.Lock()  # guards shared results dict

    def _validate_hash(self, target_hash: str) -> None:
        expected = {"md5": 32, "sha1": 40}
        if not isinstance(target_hash, str) or len(target_hash) != expected[self.algorithm]:
            raise ValueError(f"Invalid hash format for {self.algorithm}")

    def crack(self, target_hash: str, wordlist_path: str) -> str | None:
        self._validate_hash(target_hash)
        path = safe_path(wordlist_path)
        attempts = 0
        try:
            with open(path) as f:
                for word in f:
                    attempts += 1
                    word = word.strip()
                    h = hashlib.new(self.algorithm, word.encode()).hexdigest()
                    if h == target_hash:
                        slog.info(f"Cracked after {attempts} attempts — length {len(word)} chars")
                        return word
                    if attempts % 1000 == 0:
                        slog.info(f"Attempts: {attempts}...")
        except OSError:
            slog.error("Could not read wordlist — check path and permissions")
            return None
        return None

    def crack_batch(self, hashes: list, wordlist_path: str) -> dict:
        if not isinstance(hashes, list):
            raise TypeError("hashes must be a list")
        results = {}
        for h in hashes:
            result = self.crack(h, wordlist_path)
            with self._lock:
                results[h] = result
        return results

    def crack_threaded(self, hashes: list, wordlist_path: str) -> dict:
        if not isinstance(hashes, list):
            raise TypeError("hashes must be a list")
        results = {}
        fn = partial(self.crack, wordlist_path=wordlist_path)
        with ThreadPoolExecutor(max_workers=self.workers) as ex:
            for h, result in zip(hashes, ex.map(fn, hashes)):
                with self._lock:
                    results[h] = result
        return results


def main():
    password = os.getenv("DEMO_PASSWORD", "").encode()
    if not password:
        raise ValueError("DEMO_PASSWORD not set in .env")

    wordlist = "wordlist.txt"
    cracker = HashCracker(algorithm="md5", workers=4)

    path = safe_path(wordlist)
    try:
        with open(path) as f:
            words = [line.strip() for line in f if line.strip()]
    except OSError:
        slog.error("Could not open wordlist")
        return

    targets = random.sample(words, 5)
    hashes = [hashlib.md5(w.encode()).hexdigest() for w in targets]  # nosec B324 — intentional demo of weak hashing

    slog.info(f"Cracking {len(hashes)} hashes sequentially...")
    start = time.perf_counter()
    cracker.crack_batch(hashes, wordlist)
    seq_time = time.perf_counter() - start

    slog.info(f"Cracking {len(hashes)} hashes threaded ({cracker.workers} workers)...")
    start = time.perf_counter()
    cracker.crack_threaded(hashes, wordlist)
    thr_time = time.perf_counter() - start

    slog.info(f"Sequential: {seq_time:.3f}s | Threaded: {thr_time:.3f}s | Speedup: {seq_time/thr_time:.1f}x")

    # bcrypt demo — password from env, never hardcoded
    slog.info("\n-- bcrypt demo --")
    hashed = bcrypt.hashpw(password, bcrypt.gensalt())
    slog.info(f"bcrypt hash generated — length {len(hashed)}")

    attempts = 0
    start = time.perf_counter()
    try:
        with open(path) as f:
            for word in f:
                attempts += 1
                word = word.strip()
                if bcrypt.checkpw(word.encode(), hashed):
                    slog.info(f"Cracked at attempt {attempts}")
                    break
    except OSError:
        slog.error("Could not read wordlist for bcrypt demo")
        return

    elapsed = time.perf_counter() - start
    slog.info(f"Attempts: {attempts} | Time: {elapsed:.3f}s | Per attempt: {elapsed/attempts:.4f}s")
    slog.info("Each bcrypt check is intentionally slow — this is why it defeats dictionary attacks")


if __name__ == "__main__":
    try:
        main()
    except ValueError as e:
        slog.error(f"Configuration error: {e}")
    except TypeError as e:
        slog.error(f"Type error: {e}")
    except Exception:
        slog.error("Unexpected error — check configuration")