"""
brute_force_demo.py
Demonstrates dictionary attack mechanics against weak hashes.
EDUCATIONAL DEMO — LOCAL USE ONLY.
Never use against systems you do not own.
Real passwords use bcrypt/Argon2 — this would take centuries on those.
"""

import hashlib
import logging
import os
import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from pathlib import Path
import bcrypt
from dotenv import load_dotenv

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger(__name__)

load_dotenv()

MAX_WORKERS = 8
_ALLOWED_BASE = Path(".").resolve()


def _safe_path(filepath: str) -> Path:
    """Reject path traversal outside working directory."""
    p = Path(filepath).resolve()
    if not str(p).startswith(str(_ALLOWED_BASE)):
        raise ValueError("Invalid file path.")
    return p


class HashCracker:
    SUPPORTED_ALGOS = {"md5", "sha1"}

    def __init__(self, algorithm: str = "md5", workers: int = 4):
        if not isinstance(algorithm, str) or algorithm not in self.SUPPORTED_ALGOS:
            raise ValueError(f"Unsupported algorithm. Choose from: {self.SUPPORTED_ALGOS}")
        if not isinstance(workers, int) or not (1 <= workers <= MAX_WORKERS):
            raise ValueError(f"workers must be between 1 and {MAX_WORKERS}.")
        self.algorithm = algorithm
        self.workers = workers
        self._lock = threading.Lock()

    def crack(self, target_hash: str, wordlist_path: str) -> str | None:
        path = _safe_path(wordlist_path)
        attempts = 0
        try:
            with open(path) as f:
                for word in f:
                    attempts += 1
                    word = word.strip()
                    h = hashlib.new(self.algorithm, word.encode()).hexdigest()
                    if h == target_hash:
                        # log attempt count only — never log the cracked word
                        log.info(f"Cracked after {attempts} attempts.")
                        return word
                    if attempts % 1000 == 0:
                        log.info(f"Attempts: {attempts}...")
        except OSError:
            log.error("Could not read wordlist.")
        return None

    def crack_batch(self, hashes: list, wordlist_path: str) -> dict:
        if not isinstance(hashes, list):
            raise TypeError("hashes must be a list.")
        results = {}
        for h in hashes:
            result = self.crack(h, wordlist_path)
            with self._lock:
                results[h] = result
        return results

    def crack_threaded(self, hashes: list, wordlist_path: str) -> dict:
        if not isinstance(hashes, list):
            raise TypeError("hashes must be a list.")
        fn = partial(self.crack, wordlist_path=wordlist_path)
        results = {}
        with ThreadPoolExecutor(max_workers=self.workers) as ex:
            for h, result in zip(hashes, ex.map(fn, hashes)):
                with self._lock:
                    results[h] = result
        return results


def main() -> None:
    password = os.getenv("DEMO_PASSWORD", "").encode()
    if not password:
        raise ValueError("DEMO_PASSWORD not set in .env")

    wordlist = "wordlist.txt"
    cracker = HashCracker(algorithm="md5", workers=4)

    path = _safe_path(wordlist)
    try:
        with open(path) as f:
            words = [line.strip() for line in f if line.strip()]
    except OSError:
        log.error("Could not open wordlist.")
        return

    targets = random.sample(words, 5)
    hashes = [hashlib.md5(w.encode()).hexdigest() for w in targets]  # nosec B324 — intentional demo of weak hashing

    log.info(f"Cracking {len(hashes)} hashes sequentially...")
    start = time.perf_counter()
    cracker.crack_batch(hashes, wordlist)
    seq_time = time.perf_counter() - start

    log.info(f"Cracking {len(hashes)} hashes threaded ({cracker.workers} workers)...")
    start = time.perf_counter()
    cracker.crack_threaded(hashes, wordlist)
    thr_time = time.perf_counter() - start

    log.info(f"Sequential: {seq_time:.3f}s | Threaded: {thr_time:.3f}s | Speedup: {seq_time/thr_time:.1f}x")

    # bcrypt demo — password from env, never hardcoded
    log.info("\n-- bcrypt demo --")
    hashed = bcrypt.hashpw(password, bcrypt.gensalt())
    log.info(f"bcrypt hash generated — length {len(hashed)}")

    attempts = 0
    start = time.perf_counter()
    try:
        with open(path) as f:
            for word in f:
                attempts += 1
                word = word.strip()
                if bcrypt.checkpw(word.encode(), hashed):
                    log.info(f"Cracked at attempt {attempts}.")
                    break
    except OSError:
        log.error("Could not read wordlist for bcrypt demo.")
        return

    elapsed = time.perf_counter() - start
    log.info(f"Attempts: {attempts} | Time: {elapsed:.3f}s | Per attempt: {elapsed/attempts:.4f}s")
    log.info("Each bcrypt check is intentionally slow — this is why it defeats dictionary attacks.")


if __name__ == "__main__":
    try:
        main()
    except ValueError as e:
        log.error(f"Configuration error: {e}")
    except Exception:
        log.error("Unexpected error — check configuration.")