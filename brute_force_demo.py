import hashlib
from functools import partial
from concurrent.futures import ThreadPoolExecutor
import threading
import bcrypt
import random  # NOT USED AS ALGO!
import time

# EDUCATIONAL DEMO — LOCAL USE ONLY
# This tool demonstrates why MD5 is unsuitable for password storage.
# Never use against systems you do not own.
# Real passwords use bcrypt/Argon2 — this would take centuries on those.

class HashCracker:
    SUPPORTED_ALGOS = {"md5", "sha1"}

    def __init__(self, algorithm="md5"):
        if algorithm not in self.SUPPORTED_ALGOS:
            raise ValueError(f"Unsupported algorithm: {algorithm}. Please use MD5 or SHA!")
        self.algorithm = algorithm

    def crack(self, target_hash: str, wordlist_path: str) -> str | None:
        attempts = 0
        with open(wordlist_path) as f:
            for word in f:
                attempts += 1
                word = word.strip()
                h = hashlib.new(self.algorithm, word.encode()).hexdigest()
                if h == target_hash:
                    print(f"CRACKED after {attempts} attempts: {word}")
                    return word
                if attempts % 1000 == 0:
                    print(f"Attempts: {attempts}...")
        return None


    def crack_batch(self, hashes: list, wordlist_path: str) -> dict:
        results = {}
        for h in hashes:
            result = self.crack(h, wordlist_path)
            results[h] = result
        return results

    def crack_threaded(self, hashes: list, wordlist_path: str, workers=4) -> dict:
        fn = partial(self.crack, wordlist_path=wordlist_path)
        with ThreadPoolExecutor(max_workers=workers) as ex:
            results = list(ex.map(fn, hashes))
        return dict(zip(hashes, results))

def main():
    cracker = HashCracker(algorithm="md5")
    wordlist = "wordlist.txt"

    with open(wordlist) as f:
        words = [line.strip() for line in f]

    targets = random.sample(words, 5)
    hashes = [hashlib.md5(w.encode()).hexdigest() for w in targets]

    print(f"cracking {len(hashes)} hashes...")

    start = time.perf_counter()
    cracker.crack_batch(hashes, wordlist)
    seq_time = time.perf_counter() - start

    start = time.perf_counter()
    cracker.crack_threaded(hashes, wordlist, workers=4)
    thr_time = time.perf_counter() - start

    print(f"sequential: {seq_time:.3f}s  threaded: {thr_time:.3f}s  speedup: {seq_time/thr_time:.1f}x")

    print("\n-- bcrypt demo --")
    hashed = bcrypt.hashpw(b"Summer2024!", bcrypt.gensalt())
    print(f"bcrypt hash: {hashed}")
    start = time.perf_counter()
    attempts = 0
    with open(wordlist) as f:
        for word in f:
            attempts += 1
            word = word.strip()
            if bcrypt.checkpw(word.encode(), hashed):
                print(f"cracked: {word}")
                break
    elapsed = time.perf_counter() - start
    print(f"attempts: {attempts}  time: {elapsed:.3f}s  per attempt: {elapsed/attempts:.3f}s")
    print(f"\neach bcrypt check is intentionally slow -- this is why it defeats dictionary attacks")
    print("")
if __name__ == "__main__":
    main()
