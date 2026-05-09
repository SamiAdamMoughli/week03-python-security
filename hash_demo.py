import hashlib
import time
import os

algos = ["md5", "sha1", "sha256", "sha512"]

for algo in algos:
    h = hashlib.new(algo, b"hello")
    result = h.hexdigest()
    length_digest = h.digest_size
    print (f"Algorithm: {algo} | Result: {result} | Length: {length_digest} bytes")


hash1 = hashlib.sha256(b"hello").hexdigest()
hash2 = hashlib.sha256(b"hello").hexdigest()
if hash1 == hash2:
    print(f"{hash1} and {hash2} are the same.")
else:
    print(f"{hash1} and {hash2} are NOT the same.")

avhash1 = hashlib.sha256(b"hello").hexdigest()
avhash2 = hashlib.sha256(b"Hello").hexdigest()
print(f"hello : {avhash1}")
print(f"Hello : {avhash2}")

iters = 600_000
salt = os.urandom(16)

hashed_password = hashlib.pbkdf2_hmac("sha256", b"myverystrongpassword", salt, iters).hex()
print(f"Hashed password: {hashed_password}")

start_time = time.perf_counter()
md5_hashing = hashlib.md5(b"hello").hexdigest()
end_time = time.perf_counter()
time_elapsed = end_time - start_time
print(f"MD5 took: {time_elapsed:-10f} seconds")

start_time = time.perf_counter()
pbkdf2_hashing = hashlib.pbkdf2_hmac("sha256", b"hello", salt, iters).hex()
end_time = time.perf_counter()
time_elapsed = end_time - start_time
print(f"PBKDF2 took: {time_elapsed:-10f} seconds")

# What is a hash collision?

# A collision occurs when 2 distinct and different inputs produce the same hash output.
# Ideally, every unique input should result in one unique hash value.

# Why MD5 is vulnerable

# MD5 is no longer "cryptographically secure" because it lacks "collision resistance".
# Real-world attacks have proven this.

# Why collisions matter!

# If 2 different files share one hash, an attacker can bypass integrity checks by swapping a safe for a malicious one.
# This enables -> FOrging digital signatures
#              -> Creating fake SSL certs to intercept traffic
#              -> Tampering with software downloads

# Why SHA-256 is currently safe.

# SHA-256 remains the industry standard because of collision resistance and massive bit-size.