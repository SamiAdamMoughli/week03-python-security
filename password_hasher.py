"""Password Hasher — OWASP Secure Coding Practices"""
import hashlib
import os
import json
import unicodedata
import re
import bcrypt

# OWASP: common/breached passwords blocklist (extend in production)
COMMON_PASSWORDS = {
    "password", "password1", "123456789", "qwerty123",
    "iloveyou", "admin123", "letmein1", "welcome1"
}

class PasswordHasher:
    def __init__(self, algorithm="bcrypt", rounds=12):
        self.algorithm = algorithm
        self.rounds = rounds

    def hash(self, password: str) -> str:
        self._validate_password(password)
        if self.algorithm == "bcrypt":
            # OWASP: normalize unicode before encoding to ensure consistency
            # e.g. "café" and "cafe\u0301" become the same bytes
            normalized = unicodedata.normalize("NFC", password)

            # OWASP: bcrypt silently truncates at 72 bytes — pre-hash with
            # SHA-256 to safely support passwords up to 128 chars
            pre_hashed = hashlib.sha256(normalized.encode()).hexdigest().encode()

            salt = bcrypt.gensalt(rounds=self.rounds)
            hashed = bcrypt.hashpw(pre_hashed, salt)
            return hashed.decode()
        else:
            iters = self.rounds * 1000
            normalized = unicodedata.normalize("NFC", password)
            h_passwd = normalized.encode()
            salt = os.urandom(16)
            hashed = hashlib.pbkdf2_hmac("sha256", h_passwd, salt, iters).hex()
            return hashed

    def verify(self, password: str, hashed: str) -> bool:
        try:
            self._validate_password(password)
            # Must pre-hash here too so verify matches hash exactly
            normalized = unicodedata.normalize("NFC", password)
            pre_hashed = hashlib.sha256(normalized.encode()).hexdigest().encode()
            return bcrypt.checkpw(pre_hashed, hashed.encode())
        except Exception:
            return False

    def needs_rehash(self, hashed: str) -> bool:
        match = re.search(r"\$(\d+)\$", hashed)
        if not match:
            return True
        current_rounds = int(match.group(1))
        return current_rounds < self.rounds

    def _validate_password(self, password):
        if not isinstance(password, str):
            raise ValueError("Password must be a string.")
        if not len(password) > 0:
            raise ValueError("Password cannot be empty.")
        if len(password) < 8:
            raise ValueError("Password cannot be shorter than 8 characters.")

        # OWASP: enforce maximum length (128 chars) to prevent DoS attacks
        # where attackers submit huge strings to slow down bcrypt
        if len(password) > 128:
            raise ValueError("Password cannot exceed 128 characters.")

        # OWASP: reject common or breached passwords
        if password.lower() in COMMON_PASSWORDS:
            raise ValueError("Password is too common. Please choose a stronger password.")


class PasswordStore:
    def __init__(self):
        self._passwords = {}
        self.hasher = PasswordHasher()
        # OWASP: track failed attempts per user to enable lockout
        self._failed_attempts = {}
        self.max_attempts = 5

    def add_user(self, username, password):
        if username in self._passwords:
            # OWASP: vague error — don't confirm whether username exists
            raise ValueError("Could not create account. Please try again.")
        hashed = self.hasher.hash(password)
        self._passwords[username] = hashed

    def authenticate(self, username, password) -> bool:
        # OWASP: account lockout after too many failed attempts
        if self._failed_attempts.get(username, 0) >= self.max_attempts:
            raise PermissionError("Account locked. Too many failed attempts.")

        if username not in self._passwords:
            return False

        hashed = self._passwords[username]
        result = self.hasher.verify(password, hashed)

        if result:
            # Reset failed attempts on success
            self._failed_attempts[username] = 0
        else:
            # Increment failed attempts on failure
            self._failed_attempts[username] = self._failed_attempts.get(username, 0) + 1

        return result

    def change_password(self, username, old_password, new_password):
        # OWASP: vague error — don't reveal which field was wrong
        if not self.authenticate(username, old_password):
            raise ValueError("Authentication failed.")

        # OWASP: prevent reuse of the same password
        if self.hasher.verify(new_password, self._passwords[username]):
            raise ValueError("New password must be different from current password.")

        self.hasher._validate_password(new_password)
        self._passwords[username] = self.hasher.hash(new_password)

    def save(self, filepath):
        try:
            with open(filepath, "w") as f:
                json.dump(self._passwords, f)
        except Exception as e:
            raise Exception(f"Could not save: {e}")

    def load(self, filepath):
        try:
            with open(filepath, "r") as f:
                self._passwords = json.load(f)
        except FileNotFoundError:
            raise FileNotFoundError(f"File not found: {filepath}")
        except Exception as e:
            raise Exception(f"Could not load: {e}")


def main():
    store = PasswordStore()

    store.add_user("j.smith", "Morning$Coffee92")
    store.add_user("m.taylor", "BlueSky!2024xZ")
    store.add_user("r.patel", "Secure#Pass77!")

    print(store.authenticate("j.smith", "Morning$Coffee92"))   # True
    print(store.authenticate("m.taylor", "BlueSky!2024xZ"))    # True
    print(store.authenticate("j.smith", "password123"))        # False
    print(store.authenticate("r.patel", "wrongpassword"))      # False

    store.change_password("r.patel", "Secure#Pass77!", "NewPass#2025!")
    print(store.authenticate("r.patel", "NewPass#2025!"))      # True

    store.save("userstore.json")
    store.load("userstore.json")
    print(store.authenticate("m.taylor", "BlueSky!2024xZ"))    # True


if __name__ == "__main__":
    main()