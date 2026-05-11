"""Password Hasher — OWASP Secure Coding Practices"""
import hashlib
import os
import json
import unicodedata
import re
import logging
import threading
from pathlib import Path
import bcrypt

log = logging.getLogger(__name__)

COMMON_PASSWORDS = {
    "password", "password1", "123456789", "qwerty123",
    "iloveyou", "admin123", "letmein1", "welcome1"
}

_ALLOWED_BASE = Path(".").resolve()


def _safe_path(filepath: str) -> Path:
    """Reject path traversal — must stay within working directory."""
    p = Path(filepath).resolve()
    if not str(p).startswith(str(_ALLOWED_BASE)):
        raise ValueError("Invalid file path")
    return p


class PasswordHasher:
    def __init__(self, algorithm="bcrypt", rounds=12):
        self.algorithm = algorithm
        self.rounds = rounds

    def hash(self, password: str) -> str:
        self._validate_password(password)
        if self.algorithm == "bcrypt":
            normalized = unicodedata.normalize("NFC", password)
            pre_hashed = hashlib.sha256(normalized.encode()).hexdigest().encode()

            salt = bcrypt.gensalt(rounds=self.rounds)
            hashed = bcrypt.hashpw(pre_hashed, salt)
            return hashed.decode()
        else:
            iters = self.rounds * 1000
            normalized = unicodedata.normalize("NFC", password)

            salt = os.urandom(16)
            hashed = hashlib.pbkdf2_hmac("sha256", normalized.encode(), salt, iters).hex()
            return hashed

    def verify(self, password: str, hashed: str) -> bool:
        try:
            self._validate_password(password)
            normalized = unicodedata.normalize("NFC", password)
            pre_hashed = hashlib.sha256(normalized.encode()).hexdigest().encode()
            return bcrypt.checkpw(pre_hashed, hashed.encode())
        except Exception:
            return False

    def needs_rehash(self, hashed: str) -> bool:
        match = re.search(r"\$(\d+)\$", hashed)
        if not match:
            return True
        return int(match.group(1)) < self.rounds

    def _validate_password(self, password: str) -> None:
        if not isinstance(password, str):
            raise ValueError("Password must be a string.")
        if len(password) == 0:
            raise ValueError("Password cannot be empty.")
        if len(password) < 8:
            raise ValueError("Password cannot be shorter than 8 characters.")
        if len(password) > 128:
            raise ValueError("Password cannot exceed 128 characters.")
        if password.lower() in COMMON_PASSWORDS:
            raise ValueError("Password is too common. Please choose a stronger password.")


class PasswordStore:
    def __init__(self):
        self._lock = threading.Lock()  # guards _passwords and _failed_attempts
        self._passwords: dict = {}
        self._failed_attempts: dict = {}
        self.hasher = PasswordHasher()
        self.max_attempts = 5

    def add_user(self, username: str, password: str) -> None:
        if not isinstance(username, str) or not username.strip():
            raise ValueError("Invalid username.")
        # OWASP: reject usernames with special characters
        if not re.match(r"^[a-zA-Z0-9._-]{1,64}$", username):
            raise ValueError("Username contains invalid characters.")
        with self._lock:
            if username in self._passwords:
                raise ValueError("Could not create account. Please try again.")
            hashed = self.hasher.hash(password)
            self._passwords[username] = hashed

    def authenticate(self, username: str, password: str) -> bool:
        if not isinstance(username, str):
            return False
        with self._lock:
            if self._failed_attempts.get(username, 0) >= self.max_attempts:
                raise PermissionError("Account locked. Too many failed attempts.")
            if username not in self._passwords:
                return False
            hashed = self._passwords[username]

        result = self.hasher.verify(password, hashed)

        with self._lock:
            if result:
                self._failed_attempts[username] = 0
            else:
                self._failed_attempts[username] = self._failed_attempts.get(username, 0) + 1
        return result

    def change_password(self, username: str, old_password: str, new_password: str) -> None:
        if not self.authenticate(username, old_password):
            raise ValueError("Authentication failed.")
        with self._lock:
            if self.hasher.verify(new_password, self._passwords[username]):
                raise ValueError("New password must be different from current password.")
            self.hasher._validate_password(new_password)
            self._passwords[username] = self.hasher.hash(new_password)

    def save(self, filepath: str) -> None:
        try:
            path = _safe_path(filepath)
            with open(path, "w") as f:
                json.dump(self._passwords, f)
        except ValueError:
            raise
        except Exception:
            # OWASP: don't leak internal path or exception details
            raise Exception("Could not save password store.")

    def load(self, filepath: str) -> None:
        try:
            path = _safe_path(filepath)
            with open(path) as f:
                with self._lock:
                    self._passwords = json.load(f)
        except ValueError:
            raise
        except FileNotFoundError:
            raise FileNotFoundError("Password store file not found.")
        except Exception:
            raise Exception("Could not load password store.")


def main():
    store = PasswordStore()

    store.add_user("j.smith", "Morning$Coffee92")
    store.add_user("m.taylor", "BlueSky!2024xZ")
    store.add_user("r.patel", "Secure#Pass77!")

    print(store.authenticate("j.smith", "Morning$Coffee92"))
    print(store.authenticate("m.taylor", "BlueSky!2024xZ"))
    print(store.authenticate("j.smith", "password123"))
    print(store.authenticate("r.patel", "wrongpassword"))

    store.change_password("r.patel", "Secure#Pass77!", "NewPass#2025!")
    print(store.authenticate("r.patel", "NewPass#2025!"))

    store.save("userstore.json")
    store.load("userstore.json")
    print(store.authenticate("m.taylor", "BlueSky!2024xZ"))


if __name__ == "__main__":
    main()