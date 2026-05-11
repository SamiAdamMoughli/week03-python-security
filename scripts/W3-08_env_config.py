"""
env_config.py
Environment variable loader with type coercion and validation.
Wraps os.environ with safe accessors — never exposes raw key names in errors.
"""

import os
import logging
from dotenv import load_dotenv

load_dotenv()  # load once at module level — not per-instance

log = logging.getLogger(__name__)


class ConfigError(Exception):
    pass


class Config:

    def _validate_key(self, key: str) -> None:
        """Reject non-string or empty keys."""
        if not isinstance(key, str) or not key.strip():
            raise ConfigError("Invalid config key.")

    def get(self, key: str, default=None) -> str | None:
        self._validate_key(key)
        return os.environ.get(key, default)

    def require(self, key: str) -> str:
        self._validate_key(key)
        result = self.get(key)
        if result is None:
            # don't leak key name — log internally, raise vague error
            log.error(f"Missing required config key: {key}")
            raise ConfigError("A required configuration value is missing.")
        return result

    def get_int(self, key: str) -> int:
        self._validate_key(key)
        result = self.get(key)
        if result is None:
            return 0
        try:
            return int(result)
        except ValueError:
            log.error(f"Config key {key} is not a valid integer.")
            raise ConfigError("A configuration value is not a valid integer.")

    def get_bool(self, key: str) -> bool:
        self._validate_key(key)
        result = self.get(key)
        if result is None:
            return False
        return result.lower() in ("true", "1", "yes")

    def get_list(self, key: str, separator: str = ",") -> list:
        self._validate_key(key)
        result = self.get(key)
        if result is None:
            return []
        return [item.strip() for item in result.split(separator)]

    def validate(self, required_keys: list) -> None:
        """Check all required keys are present and non-empty."""
        if not isinstance(required_keys, list):
            raise TypeError("required_keys must be a list.")
        missing = []
        for key in required_keys:
            value = os.environ.get(key, "").strip()
            if not value:
                log.error(f"Empty or missing config key: {key}")
                missing.append(key)
        if missing:
            raise ConfigError(f"{len(missing)} required config value(s) are missing or empty.")