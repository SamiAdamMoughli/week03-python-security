import os
from dotenv import load_dotenv


class ConfigError(Exception):
    pass

class Config:

    def __init__(self):
        load_dotenv()

    def get(self, key, default=None):
        return os.environ.get(key, default)

    def require(self, key):
        result = self.get(key)
        if result is None:
            raise ConfigError(f"Missing required config key: {key}")

    def get_int(self, key) -> int:
        try:
            result = self.get(key)
            if result is None:
                return 0
            else:
                return int(result)
        except ValueError:
            raise ConfigError(f"{key} must be a valid integer.")

    def get_bool(self, key) -> bool:
        try:
            result = self.get(key)
            if result is None:
                return False
            else:
                return result.lower() in ("true", "1", "yes")
        except ValueError:
            raise ConfigError(f"{key} must be a valid boolean.")

    def get_list(self, key, seperator=","):
        try:
            result = self.get(key)
            if result is None:
                return []
            else:
                return result.split(seperator)
        except ValueError:
            raise ConfigError(f"{key} must be a valid boolean.")

    def validate(self):
        for key, value in os.environ.items():
            if value is None or value == 0:
                raise ConfigError(f"Empty config value for key: {key}")