# Week 03 — Security Hardening Notes
## Python Security Checklist + Findings + Fixes

---

## The Hardened Checklist

| # | Item | Rule |
|---|------|------|
| 1 | File paths | Validate with `_safe_path()` — reject `../` traversal outside working directory |
| 2 | Network targets | Validate IP or hostname with regex before any socket or subprocess call |
| 3 | Subprocesses | Always `shell=False`, always a list — never a string |
| 4 | Secrets | Load from environment via `os.getenv()` + `load_dotenv()` — never hardcoded |
| 5 | User input | Type-check with `isinstance()` before processing |
| 6 | Error messages | Never echo raw input, internal paths, or `str(e)` to the user |
| 7 | Logging | Use `logging` module — never `print()` for status; never log sensitive values |
| 8 | File handles | Always `with open()` — no unclosed handles |
| 9 | Thread safety | Any shared dict or list written from multiple threads needs `threading.Lock()` |
| 10 | Rate limiting | Network tools must have configurable timeout + `MAX_WORKERS` hard cap |

---

## Script-by-Script Findings + Fixes

---

### hash_demo.py

**Purpose:** Demonstrates hashing algorithms, avalanche effect, and PBKDF2 timing.

| # | Finding | Fix |
|---|---------|-----|
| 4 | `b"myverystrongpassword"` hardcoded in `pbkdf2_hmac()` call | Loaded from `DEMO_PASSWORD` env var via `load_dotenv()` |
| 6 | No error handling — raw stack traces on failure | Wrapped in `main()` with `try/except ValueError` and bare `except` |
| 7 | `print()` used throughout | Replaced with `logging.getLogger(__name__)` |

**Key principle:** `load_dotenv()` must be at module level — not inside a function or at the bottom of the file.

---

### brute_force_demo.py

**Purpose:** Demonstrates dictionary attack speed against MD5 vs bcrypt resistance.

| # | Finding | Fix |
|---|---------|-----|
| 1 | `wordlist_path` passed directly to `open()` | `_safe_path()` rejects traversal outside working directory |
| 4 | `b"Summer2024!"` hardcoded as bcrypt password | Replaced with `password` loaded from `DEMO_PASSWORD` env var |
| 4 | `load_dotenv()` placed after `main()` — never executed | Moved to module level |
| 6 | `crack()` printed the cracked word directly | Logs attempt count only — cracked word never logged |
| 7 | `print()` used throughout | Replaced with `logging` |
| 9 | `results` dict written from threads without lock | `threading.Lock()` added — acquired before every write |
| 10 | `workers=4` hardcoded, no cap | `MAX_WORKERS = 8` constant, validated in `__init__` |

**Key principle:** Never log cracked passwords — log attempt count and word length only.

---

### password_hasher.py

**Purpose:** OWASP-compliant password hashing, verification, and storage.

| # | Finding | Fix |
|---|---------|-----|
| 1 | `save()` and `load()` took raw filepath with no traversal check | `_safe_path()` rejects anything outside working directory |
| 5 | `username` never validated — any string accepted | `isinstance()` check + regex: alphanumeric, dots, dashes, max 64 chars |
| 6 | `save()`/`load()` leaked filepath and `str(e)` in exceptions | Caught and re-raised with generic message; path stripped |
| 9 | `_passwords` and `_failed_attempts` had no lock | `threading.Lock()` guards all reads and writes |

**Key principle:** Vague error messages are a feature, not a bug — don't confirm whether a username exists.

---

### file_integrity_checker.py

**Purpose:** Hash-based file integrity monitoring with baseline comparison.

| # | Finding | Fix |
|---|---------|-----|
| 1 | `hash_directory()` and `create_baseline()` took raw paths | `_safe_path()` on every path argument |
| 5 | `argparse` values fed directly into functions without validation | `--output` and `--baseline-file` checked as required before use |
| 6 | `OSError` and filepath leaked in log messages | Filepath stripped from all error output |
| 6 | `hash_file()` logged full filepath on failure | Replaced with generic message |
| 10 | `rglob("*")` had no file count cap | `MAX_FILES = 100_000` — scan truncates at limit with warning |
| 10 | `watch()` accepted any interval | Minimum 5 seconds enforced |

**Key principle:** `rglob()` on an untrusted path with no cap is a resource exhaustion vector.

---

### subprocess_tool.py

**Purpose:** Safe subprocess wrapper enforcing `shell=False` and input validation.

| # | Finding | Fix |
|---|---------|-----|
| 6 | `str(e)` passed to `logger.warning()` — exception text leaked | Exception type logged internally; generic message only |
| 6 | `run_with_input()` returned `str(e)` to caller on failure | Returns `None` on failure — exception never reaches caller |
| 10 | `ping()` and `get_open_ports()` had no call interval | `_rate_limit()` enforces 1 second minimum between network calls |

**Key principle:** `str(e)` in a return value is as dangerous as printing it — the caller sees it.

---

### network_scanner.py

**Purpose:** CIDR ping sweep and port scanner using `SafeShell` and `ThreadedPortScanner`.

| # | Finding | Fix |
|---|---------|-----|
| 6 | `ValueError` echoed raw `network` input from argparse | Generic message — raw input stripped |
| 7 | `print()` used for all status output | Replaced with `logging` |
| 10 | `max_workers=50` hardcoded, no cap | `MAX_WORKERS = 20` constant, validated in `__init__` |
| 10 | `full_scan()` used `ThreadPoolExecutor()` with no `max_workers` | Uses `self.max_workers` |
| 10 | `compare_speed()` ran automatically in `main()` | Moved behind `--compare-speed` flag — opt-in only |
| 5 | `network.hosts()` missing — included broadcast/network addresses | Changed `list(self.network)` to `list(self.network.hosts())` |

**Key principle:** Never run benchmark or diagnostic functions automatically — always opt-in via a flag.

---

### threaded_scanner.py

**Purpose:** Sequential and threaded TCP port scanner with banner grabbing.

| # | Finding | Fix |
|---|---------|-----|
| 2 | `socket.gethostbyname()` called without prior validation | `_validate_target()` — regex check before resolution |
| 5 | Port range from `argparse` had no bounds check | `_validate_port_range()` — rejects out-of-range and inverted ranges |
| 6 | `ValueError` echoed raw target string | Generic message — raw input stripped |
| 6 | Banner bytes decoded and logged without sanitisation | `_sanitise_banner()` — printable ASCII only, capped at 256 chars |
| 7 | `print()` used throughout | Replaced with `logging` |
| 10 | `max_workers=100` default, no cap | `MAX_WORKERS = 50`, validated in `__init__` |
| 10 | `scan_common()` used `self.max_workers` inconsistently | Enforced throughout |
| 10 | `compare_speed()` ran automatically in `main()` | Moved behind `--compare-speed` flag |

**Key principle:** Banner data is attacker-controlled — always sanitise before logging or displaying.

---

### env_config.py

**Purpose:** Environment variable loader with type coercion and validation.

| # | Finding | Fix |
|---|---------|-----|
| 4 | `load_dotenv()` called in `__init__` — ran on every instantiation | Moved to module level |
| 5 | `key` parameter never validated — `None` or `int` accepted | `_validate_key()` rejects non-string and empty keys |
| 6 | Key names leaked in all `ConfigError` messages | Logged internally; generic message raised to caller |
| 7 | No logging at all | `log.error()` on all failure paths |
| Bug | `require()` missing `return result` | Fixed — now returns the value |
| Bug | `get_list()` error message said "valid boolean" | Fixed to say "valid list" |
| Bug | `validate()` checked `value == 0` — always False for env strings | Rewritten to accept `required_keys` list, checks empty strings |
| Bug | `seperator` typo in `get_list()` | Fixed to `separator` |

**Key principle:** Config key names are internal structure — never expose them in user-facing errors.

---

## Universal Patterns Applied Across All Scripts

```python