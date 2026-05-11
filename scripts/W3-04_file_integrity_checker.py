"""
file_integrity_checker.py
File integrity monitoring via SHA-256 baseline comparison.
Detects new, deleted, and modified files in a directory.
"""

import hashlib
import json
import logging
import time
import argparse
import fnmatch
from datetime import datetime
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

DEFAULT_EXCLUDES = {".git", "*.log", "*.tmp"}
MAX_FILES = 100_000  # cap rglob to prevent runaway scans


def _safe_path(filepath: str, must_exist: bool = False) -> Path:
    """Resolve path and reject traversal outside working directory."""
    try:
        p = Path(filepath).resolve()
    except Exception:
        raise ValueError("Invalid file path.")
    allowed = Path(".").resolve()
    if not str(p).startswith(str(allowed)):
        raise ValueError("Path outside allowed directory — rejected.")
    if must_exist and not p.exists():
        raise FileNotFoundError("Path does not exist.")
    return p


class FileHasher:

    def hash_file(self, filepath, algorithm="sha256") -> str | None:
        """Hash a single file in chunks; return hex digest or None on failure."""
        try:
            hasher = hashlib.new(algorithm)
            with open(filepath, "rb") as f:
                while chunk := f.read(8192):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except (FileNotFoundError, PermissionError, ValueError):
            # don't log filepath — may contain sensitive system path
            log.error("Failed to hash a file — skipping.")
            return None

    def hash_directory(self, path: str, exclude=None) -> dict | None:
        """Recursively hash all files in a directory; return {filepath: hash}."""
        exclude = exclude or DEFAULT_EXCLUDES
        try:
            safe = _safe_path(path, must_exist=True)
            results = {}
            file_count = 0
            for file in safe.rglob("*"):
                if not file.is_file():
                    continue
                if any(fnmatch.fnmatch(file.name, pat) or pat in file.parts for pat in exclude):
                    continue
                file_count += 1
                if file_count > MAX_FILES:
                    log.warning("File count limit reached — scan truncated.")
                    break
                results[str(file)] = self.hash_file(file)
            return results
        except (ValueError, FileNotFoundError) as e:
            log.error(f"Directory error: {e}")
            return None
        except PermissionError:
            log.error("Permission denied accessing directory.")
            return None


class BaselineStore:

    def save(self, baseline: dict, filepath: str) -> None:
        """Save hash baseline to JSON with timestamp."""
        try:
            path = _safe_path(filepath)
            with open(path, "w") as f:
                json.dump({"timestamp": datetime.now().isoformat(), "hashes": baseline}, f, indent=2)
        except ValueError as e:
            raise ValueError(f"Invalid output path: {e}")
        except OSError:
            raise OSError("Could not save baseline — check permissions.")

    def load(self, filepath: str) -> dict:
        """Load and validate baseline JSON; raise ValueError if corrupted."""
        try:
            path = _safe_path(filepath, must_exist=True)
            with open(path) as f:
                data = json.load(f)
            if "timestamp" not in data or "hashes" not in data:
                raise ValueError("Corrupted baseline file.")
            return data
        except ValueError:
            raise
        except FileNotFoundError:
            raise FileNotFoundError("Baseline file not found.")
        except json.JSONDecodeError:
            raise ValueError("Corrupted baseline file — invalid JSON.")
        except OSError:
            raise OSError("Could not load baseline — check permissions.")

    def get_timestamp(self, filepath: str) -> str:
        return self.load(filepath)["timestamp"]


class FileIntegrityChecker:

    def notify(self, report: "IntegrityReport") -> None:
        """Alert on detected changes — override for email, Slack, etc."""
        print(report)

    def create_baseline(self, directory: str, output_file: str, exclude=None) -> None:
        """Scan directory and save hash baseline."""
        try:
            hashes = FileHasher().hash_directory(directory, exclude)
            if hashes is None:
                raise ValueError("Failed to hash directory.")
            BaselineStore().save(hashes, output_file)
        except (OSError, ValueError) as e:
            log.error(f"create_baseline failed: {e}")

    def verify(self, directory: str, baseline_file: str, exclude=None) -> "IntegrityReport | None":
        """Compare current state against baseline; return IntegrityReport."""
        try:
            baseline = BaselineStore().load(baseline_file)
            hashes = FileHasher().hash_directory(directory, exclude)
            if hashes is None:
                raise ValueError("Failed to hash directory.")

            baseline_files = set(baseline["hashes"].keys())
            current_files  = set(hashes.keys())
            both           = baseline_files & current_files

            new_files      = list(current_files - baseline_files)
            deleted_files  = list(baseline_files - current_files)
            modified_files = [f for f in both if hashes[f] != baseline["hashes"][f]]
            unchanged      = len([f for f in both if hashes[f] == baseline["hashes"][f]])

            return IntegrityReport(new_files, deleted_files, modified_files, unchanged)
        except (OSError, ValueError) as e:
            log.error(f"verify failed: {e}")
            return None

    def watch(self, directory: str, baseline_file: str, interval: int = 60, exclude=None) -> None:
        """Continuously verify directory; call notify() when changes detected."""
        if not isinstance(interval, int) or interval < 5:
            raise ValueError("Interval must be an integer of at least 5 seconds.")
        try:
            while True:
                report = self.verify(directory, baseline_file, exclude)
                if report and report.has_changes():
                    self.notify(report)
                time.sleep(interval)
        except KeyboardInterrupt:
            log.info("Monitoring stopped.")


class IntegrityReport:

    def __init__(self, new_files: list, deleted_files: list, modified_files: list, unchanged_files: int):
        self.new_files       = new_files
        self.deleted_files   = deleted_files
        self.modified_files  = modified_files
        self.unchanged_files = unchanged_files

    def has_changes(self) -> bool:
        return bool(self.new_files or self.deleted_files or self.modified_files)

    def to_dict(self) -> dict:
        return {
            "timestamp":      datetime.now().isoformat(),
            "new_files":      self.new_files,
            "deleted_files":  self.deleted_files,
            "modified_files": self.modified_files,
            "unchanged":      self.unchanged_files,
        }

    def __str__(self):
        lines = [f"Integrity Report — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"]
        lines.append(f"\nNew files ({len(self.new_files)}):")
        for f in self.new_files:
            lines.append(f"  + {f}")
        lines.append(f"\nDeleted files ({len(self.deleted_files)}):")
        for f in self.deleted_files:
            lines.append(f"  - {f}")
        lines.append(f"\nModified files ({len(self.modified_files)}):")
        for f in self.modified_files:
            lines.append(f"  ~ {f}")
        lines.append(f"\nUnchanged: {self.unchanged_files}")
        return "\n".join(lines)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="File Integrity Checker")
    parser.add_argument("--baseline", help="Directory to baseline")
    parser.add_argument("--verify", help="Directory to verify")
    parser.add_argument("--watch", help="Directory to watch")
    parser.add_argument("--output", help="Output file for baseline")
    parser.add_argument("--baseline-file", help="Baseline JSON file")
    parser.add_argument("--interval", type=int, default=60)
    parser.add_argument("--exclude", nargs="*", help="Patterns to exclude e.g. *.log .git")
    parser.add_argument("--output-format", choices=["text", "json"], default="text")
    args = parser.parse_args()

    exclude = set(args.exclude) if args.exclude else DEFAULT_EXCLUDES
    checker = FileIntegrityChecker()

    if args.baseline:
        if not args.output:
            log.error("--output required with --baseline")
        else:
            checker.create_baseline(args.baseline, args.output, exclude)
    elif args.verify:
        if not args.baseline_file:
            log.error("--baseline-file required with --verify")
        else:
            report = checker.verify(args.verify, args.baseline_file, exclude)
            if report:
                print(json.dumps(report.to_dict(), indent=2) if args.output_format == "json" else report)
    elif args.watch:
        if not args.baseline_file:
            log.error("--baseline-file required with --watch")
        else:
            checker.watch(args.watch, args.baseline_file, args.interval, exclude)