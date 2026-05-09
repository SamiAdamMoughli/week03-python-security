import hashlib
import json
import logging
import time
import argparse
import fnmatch
from datetime import datetime
from pathlib import Path

logging.basicConfig(level=logging.INFO)

DEFAULT_EXCLUDES = {".git", "*.log", "*.tmp"}


class FileHasher:

    def hash_file(self, filepath, algorithm="sha256") -> str:
        """Hash a single file in chunks; return hex digest or None on failure."""
        try:
            hasher = hashlib.new(algorithm)
            with open(filepath, "rb") as f:
                while chunk := f.read(8192):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except (FileNotFoundError, PermissionError, ValueError) as e:
            logging.getLogger(__name__).error(f"Failed to hash {filepath}: {e}")
            return None

    def hash_directory(self, path, exclude=None) -> dict:
        """Recursively hash all files in a directory; return {filepath: hash}."""
        exclude = exclude or DEFAULT_EXCLUDES
        try:
            results = {}
            for file in Path(path).rglob("*"):
                if not file.is_file():
                    continue
                if any(fnmatch.fnmatch(file.name, pat) or pat in file.parts for pat in exclude):
                    continue
                results[str(file)] = self.hash_file(file)
            return results
        except (FileNotFoundError, PermissionError, ValueError) as e:
            logging.getLogger(__name__).error(f"Failed to hash directory {path}: {e}")
            return None


class BaselineStore:

    def save(self, baseline: dict, filepath):
        """Save hash baseline to JSON with timestamp."""
        try:
            with open(filepath, "w") as f:
                json.dump({"timestamp": datetime.now().isoformat(), "hashes": baseline}, f, indent=2)
        except OSError as e:
            raise OSError(f"Could not save baseline to {filepath}: {e}")

    def load(self, filepath) -> dict:
        """Load and validate baseline JSON; raise ValueError if corrupted."""
        try:
            with open(filepath, "r") as f:
                data = json.load(f)
            if "timestamp" not in data or "hashes" not in data:
                raise ValueError("Corrupted baseline file")
            return data
        except json.JSONDecodeError as e:
            raise ValueError(f"Corrupted baseline file: {e}")
        except OSError as e:
            raise OSError(f"Could not load baseline from {filepath}: {e}")

    def get_timestamp(self, filepath) -> str:
        """Return the timestamp from a saved baseline file."""
        return self.load(filepath)["timestamp"]


class FileIntegrityChecker:

    def notify(self, report: "IntegrityReport"):
        """Alert on detected changes — override this for email, Slack, etc."""
        print(report)

    def create_baseline(self, directory, output_file, exclude=None):
        """Scan directory and save hash baseline."""
        try:
            hashes = FileHasher().hash_directory(directory, exclude)
            if hashes is None:
                raise ValueError(f"Failed to hash directory: {directory}")
            BaselineStore().save(hashes, output_file)
        except (OSError, ValueError) as e:
            logging.getLogger(__name__).error(f"create_baseline failed: {e}")

    def verify(self, directory, baseline_file, exclude=None) -> "IntegrityReport":
        """Compare current directory state against baseline; return IntegrityReport."""
        try:
            baseline = BaselineStore().load(baseline_file)
            hashes = FileHasher().hash_directory(directory, exclude)

            baseline_files = set(baseline["hashes"].keys())
            current_files  = set(hashes.keys())
            both           = baseline_files & current_files

            new_files      = list(current_files - baseline_files)
            deleted_files  = list(baseline_files - current_files)
            modified_files = [f for f in both if hashes[f] != baseline["hashes"][f]]
            unchanged      = len([f for f in both if hashes[f] == baseline["hashes"][f]])

            return IntegrityReport(new_files, deleted_files, modified_files, unchanged)
        except (OSError, ValueError) as e:
            logging.getLogger(__name__).error(f"verify failed: {e}")
            return None

    def watch(self, directory, baseline_file, interval=60, exclude=None):
        """Continuously verify directory; call notify() when changes detected."""
        try:
            while True:
                report = self.verify(directory, baseline_file, exclude)
                if report and report.has_changes():
                    self.notify(report)
                time.sleep(interval)
        except KeyboardInterrupt:
            logging.getLogger(__name__).info("Monitoring stopped.")


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
        checker.create_baseline(args.baseline, args.output, exclude)
    elif args.verify:
        report = checker.verify(args.verify, args.baseline_file, exclude)
        if report:
            print(json.dumps(report.to_dict(), indent=2) if args.output_format == "json" else report)
    elif args.watch:
        checker.watch(args.watch, args.baseline_file, args.interval, exclude)
