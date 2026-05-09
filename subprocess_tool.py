import subprocess
import re
import shutil
import socket
import logging

logging.basicConfig(level=logging.INFO)


class SafeShell:
    """Safe subprocess wrapper — always list, never shell=True."""

    BLOCKED_COMMANDS = frozenset({'rm', 'dd', 'mkfs', 'shutdown', 'reboot'})
    DANGEROUS_CHARS  = re.compile(r'[;&|`$<>\\]')
    HOSTNAME_PATTERN = re.compile(
        r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
        r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    )
    IP_PATTERN = re.compile(
        r'^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$'
    )
    COMMON_PORTS = (22, 80, 443, 8080)

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def _validate_command(self, command: list):
        """Raise ValueError if command contains non-strings, metacharacters, or blocked commands."""
        if not command:
            raise ValueError("Command must not be empty")
        for arg in command:
            if not isinstance(arg, str):
                raise ValueError(f"All arguments must be strings, got {type(arg)}: {arg!r}")
            if self.DANGEROUS_CHARS.search(arg):
                raise ValueError(f"Dangerous character found in argument: {arg!r}")
        if command[0] in self.BLOCKED_COMMANDS:
            raise ValueError(f"Command '{command[0]}' is blocked for security reasons")

    def run(self, command: list, timeout=30) -> tuple[str, str, int]:
        """Execute a command safely; return (stdout, stderr, returncode)."""
        try:
            self._validate_command(command)
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                timeout=timeout,
            )
            return (result.stdout.decode('utf-8'), result.stderr.decode('utf-8'), result.returncode)
        except subprocess.TimeoutExpired as e:
            self.logger.warning(f"Command timed out: {e}")
            return ("", str(e), 1)
        except FileNotFoundError as e:
            self.logger.warning(f"Command not found: {e}")
            return ("", str(e), 1)
        except Exception as e:
            self.logger.error(f"Unexpected error in run(): {e}")
            return ("", str(e), 1)

    def run_with_input(self, command: list, input_data: str) -> str:
        """Execute a command with piped stdin; return stdout."""
        try:
            self._validate_command(command)
            result = subprocess.run(
                command,
                input=input_data.encode('utf-8'),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
            )
            return result.stdout.decode('utf-8')
        except Exception as e:
            self.logger.error(f"run_with_input failed: {e}")
            return str(e)

    def ping(self, host: str) -> bool:
        """Ping a host after validating it is a safe hostname or IPv4 address."""
        try:
            if not (self.HOSTNAME_PATTERN.match(host) or self.IP_PATTERN.match(host)):
                raise ValueError(f"Invalid hostname or IP address: {host!r}")
            _, _, returncode = self.run(["ping", "-c", "1", host], timeout=5)
            return returncode == 0
        except ValueError as e:
            self.logger.warning(f"Invalid target: {e}")
        except Exception as e:
            self.logger.error(f"Ping error: {e}")
        return False

    def get_open_ports(self, host: str) -> list:
        """Return open ports via nmap if available, else socket fallback."""
        if not (self.HOSTNAME_PATTERN.match(host) or self.IP_PATTERN.match(host)):
            raise ValueError(f"Invalid host: {host!r}")

        if shutil.which("nmap"):
            try:
                stdout, _, _ = self.run(["nmap", "-F", host])
                return [int(p) for p, _ in re.findall(r'(\d+)/(tcp|udp)', stdout)]
            except Exception as e:
                self.logger.error(f"nmap scan failed: {e}")
                return []

        open_ports = []
        for port in self.COMMON_PORTS:
            try:
                with socket.create_connection((host, port), timeout=1):
                    open_ports.append(port)
            except (socket.timeout, ConnectionRefusedError, OSError):
                pass
        return open_ports

    def get_process_list(self) -> list:
        """Return running processes as a list of dicts (user, pid, cpu, mem, command)."""
        try:
            stdout, stderr, returncode = self.run(["ps", "aux"])
            if returncode != 0:
                self.logger.error(f"ps failed: {stderr}")
                return []
            processes = []
            for line in stdout.strip().split("\n")[1:]:
                parts = line.split(None, 10)
                if len(parts) < 11:
                    continue
                processes.append({
                    "user":    parts[0],
                    "pid":     int(parts[1]),
                    "cpu":     float(parts[2]),
                    "mem":     float(parts[3]),
                    "command": parts[10].strip(),
                })
            return processes
        except Exception as e:
            self.logger.error(f"get_process_list failed: {e}")
            return []


if __name__ == "__main__":
    shell = SafeShell()

    # UNSAFE — never do this:
    # subprocess.run(f"ping google.com; rm -rf /", shell=True)
    # shell=True passes the string to /bin/sh — the semicolon runs a second command.

    shell.ping("google.com; rm -rf /")         # rejected by host validation
    shell.run(["ls", "-la; rm -rf /"])          # rejected by _validate_command
    shell.ping("google.com")
    shell.run_with_input(["grep", "root"], "root:x:0:0\nnobody:x:99:99")

    for p in shell.get_process_list()[:5]:
        print(p)