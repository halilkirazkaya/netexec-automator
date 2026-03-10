#!/usr/bin/env python3

import argparse
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from threading import Lock
from typing import Literal

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

ALL_PROTOCOLS = ["smb", "ssh", "ldap", "ftp", "wmi", "winrm", "rdp", "vnc", "mssql", "nfs"]
LOCAL_AUTH_PROTOCOLS = {"smb", "wmi", "winrm", "rdp", "mssql"}

DEFAULT_WORKERS = len(ALL_PROTOCOLS) + len(LOCAL_AUTH_PROTOCOLS)
MAX_RETRY = 3
SUBPROCESS_TIMEOUT = 45
NETEXEC_TIMEOUT = 30
BANNER_WIDTH = 60
PROGRESS_CLEAR_WIDTH = 70

TaskKey = tuple[str, bool]
ParsedStatus = tuple[str, str]
AttemptClassification = Literal["credential_response", "connectivity_timeout", "ambiguous"]

AUTH_RESPONSE_PATTERNS = (
    "status_logon_failure",
    "status_access_denied",
    "rpc_s_access_denied",
    "access denied",
    "authentication failed",
    "invalid credentials",
    "bad credentials",
    "permission denied",
    "login failed",
    "logon failure",
)

CONNECTIVITY_TIMEOUT_PATTERNS = (
    "timed out",
    "connection timeout",
    "connection refused",
    "connection reset",
    "reset by peer",
    "could not connect",
    "connection error",
    "host is unreachable",
    "no route to host",
    "network is unreachable",
    "netbios connection",
    "name or service not known",
    "temporary failure in name resolution",
    "broken pipe",
    "errno 110",
    "errno 111",
    "errno 113",
)

class NxcAutomator:
    """Run nxc across all protocols with combination or linear credential pairing."""

    def __init__(
        self,
        target: str,
        user: str,
        password: str,
        output: str | None = None,
        workers: int = DEFAULT_WORKERS,
        mode: str = "combination",
    ):
        self.targets = self._read_value_or_file(target)
        self.users = self._read_value_or_file(user)
        self.passwords = self._read_value_or_file(password)
        self.mode = mode.lower()
        self.credential_pairs = self._build_credential_pairs()
        self.workers = workers
        self.lock = Lock()
        self.completed = 0
        self.total_tasks = 0
        self.log_file = output if output else datetime.now().strftime("%H-%M-%S-%f")[:-3] + ".txt"

    @staticmethod
    def _read_lines(path: str) -> list[str]:
        with open(path) as f:
            return [line.strip() for line in f if line.strip()]

    @classmethod
    def _read_value_or_file(cls, source: str) -> list[str]:
        """Return direct value as one-item list, or load non-empty lines from file."""
        return cls._read_lines(source) if os.path.isfile(source) else [source]

    @staticmethod
    def _auth_scope(local_auth: bool) -> str:
        return "local" if local_auth else "domain"

    def _task_label(self, protocol: str, local_auth: bool) -> str:
        """Return standardized display label for protocol/auth scope."""
        return f"{protocol.upper()} ({self._auth_scope(local_auth)})"

    @staticmethod
    def _build_protocol_tasks() -> list[TaskKey]:
        tasks: list[TaskKey] = []
        for protocol in ALL_PROTOCOLS:
            tasks.append((protocol, False))
            if protocol in LOCAL_AUTH_PROTOCOLS:
                tasks.append((protocol, True))
        return tasks

    def _build_credential_pairs(self) -> list[tuple[str, str]]:
        # "combination" keeps the existing cartesian product behavior.
        if self.mode == "combination":
            return [(user, password) for user in self.users for password in self.passwords]
        # "linear" enforces one-to-one index matching between both lists.
        if self.mode == "linear":
            if len(self.users) != len(self.passwords):
                raise ValueError(
                    "Linear mode requires user and password lists to have the same length."
                )
            return list(zip(self.users, self.passwords))
        raise ValueError(f"Unsupported mode: {self.mode}")

    def _redraw_progress(self):
        if self.total_tasks > 0:
            bar_len = 20
            filled = int(bar_len * self.completed / self.total_tasks)
            bar = f"{'█' * filled}{'░' * (bar_len - filled)}"
            pct = int(100 * self.completed / self.total_tasks)
            sys.stderr.write(f"\r  {DIM}{bar} {pct:3d}% ({self.completed}/{self.total_tasks}){RESET}")
            sys.stderr.flush()

    def _update_progress(self):
        with self.lock:
            self.completed += 1
            self._redraw_progress()

    def _skip_progress(self, count: int):
        with self.lock:
            self.completed += count
            self._redraw_progress()

    def _print_live(self, msg: str):
        """Print a finding in real-time, temporarily clearing the progress bar."""
        with self.lock:
            sys.stderr.write("\r" + " " * PROGRESS_CLEAR_WIDTH + "\r")
            sys.stderr.flush()
            print(msg, flush=True)
            self._redraw_progress()

    def _build_nxc_command(
        self, protocol: str, target: str, user: str, password: str, local_auth: bool
    ) -> list[str]:
        cmd = ["nxc", protocol, target, "-u", user, "-p", password]
        if local_auth:
            cmd.append("--local-auth")
        cmd.extend(["--timeout", str(NETEXEC_TIMEOUT), "--log", self.log_file])
        return cmd

    def _report_success_lines(self, stdout: str, protocol: str, local_auth: bool):
        for raw_line in stdout.split("\n"):
            marker, msg = self._parse_nxc_line(raw_line.strip())
            if marker == "[+]":
                label = self._task_label(protocol, local_auth)
                self._print_live(
                    f"  {GREEN}{BOLD}⚡ {label}{RESET} {GREEN}{msg}{RESET}"
                )

    @staticmethod
    def _parse_status_blocks(blocks: list[str]) -> list[ParsedStatus]:
        parsed: list[ParsedStatus] = []
        for block in blocks:
            for line in block.split("\n"):
                line = line.strip()
                if not line:
                    continue
                marker, msg = NxcAutomator._parse_nxc_line(line)
                if marker in ("[+]", "[-]", "[!]"):
                    parsed.append((marker, msg))
        return parsed

    @staticmethod
    def _status_icon(parsed: list[ParsedStatus]) -> str:
        has_success = any(marker == "[+]" for marker, _ in parsed)
        has_skip = any(marker == "[!]" for marker, _ in parsed)
        if has_success:
            return f"{GREEN}✔{RESET}"
        if has_skip:
            return f"{YELLOW}⏱{RESET}"
        return f"{RED}✘{RESET}"

    @staticmethod
    def _contains_any_pattern(text: str, patterns: tuple[str, ...]) -> bool:
        return any(pattern in text for pattern in patterns)

    def _classify_attempt_output(self, stdout: str, stderr: str) -> AttemptClassification:
        """Classify one nxc run to decide timeout skip behavior."""
        combined = "\n".join(part for part in (stdout, stderr) if part).lower()
        if not combined:
            return "ambiguous"

        # Credential-related failures mean the service responded, so they should
        # not contribute to consecutive connectivity timeout skips.
        if self._contains_any_pattern(combined, AUTH_RESPONSE_PATTERNS):
            return "credential_response"

        if self._contains_any_pattern(combined, CONNECTIVITY_TIMEOUT_PATTERNS):
            return "connectivity_timeout"

        for raw_line in (stdout + "\n" + stderr).split("\n"):
            marker, _ = self._parse_nxc_line(raw_line.strip())
            if marker in ("[+]", "[-]", "[*]", "[!]"):
                return "credential_response"

        return "ambiguous"

    def _format_stderr_block(self, stderr: str, fallback_marker: str) -> str | None:
        """Convert stderr lines to parseable status lines for result summary."""
        formatted: list[str] = []
        for raw_line in stderr.split("\n"):
            line = raw_line.strip()
            if not line:
                continue
            marker, msg = self._parse_nxc_line(line)
            if marker in ("[+]", "[-]", "[!]"):
                formatted.append(f"{marker} {msg}")
            else:
                formatted.append(f"{fallback_marker} {line}")
        return "\n".join(formatted) if formatted else None

    def _run_protocol_task(self, protocol: str, target: str, local_auth: bool = False) -> list[str]:
        """Run all credential pairs for one protocol/auth-type, return captured output."""
        output_lines: list[str] = []
        timeout_count = 0
        total_per_task = len(self.credential_pairs)
        ran = 0
        for user, password in self.credential_pairs:
            cmd = self._build_nxc_command(protocol, target, user, password, local_auth)
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=SUBPROCESS_TIMEOUT)
                stdout = (result.stdout or "").strip()
                stderr = (result.stderr or "").strip()
                classification = self._classify_attempt_output(stdout, stderr)

                if stdout:
                    output_lines.append(stdout)
                    self._report_success_lines(stdout, protocol, local_auth)

                # stderr often carries connection errors; include it when stdout is empty
                # or when we classified this attempt as a connectivity timeout.
                if stderr and (not stdout or classification == "connectivity_timeout"):
                    marker = "[!]" if classification == "connectivity_timeout" else "[-]"
                    stderr_block = self._format_stderr_block(stderr, marker)
                    if stderr_block:
                        output_lines.append(stderr_block)

                if classification == "connectivity_timeout":
                    timeout_count += 1
                else:
                    timeout_count = 0
            except subprocess.TimeoutExpired:
                timeout_count += 1

            ran += 1
            self._update_progress()

            if timeout_count >= MAX_RETRY:
                # Skip remaining credentials for this protocol after repeated timeouts.
                output_lines.append(f"[!] {MAX_RETRY} consecutive timeouts — skipped")
                label = self._task_label(protocol, local_auth)
                self._print_live(
                    f"  {YELLOW}⏱ {label}{RESET} {DIM}{MAX_RETRY} consecutive timeouts — skipping{RESET}"
                )
                remaining = total_per_task - ran
                if remaining > 0:
                    self._skip_progress(remaining)
                break
        return output_lines

    @staticmethod
    def _parse_nxc_line(line: str) -> tuple[str | None, str]:
        """Extract status marker and message from nxc output.

        'SMB  10.x.x.x  445  DC01  [+] dom\\user:pass' -> ('[+]', 'dom\\user:pass')
        """
        for marker in ("[+]", "[-]", "[*]", "[!]"):
            idx = line.find(marker)
            if idx != -1:
                return marker, line[idx + 4:].strip()
        return None, line.strip()

    @staticmethod
    def _extract_target_info(results: dict) -> str | None:
        """Get first [*] info line to display target OS/host details once."""
        for blocks in results.values():
            for block in blocks:
                for line in block.split("\n"):
                    if "[*]" in line:
                        idx = line.find("[*]")
                        return line[idx + 4:].strip()
        return None

    def _print_scan_banner(self, total_attempts: int):
        print(f"\n{BOLD}{'═' * BANNER_WIDTH}{RESET}")
        print(f"  {CYAN}{BOLD}⚡ NetExec Automator{RESET}")
        print(f"{'═' * BANNER_WIDTH}")
        print(f"  Targets Count   {DIM}│{RESET} {BOLD}{len(self.targets):<11}{RESET} Protocols {DIM}│{RESET} {BOLD}{len(ALL_PROTOCOLS)}{RESET} (+ local auth)")
        print(f"  Users Count     {DIM}│{RESET} {BOLD}{len(self.users):<11}{RESET} Workers   {DIM}│{RESET} {BOLD}{self.workers}{RESET}")
        print(f"  Passwords Count {DIM}│{RESET} {BOLD}{len(self.passwords):<11}{RESET} Timeout   {DIM}│{RESET} {BOLD}30s{RESET}/attempt")
        print(f"  Pairing Mode    {DIM}│{RESET} {BOLD}{self.mode.upper():<11}{RESET} Log File  {DIM}│{RESET} {BOLD}{self.log_file}{RESET}")
        print(f"  Total Tasks     {DIM}│{RESET} {BOLD}{total_attempts}{RESET}")
        print(f"{'═' * BANNER_WIDTH}\n")

    def _collect_target_results(self, target: str, tasks: list[TaskKey], pair_count: int) -> dict[TaskKey, list[str]]:
        self.completed = 0
        self.total_tasks = len(tasks) * pair_count
        results: dict[TaskKey, list[str]] = {}

        # Each future handles one protocol/auth scope task and runs all credentials sequentially.
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures: dict = {}
            for protocol, local_auth in tasks:
                fut = pool.submit(self._run_protocol_task, protocol, target, local_auth)
                futures[fut] = (protocol, local_auth)

            for future in as_completed(futures):
                key = futures[future]
                try:
                    results[key] = future.result()
                except Exception as exc:
                    results[key] = [f"[!] Error: {exc}"]
        return results

    def _print_target_results(self, results: dict[TaskKey, list[str]], tasks: list[TaskKey]):
        target_info = self._extract_target_info(results)

        print(f"\n{'─' * BANNER_WIDTH}")
        print(f"  {CYAN}{BOLD}📋 NetExec Automator Results{RESET}")
        print(f"{'─' * BANNER_WIDTH}")

        if target_info:
            print(f"    {DIM}{target_info}{RESET}")
        print()

        successes: list[tuple[str, str]] = []
        # Track no-response by protocol name so domain/local variants collapse into one line.
        no_output_protos: set[str] = set()

        for protocol, local_auth in tasks:
            key = (protocol, local_auth)
            label = self._task_label(protocol, local_auth)
            blocks = results.get(key, [])

            if not blocks:
                no_output_protos.add(protocol.upper())
                continue

            # Keep only user-facing status lines from raw nxc output.
            parsed = self._parse_status_blocks(blocks)

            if not parsed:
                no_output_protos.add(protocol.upper())
                continue

            icon = self._status_icon(parsed)

            for i, (marker, msg) in enumerate(parsed):
                if i == 0:
                    prefix = f"  {icon} {BOLD}{label:<20}{RESET}"
                else:
                    prefix = f"      {'':<20}"

                if marker == "[+]":
                    print(f"{prefix} {GREEN}{msg}{RESET}")
                    successes.append((label, msg))
                elif marker == "[-]":
                    print(f"{prefix} {DIM}{msg}{RESET}")
                elif marker == "[!]":
                    print(f"{prefix} {YELLOW}{msg}{RESET}")

        if no_output_protos:
            ordered = [p for p in ALL_PROTOCOLS if p.upper() in no_output_protos]
            names = ", ".join(p.upper() for p in ordered)
            print(f"\n  {DIM}── No response: {names}{RESET}")

        print(f"\n{'─' * BANNER_WIDTH}")

        if successes:
            print(f"\n  {GREEN}{BOLD}✓ VALID CREDENTIALS{RESET}\n")
            for label, msg in successes:
                print(f"    {GREEN}►{RESET} {BOLD}{label:<20}{RESET} {DIM}│{RESET} {msg}")
            print()
        else:
            print(f"\n  {RED}{BOLD}✗ No valid credentials found.{RESET}\n")

        print(f"{'═' * BANNER_WIDTH}\n")

    def run(self):
        task_count = len(ALL_PROTOCOLS) + len(LOCAL_AUTH_PROTOCOLS)
        pair_count = len(self.credential_pairs)
        total_attempts = len(self.targets) * pair_count * task_count

        self._print_scan_banner(total_attempts)

        for target in self.targets:
            print(f"  {GREEN}{BOLD}► {target}{RESET}\n")

            tasks = self._build_protocol_tasks()
            results = self._collect_target_results(target, tasks, pair_count)

            sys.stderr.write("\r" + " " * PROGRESS_CLEAR_WIDTH + "\r")
            sys.stderr.flush()
            self._print_target_results(results, tasks)


def parse_mode(value: str) -> str:
    """Validate accepted mode values."""
    mode = value.lower()
    if mode in ("combination", "linear"):
        return mode
    raise argparse.ArgumentTypeError("Mode must be one of: combination, linear")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run nxc across all protocols with combination or linear credential pairing."
    )
    parser.add_argument("-t", "--target", required=True, help="Target IP/hostname or path to targets.txt")
    parser.add_argument("-u", "--user", required=True, help="Username or path to users.txt")
    parser.add_argument("-p", "--password", required=True, help="Password or path to passwords.txt")
    parser.add_argument("-o", "--output", help="Custom log file path (default: HH-MM-SS-mmm.txt)")
    parser.add_argument("-w", "--workers", type=int, default=DEFAULT_WORKERS,
                        help=f"Number of parallel threads (default: {DEFAULT_WORKERS})")
    parser.add_argument(
        "-m", "--mode",
        type=parse_mode,
        default="combination",
        metavar="{combination,linear}",
        help="Credential pairing mode: combination (all combinations) or linear (index-matched pairs).",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    try:
        runner = NxcAutomator(
            target=args.target,
            user=args.user,
            password=args.password,
            output=args.output,
            workers=args.workers,
            mode=args.mode,
        )
        runner.run()
    except ValueError as exc:
        print(f"{RED}{BOLD}Error:{RESET} {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
