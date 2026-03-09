#!/usr/bin/env python3

import argparse
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from threading import Lock

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
MAX_RETRY = 2
SUBPROCESS_TIMEOUT = 45
NETEXEC_TIMEOUT = 30
BANNER_WIDTH = 60

class NxcAutomator:
    """Run nxc across all protocols with single or file-based credentials."""

    def __init__(self, target: str, user: str, password: str, output: str | None = None, workers: int = DEFAULT_WORKERS):
        self.targets = self._read_lines(target) if os.path.isfile(target) else [target]
        self.users = self._read_lines(user) if os.path.isfile(user) else [user]
        self.passwords = self._read_lines(password) if os.path.isfile(password) else [password]
        self.workers = workers
        self.lock = Lock()
        self.completed = 0
        self.total_tasks = 0
        self.log_file = output if output else datetime.now().strftime("%H-%M-%S-%f")[:-3] + ".txt"

    @staticmethod
    def _read_lines(path: str) -> list[str]:
        with open(path) as f:
            return [line.strip() for line in f if line.strip()]

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
            sys.stderr.write("\r" + " " * 70 + "\r")
            sys.stderr.flush()
            print(msg, flush=True)
            self._redraw_progress()

    def _run_protocol_task(self, protocol: str, target: str, local_auth: bool = False) -> list[str]:
        """Run all user/password combos for one protocol/auth-type, return captured output."""
        output_lines: list[str] = []
        timeout_count = 0
        skipped = False
        total_per_task = len(self.users) * len(self.passwords)
        ran = 0
        for user in self.users:
            if skipped:
                break
            for password in self.passwords:
                cmd = ["nxc", protocol, target, "-u", user, "-p", password]
                if local_auth:
                    cmd.append("--local-auth")
                cmd.extend(["--timeout", str(NETEXEC_TIMEOUT), "--log", self.log_file])
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=SUBPROCESS_TIMEOUT)
                    stdout = result.stdout.strip()
                    if stdout:
                        output_lines.append(stdout)
                        timeout_count = 0
                        for raw_line in stdout.split("\n"):
                            marker, msg = self._parse_nxc_line(raw_line.strip())
                            if marker == "[+]":
                                auth = "local" if local_auth else "domain"
                                self._print_live(
                                    f"  {GREEN}{BOLD}⚡ {protocol.upper()} ({auth}){RESET} {GREEN}{msg}{RESET}"
                                )
                    else:
                        timeout_count += 1
                except subprocess.TimeoutExpired:
                    timeout_count += 1

                ran += 1
                self._update_progress()

                if timeout_count >= MAX_RETRY:
                    output_lines.append(f"[!] {MAX_RETRY} consecutive timeouts — skipped")
                    auth = "local" if local_auth else "domain"
                    self._print_live(
                        f"  {YELLOW}⏱ {protocol.upper()} ({auth}){RESET} {DIM}{MAX_RETRY} consecutive timeouts — skipping{RESET}"
                    )
                    remaining = total_per_task - ran
                    self._skip_progress(remaining)
                    skipped = True
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

    def run(self):
        task_count = len(ALL_PROTOCOLS) + len(LOCAL_AUTH_PROTOCOLS)
        total_combos = len(self.targets) * len(self.users) * len(self.passwords) * task_count

        print(f"\n{BOLD}{'═' * BANNER_WIDTH}{RESET}")
        print(f"  {CYAN}{BOLD}⚡ NetExec Automator{RESET}")
        print(f"{'═' * BANNER_WIDTH}")
        print(f"  Targets Count   {DIM}│{RESET} {BOLD}{len(self.targets):<11}{RESET}Protocols {DIM}│{RESET} {BOLD}{len(ALL_PROTOCOLS)}{RESET} (+ local auth)")
        print(f"  Users Count     {DIM}│{RESET} {BOLD}{len(self.users):<11}{RESET}Workers   {DIM}│{RESET} {BOLD}{self.workers}{RESET}")
        print(f"  Passwords Count {DIM}│{RESET} {BOLD}{len(self.passwords):<11}{RESET}Timeout   {DIM}│{RESET} {BOLD}30s{RESET}/attempt")
        print(f"  Total Tasks     {DIM}│{RESET} {BOLD}{total_combos:<11}{RESET}Log File  {DIM}│{RESET} {BOLD}{self.log_file}{RESET}")
        print(f"{'═' * BANNER_WIDTH}\n")

        for target in self.targets:
            print(f"  {GREEN}{BOLD}► {target}{RESET}\n")

            tasks: list[tuple[str, bool]] = []
            for protocol in ALL_PROTOCOLS:
                tasks.append((protocol, False))
                if protocol in LOCAL_AUTH_PROTOCOLS:
                    tasks.append((protocol, True))

            self.completed = 0
            self.total_tasks = len(tasks) * len(self.users) * len(self.passwords)
            results: dict[tuple[str, bool], list[str]] = {}

            with ThreadPoolExecutor(max_workers=self.workers) as pool:
                futures = {}
                for protocol, local_auth in tasks:
                    fut = pool.submit(self._run_protocol_task, protocol, target, local_auth)
                    futures[fut] = (protocol, local_auth)

                for future in as_completed(futures):
                    key = futures[future]
                    try:
                        results[key] = future.result()
                    except Exception as exc:
                        results[key] = [f"[!] Error: {exc}"]

            sys.stderr.write("\r" + " " * 70 + "\r")
            sys.stderr.flush()

            target_info = self._extract_target_info(results)

            print(f"\n{'─' * BANNER_WIDTH}")
            print(f"  {CYAN}{BOLD}📋 NetExec Automator Results{RESET}")
            print(f"{'─' * BANNER_WIDTH}")

            if target_info:
                print(f"    {DIM}{target_info}{RESET}")
            print()

            successes: list[tuple[str, str]] = []
            no_output_protos: set[str] = set()

            for protocol in ALL_PROTOCOLS:
                for local_auth in (False, True):
                    if local_auth and protocol not in LOCAL_AUTH_PROTOCOLS:
                        continue

                    key = (protocol, local_auth)
                    auth_label = "local" if local_auth else "domain"
                    label = f"{protocol.upper()} ({auth_label})"
                    blocks = results.get(key, [])

                    if not blocks:
                        no_output_protos.add(protocol.upper())
                        continue

                    parsed: list[tuple[str, str]] = []
                    for block in blocks:
                        for line in block.split("\n"):
                            line = line.strip()
                            if not line:
                                continue
                            marker, msg = self._parse_nxc_line(line)
                            if marker in ("[+]", "[-]", "[!]"):
                                parsed.append((marker, msg))

                    if not parsed:
                        no_output_protos.add(protocol.upper())
                        continue

                    has_success = any(m == "[+]" for m, _ in parsed)
                    has_skip = any(m == "[!]" for m, _ in parsed)

                    if has_success:
                        icon = f"{GREEN}✔{RESET}"
                    elif has_skip:
                        icon = f"{YELLOW}⏱{RESET}"
                    else:
                        icon = f"{RED}✘{RESET}"

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


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run nxc across all protocols with single or file-based credentials."
    )
    parser.add_argument("-t", "--target", required=True, help="Target IP/hostname or path to targets.txt")
    parser.add_argument("-u", "--user", required=True, help="Username or path to users.txt")
    parser.add_argument("-p", "--password", required=True, help="Password or path to passwords.txt")
    parser.add_argument("-o", "--output", help="Custom log file path (default: HH-MM-SS-mmm.txt)")
    parser.add_argument("-w", "--workers", type=int, default=DEFAULT_WORKERS,
                        help=f"Number of parallel threads (default: {DEFAULT_WORKERS})")
    return parser.parse_args()


def main():
    args = parse_args()
    runner = NxcAutomator(
        target=args.target,
        user=args.user,
        password=args.password,
        output=args.output,
        workers=args.workers,
    )
    runner.run()


if __name__ == "__main__":
    main()
