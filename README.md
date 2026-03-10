# NetExec Automator

**NetExec Automator** takes your targets, users, and passwords (single values or files) and blasts them across all 10 nxc protocols in parallel — with local auth variants included. Choose between **combination** (all user×password pairs) or **linear** (index-matched pairs) credential pairing. You get live hits as they come in, automatic timeout skipping, and a clean summary at the end.

![NetExec Automator Demo](assets/netexec-automator-demo.gif)

**Workflow: find creds → add to lists → re-scan → repeat.**

```bash
# Initial scan with known creds (combination mode — all user×password pairs)
python3 netexec-automator.py -t targets.txt -u users.txt -p passwords.txt

# Found svc_backup:Summer2025! in a config file? Add it and re-scan
echo 'svc_backup' >> users.txt
echo 'Summer2025!' >> passwords.txt
python3 netexec-automator.py -t targets.txt -u users.txt -p passwords.txt

# Have known user:password pairs? Use linear mode (1-to-1 index matching)
python3 netexec-automator.py -t targets.txt -u users.txt -p passwords.txt -m linear

# Got a new subnet? Add those targets and go again
echo '10.10.20.0/24' >> targets.txt
python3 netexec-automator.py -t targets.txt -u users.txt -p passwords.txt
```

## Features

- **10 protocols** — SMB, SSH, LDAP, FTP, WMI, WinRM, RDP, VNC, MSSQL, NFS
- **Local auth variants** — Automatically tests `--local-auth` for SMB, WMI, WinRM, RDP, MSSQL
- **Credential pairing modes** — `combination` (cartesian product, default) or `linear` (index-matched 1-to-1 pairs)
- **Parallel execution** — 15 concurrent workers by default (one per protocol/auth-type)
- **Live findings** — Valid credentials (`⚡`) and timeout skips (`⏱`) printed in real-time
- **Auto-skip** — Protocols that timeout consecutively are skipped to save time
- **Clean output** — Parsed nxc output, grouped by protocol, with a final credential summary
- **Progress bar** — Real-time tracking per individual nxc command
- **File input** — Accepts single values or newline-separated files for targets, users, and passwords

## Requirements

- Python 3.10+
- [NetExec](https://github.com/Pennyw0rth/NetExec) installed and available as `nxc` in PATH

## Usage

```bash
# Single target, single credential
python3 netexec-automator.py -t 10.10.10.1 -u admin -p 'Password123!'

# File-based inputs — the intended workflow
python3 netexec-automator.py -t targets.txt -u users.txt -p passwords.txt

# Linear mode — each user[i] paired only with password[i]
python3 netexec-automator.py -t targets.txt -u users.txt -p passwords.txt -m linear

# Custom output file and worker count
python3 netexec-automator.py -t 10.10.10.1 -u admin -p pass.txt -o results.txt -w 20
```

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `-t, --target` | Target IP/hostname or path to targets file | *required* |
| `-u, --user` | Username or path to users file | *required* |
| `-p, --password` | Password or path to passwords file | *required* |
| `-o, --output` | Custom log file path | `HH-MM-SS-mmm.txt` |
| `-w, --workers` | Number of parallel threads | `15` |
| `-m, --mode` | Credential pairing: `combination` (all pairs) or `linear` (index-matched) | `combination` |

## Output

The tool produces three sections:

### 1. Live Scan

Findings appear in real-time as protocols are tested:

```
  ► 10.10.10.1

  ⚡ SMB (domain) corp.local\admin:Password123!
  ⚡ LDAP (domain) corp.local\admin:Password123!
  ⏱ SSH (domain) 2 consecutive timeouts — skipping
```

### 2. Detailed Results

After scanning completes, all results are shown grouped by protocol:

```
────────────────────────────────────────────────────────────
  📋 NetExec Automator Results
────────────────────────────────────────────────────────────
    Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:corp.local)

  ✔ SMB (domain)         corp.local\admin:Password123!
  ✘ SMB (local)          DC01\admin:Password123! STATUS_LOGON_FAILURE
  ✔ LDAP (domain)        corp.local\admin:Password123!
  ⏱ SSH (domain)         2 consecutive timeouts — skipped

  ── No response: FTP, VNC, NFS
```

### 3. Summary

A clean list of only the valid credentials:

```
  ✓ VALID CREDENTIALS

    ► SMB (domain)         │ corp.local\admin:Password123!
    ► LDAP (domain)        │ corp.local\admin:Password123!
```

## Credential Pairing Modes

| Mode | Behavior | Example (2 users, 3 passwords) |
|------|----------|-------------------------------|
| `combination` | Cartesian product — every user tested with every password | 2 × 3 = **6 pairs** |
| `linear` | Index-matched — user[i] paired only with password[i] (lists must be equal length) | **not allowed** (lengths differ) |

**combination** (default) is ideal when you have separate wordlists. **linear** is useful when you have known `user:password` pairs (e.g. from a credential dump) and want to test each pair as-is.

## Configuration

Constants at the top of the script:

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_RETRY` | `2` | Consecutive timeouts before skipping a protocol |
| `NETEXEC_TIMEOUT` | `30` | nxc `--timeout` per connection attempt (seconds) |
| `SUBPROCESS_TIMEOUT` | `45` | Python-level safety timeout per nxc command (seconds) |
| `DEFAULT_WORKERS` | `15` | Thread pool size (10 protocols + 5 local auth) |

## Disclaimer

This tool is intended for authorized penetration testing and security assessments only. Always ensure you have explicit written permission before testing credentials against any target. Unauthorized access to computer systems is illegal.
