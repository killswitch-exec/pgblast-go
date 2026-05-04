# pgblast

Fast PostgreSQL security scanner written in Go. Performs credential bruteforcing across large target lists, post-auth reconnaissance, privilege escalation checks, and database/table enumeration.

## Install

```bash
git clone https://github.com/killswitch-exec/pgblast-go
cd pgblast-go
go build -o pgblast .
```

Requires Go 1.21+. Produces a single static binary with no runtime dependencies.

## Usage

```bash
./pgblast --hosts hosts.txt --users users.txt --passwords passwords.txt [options]
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `--hosts` | required | Target hosts file (see format below) |
| `--users` | required | Username wordlist, one per line |
| `--passwords` | required | Password wordlist, one per line |
| `--ports` | `5432` | Default port(s) for hosts with no port specified, comma-separated |
| `--threads` | `10` | Concurrent hosts scanned in parallel |
| `--cred-threads` | `16` | Concurrent credential attempts per host |
| `--timeout` | `5` | Connection timeout in seconds |
| `--enumerate` | off | Enumerate accessible databases, schemas, and tables per credential |
| `--output` | — | Stream full per-host results as JSON Lines (NDJSON) to this file |
| `--verbose` | off | Full recon output with finding details |

### Host file format

```
192.168.1.10              # scanned on --ports default
192.168.1.11:5432         # single port override
192.168.1.12:5432,5433    # multiple ports for this host
```

### Credential testing

- **Password-first order (spray pattern)** — each password is tried against every user before moving to the next password. Finds common credentials fastest and limits per-user failure rate.
- **Stop-on-success per user** — once any password works for a user, no further passwords are tried for that user. Avoids redundant work and account-lockout pressure on hardened servers.
- **Trust auth pre-check (Phase 0)** — before the cartesian credential test, each user is probed once with a random password. If a random password authenticates, the user has `trust` auth (or an unset password hash) and is recorded as a CRITICAL finding instead of polluting the output with bogus 'cracked' credentials.

## Examples

```bash
# Basic scan
./pgblast --hosts hosts.txt --users users.txt --passwords passwords.txt

# Scan multiple default ports with 200 hosts in parallel
./pgblast --hosts hosts.txt --users users.txt --passwords passwords.txt \
  --ports 5432,5433 --threads 200

# Large target list, medium wordlist
./pgblast --hosts hosts.txt --users users.txt --passwords passwords.txt \
  --threads 200 --cred-threads 8

# Full audit: enumerate tables and save JSON report
./pgblast --hosts hosts.txt --users users.txt --passwords passwords.txt \
  --enumerate --output report.json --verbose
```

### Tuning concurrency

Total in-flight sockets equals `--threads × --cred-threads` and must fit under your file-descriptor limit (`ulimit -n`).

| Scenario | `--threads` | `--cred-threads` |
|---|---|---|
| Huge host list, small wordlist | 300 | 4 |
| Huge host list, medium wordlist (~1k) | 200 | 8 |
| Huge host list, large wordlist (10k+) | 100 | 16 |
| Small host list, large wordlist | 10–20 | 32 |
| Stealth / lockout-sensitive | 50–100 | 2–4 |

PostgreSQL's default `max_connections` is 100, so keep `--cred-threads` well below that to avoid `too many clients already` errors. If you hit `socket: too many open files`, raise `ulimit -n` (e.g. `ulimit -n 65536`) before running.

## What it checks

### Reconnaissance (on every successful login)
- Server version, current user, superuser status
- Accessible databases, extensions
- SSL status, listen address, config file paths

### Authentication misconfiguration

| Severity | Check |
|---|---|
| CRITICAL | User accepts any password — `trust` auth in `pg_hba.conf` or unset password hash |

For users flagged with trust auth, the password loop is skipped. A random-password canary connection is used to detect the condition; recon and privesc still run as that user so the report reflects realistic exposure.

### Privilege escalation

| Severity | Check |
|---|---|
| CRITICAL | Superuser session |
| CRITICAL | `pg_shadow` readable — password hashes exposed |
| CRITICAL | `COPY TO/FROM PROGRAM` — OS command execution |
| HIGH | `pg_read_file()` — arbitrary server-side file read |
| HIGH | `pg_execute_server_program` role |
| HIGH | `pg_write_server_files` role — arbitrary file write |
| HIGH | `lo_import` / `lo_export` — large object file read/write |
| HIGH | `CREATEROLE` privilege — role escalation |
| MEDIUM | `CREATEDB` privilege |
| MEDIUM | `SECURITY DEFINER` functions accessible |
| MEDIUM | `CREATE` privilege on database — extension loading |

### Database enumeration (`--enumerate`)
- Databases the user can `CONNECT` to
- Schemas with `USAGE` privilege
- Tables and views with `SELECT` privilege and full privilege list

## Output

Default output is compact — one block per compromised host. Superuser sessions are highlighted in red. All critical findings are consolidated at the end of the run.

Use `--verbose` for full recon details, enumeration tree, and finding descriptions.

`--output FILE` streams one JSON object per host per line (NDJSON / JSON Lines) as scans complete. Memory stays flat — per-host data is dropped after print, so the scanner is safe to run against very large target lists. Convert to a single JSON array with `jq -s '.' FILE` if you need it.

## Disclaimer

For authorized penetration testing and security audits only.
