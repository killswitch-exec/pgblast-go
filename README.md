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
| `--threads` | `10` | Concurrent goroutines |
| `--timeout` | `5` | Connection timeout in seconds |
| `--enumerate` | off | Enumerate accessible databases, schemas, and tables per credential |
| `--output` | — | Write full results to a JSON file |
| `--verbose` | off | Full recon output with finding details |

### Host file format

```
192.168.1.10              # scanned on --ports default
192.168.1.11:5432         # single port override
192.168.1.12:5432,5433    # multiple ports for this host
```

Credentials are tested as a cartesian product — every username against every password.

## Examples

```bash
# Basic scan
./pgblast --hosts hosts.txt --users users.txt --passwords passwords.txt

# Scan multiple default ports with 200 goroutines
./pgblast --hosts hosts.txt --users users.txt --passwords passwords.txt \
  --ports 5432,5433 --threads 200

# Full audit: enumerate tables and save JSON report
./pgblast --hosts hosts.txt --users users.txt --passwords passwords.txt \
  --enumerate --output report.json --verbose
```

## What it checks

### Reconnaissance (on every successful login)
- Server version, current user, superuser status
- Accessible databases, extensions
- SSL status, listen address, config file paths

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

## Disclaimer

For authorized penetration testing and security audits only.
