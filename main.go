package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
)

// ─── Colors ───────────────────────────────────────────────────────────────────

const (
	colRed    = "\033[91m"
	colYellow = "\033[93m"
	colBlue   = "\033[94m"
	colWhite  = "\033[97m"
	colReset  = "\033[0m"
)

var sevColor = map[string]string{
	"CRITICAL": colRed,
	"HIGH":     colYellow,
	"MEDIUM":   colBlue,
	"INFO":     colWhite,
}
var sevOrder = map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}

func colorize(sev, text string) string {
	if c, ok := sevColor[sev]; ok {
		return c + text + colReset
	}
	return text
}

// ─── Types ────────────────────────────────────────────────────────────────────

type Finding struct {
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
}

type Credential struct {
	User     string `json:"user"`
	Password string `json:"pass"`
}

type TableEntry struct {
	Table      string `json:"table"`
	Type       string `json:"type"`
	Privileges string `json:"privileges"`
}

// DBTree: database → schema → tables
type DBTree map[string]map[string][]TableEntry

// ReconData: query key → rows
type ReconData map[string][][]interface{}

type HostResult struct {
	Host        string                 `json:"host"`
	Port        int                    `json:"port"`
	Open        bool                   `json:"open"`
	Credentials []Credential           `json:"credentials"`
	Recon       map[string]ReconData   `json:"recon"`
	Enumeration map[string]DBTree      `json:"enumeration"`
	Findings    []Finding              `json:"findings"`
}

type scanTarget struct {
	host string
	port int
}

// ─── Recon queries ────────────────────────────────────────────────────────────

type reconEntry struct{ key, sql string }

var reconQueries = []reconEntry{
	{"version", "SELECT version()"},
	{"current_user", "SELECT current_user"},
	{"session_user", "SELECT session_user"},
	{"is_superuser", "SELECT usesuper FROM pg_user WHERE usename = current_user"},
	{"databases", "SELECT datname FROM pg_database ORDER BY datname"},
	{"schemas", "SELECT schema_name FROM information_schema.schemata ORDER BY schema_name"},
	{"roles", "SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolcanlogin FROM pg_roles ORDER BY rolname"},
	{"extensions", "SELECT extname, extversion FROM pg_extension ORDER BY extname"},
	{"config_file", "SHOW config_file"},
	{"hba_file", "SHOW hba_file"},
	{"data_directory", "SHOW data_directory"},
	{"ssl", "SHOW ssl"},
	{"log_connections", "SHOW log_connections"},
	{"log_hostname", "SHOW log_hostname"},
	{"listen_addresses", "SHOW listen_addresses"},
}

// ─── Privesc checks ───────────────────────────────────────────────────────────

type privescCheck struct {
	id         string
	title      string
	severity   string
	sql        string
	execOnly   bool
	vulnerable func(rows [][]interface{}, err error) bool
	detail     string
}

var privescChecks = []privescCheck{
	{
		id: "SUPER_USER", severity: "CRITICAL",
		title: "Session has superuser privileges",
		sql:   "SELECT usesuper FROM pg_user WHERE usename = current_user",
		vulnerable: func(rows [][]interface{}, err error) bool {
			return err == nil && len(rows) > 0 && rows[0][0] == true
		},
		detail: "This account is a PostgreSQL superuser — full DB and OS-level access possible.",
	},
	{
		id: "PG_SHADOW_READABLE", severity: "CRITICAL",
		title:      "pg_shadow (password hashes) readable",
		sql:        "SELECT usename, passwd FROM pg_shadow LIMIT 1",
		vulnerable: func(_ [][]interface{}, err error) bool { return err == nil },
		detail:     "Can read pg_shadow — password hashes exposed. Offline cracking possible.",
	},
	{
		id: "COPY_PROGRAM", severity: "CRITICAL",
		title:      "COPY TO/FROM PROGRAM (OS command execution) available",
		sql:        "COPY (SELECT 1) TO PROGRAM 'id'",
		execOnly:   true,
		vulnerable: func(_ [][]interface{}, err error) bool { return err == nil },
		detail:     "COPY TO PROGRAM executes OS commands as the postgres OS user.",
	},
	{
		id: "PG_READ_SERVER_FILES", severity: "HIGH",
		title:      "pg_read_server_files role or superuser file read",
		sql:        "SELECT pg_read_file('/etc/hostname')",
		vulnerable: func(_ [][]interface{}, err error) bool { return err == nil },
		detail:     "Can read arbitrary server-side files via pg_read_file().",
	},
	{
		id: "PG_EXECUTE_SERVER_PROGRAM", severity: "HIGH",
		title: "pg_execute_server_program privilege",
		sql:   "SELECT pg_catalog.pg_has_role(current_user, 'pg_execute_server_program', 'USAGE')",
		vulnerable: func(rows [][]interface{}, err error) bool {
			return err == nil && len(rows) > 0 && rows[0][0] == true
		},
		detail: "Role allows executing server-side programs via COPY PROGRAM.",
	},
	{
		id: "PG_WRITE_SERVER_FILES", severity: "HIGH",
		title: "pg_write_server_files privilege (arbitrary file write)",
		sql:   "SELECT pg_catalog.pg_has_role(current_user, 'pg_write_server_files', 'USAGE')",
		vulnerable: func(rows [][]interface{}, err error) bool {
			return err == nil && len(rows) > 0 && rows[0][0] == true
		},
		detail: "Role allows writing arbitrary files on the server.",
	},
	{
		id: "CREATEROLE", severity: "HIGH",
		title: "CREATEROLE privilege (role escalation)",
		sql:   "SELECT rolcreaterole FROM pg_roles WHERE rolname = current_user",
		vulnerable: func(rows [][]interface{}, err error) bool {
			return err == nil && len(rows) > 0 && rows[0][0] == true
		},
		detail: "Can create roles including granting membership in existing high-privilege roles.",
	},
	{
		id: "CREATEDB", severity: "MEDIUM",
		title: "CREATEDB privilege",
		sql:   "SELECT rolcreatedb FROM pg_roles WHERE rolname = current_user",
		vulnerable: func(rows [][]interface{}, err error) bool {
			return err == nil && len(rows) > 0 && rows[0][0] == true
		},
		detail: "Can create databases — may expose data or enable lateral movement.",
	},
	{
		id: "SECURITY_DEFINER_FUNCS", severity: "MEDIUM",
		title: "SECURITY DEFINER functions accessible to current user",
		sql: `SELECT routine_name, routine_schema FROM information_schema.routines
WHERE security_type = 'DEFINER'
  AND routine_schema NOT IN ('pg_catalog','information_schema') LIMIT 20`,
		vulnerable: func(rows [][]interface{}, err error) bool {
			return err == nil && len(rows) > 0
		},
		detail: "SECURITY DEFINER functions run with the owner's privileges — potential escalation if misconfigured.",
	},
	{
		id: "EXTENSION_CREATE", severity: "MEDIUM",
		title: "Can CREATE EXTENSION (potential for untrusted extension load)",
		sql:  "SELECT has_database_privilege(current_database(), 'CREATE')",
		vulnerable: func(rows [][]interface{}, err error) bool {
			return err == nil && len(rows) > 0 && rows[0][0] == true
		},
		detail: "CREATE privilege on database may allow loading extensions depending on superuser config.",
	},
	{
		id: "LARGE_OBJECT_READ", severity: "HIGH",
		title:      "Large Object file read (lo_import)",
		sql:        "SELECT lo_import('/etc/hostname') AS oid",
		vulnerable: func(_ [][]interface{}, err error) bool { return err == nil },
		detail:     "lo_import reads server-side files into large objects — potential data exfil path.",
	},
}

// ─── DB helpers ───────────────────────────────────────────────────────────────

func dbConnect(host string, port int, user, password, dbname string, timeout time.Duration) (*pgx.Conn, error) {
	cfg, err := pgx.ParseConfig(fmt.Sprintf(
		"host=%s port=%d dbname=%s sslmode=prefer",
		host, port, dbname,
	))
	if err != nil {
		return nil, err
	}
	cfg.User = user
	cfg.Password = password

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return pgx.ConnectConfig(ctx, cfg)
}

func runQuery(conn *pgx.Conn, sql string) ([][]interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rows, err := conn.Query(ctx, sql)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result [][]interface{}
	for rows.Next() {
		vals, err := rows.Values()
		if err != nil {
			continue
		}
		result = append(result, vals)
	}
	return result, rows.Err()
}

func execQuery(conn *pgx.Conn, sql string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := conn.Exec(ctx, sql)
	return err
}

func closeConn(conn *pgx.Conn) {
	conn.Close(context.Background())
}

// ─── Recon ────────────────────────────────────────────────────────────────────

func collectRecon(conn *pgx.Conn) ReconData {
	data := make(ReconData)
	for _, q := range reconQueries {
		rows, err := runQuery(conn, q.sql)
		if err == nil {
			data[q.key] = rows
		}
	}
	return data
}

// ─── Privesc ──────────────────────────────────────────────────────────────────

func checkPrivesc(conn *pgx.Conn) []Finding {
	var findings []Finding
	for _, chk := range privescChecks {
		var rows [][]interface{}
		var err error
		if chk.execOnly {
			err = execQuery(conn, chk.sql)
		} else {
			rows, err = runQuery(conn, chk.sql)
		}
		if chk.vulnerable(rows, err) {
			findings = append(findings, Finding{
				Severity: chk.severity,
				Title:    chk.title,
				Detail:   chk.detail,
			})
		}
	}
	return findings
}

// ─── Enumeration ──────────────────────────────────────────────────────────────

func enumerateAccess(host string, port int, user, password string, timeout time.Duration) DBTree {
	conn, err := dbConnect(host, port, user, password, "postgres", timeout)
	if err != nil {
		return nil
	}
	dbRows, err := runQuery(conn, `
		SELECT datname FROM pg_database
		WHERE has_database_privilege(current_user, datname, 'CONNECT')
		  AND datname NOT IN ('template0','template1')
		ORDER BY datname`)
	closeConn(conn)
	if err != nil || len(dbRows) == 0 {
		return nil
	}

	tree := make(DBTree)
	for _, row := range dbRows {
		dbname, _ := row[0].(string)
		dbConn, err := dbConnect(host, port, user, password, dbname, timeout)
		if err != nil {
			tree[dbname] = map[string][]TableEntry{"_error": nil}
			continue
		}
		tableRows, _ := runQuery(dbConn, `
			SELECT
				t.table_schema,
				t.table_name,
				t.table_type,
				array_to_string(
					ARRAY(
						SELECT privilege_type
						FROM information_schema.role_table_grants g
						WHERE g.table_schema = t.table_schema
						  AND g.table_name   = t.table_name
						  AND g.grantee IN (current_user, 'PUBLIC')
					), ', '
				) AS privileges
			FROM information_schema.tables t
			WHERE t.table_schema NOT IN ('pg_catalog','information_schema','pg_toast')
			  AND has_table_privilege(current_user,
				quote_ident(t.table_schema)||'.'||quote_ident(t.table_name), 'SELECT')
			ORDER BY t.table_schema, t.table_name`)
		closeConn(dbConn)

		schemas := make(map[string][]TableEntry)
		for _, tr := range tableRows {
			schema, _ := tr[0].(string)
			tname, _ := tr[1].(string)
			ttype, _ := tr[2].(string)
			privs, _ := tr[3].(string)
			schemas[schema] = append(schemas[schema], TableEntry{
				Table: tname, Type: ttype, Privileges: privs,
			})
		}
		tree[dbname] = schemas
	}
	return tree
}

// ─── Scanner ──────────────────────────────────────────────────────────────────

func isPortOpen(host string, port int, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// trustCanaryPass returns a random password unlikely to collide with any real
// password in the wordlist or set on the server.
func trustCanaryPass() string {
	return fmt.Sprintf("nx_%016x", rand.Int63())
}

func scanHost(ctx context.Context, host string, port int, creds []Credential, credThreads int, timeout time.Duration, doEnum bool) HostResult {
	res := HostResult{
		Host:        host,
		Port:        port,
		Recon:       make(map[string]ReconData),
		Enumeration: make(map[string]DBTree),
	}

	if !isPortOpen(host, port, timeout) {
		return res
	}
	res.Open = true

	// Unique users in the order they appear in the credentials list.
	var userOrder []string
	seenUser := make(map[string]bool)
	for _, c := range creds {
		if !seenUser[c.User] {
			seenUser[c.User] = true
			userOrder = append(userOrder, c.User)
		}
	}

	var foundMu sync.Mutex
	found := make(map[string]bool)         // user → already cracked (skip further attempts)
	foundCred := make(map[string]Credential) // user → credential for Phase 2 recon

	// Phase 0: per-user trust-auth canary. For each user, try one random password.
	// If it authenticates, the server is not validating the password for that user
	// (typically 'trust' in pg_hba.conf, or an unset password hash). Record the
	// user and skip the password loop for them — testing the wordlist would
	// otherwise produce a flood of bogus 'valid credential' entries.
	var trustUsers []string
	{
		var wg sync.WaitGroup
		sem := make(chan struct{}, credThreads)
		for _, u := range userOrder {
			if ctx.Err() != nil {
				break
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(user string) {
				defer wg.Done()
				defer func() { <-sem }()
				if ctx.Err() != nil {
					return
				}
				conn, err := dbConnect(host, port, user, trustCanaryPass(), "postgres", timeout)
				if err != nil {
					return
				}
				conn.Close(context.Background())
				foundMu.Lock()
				found[user] = true
				foundCred[user] = Credential{User: user, Password: "<trust>"}
				trustUsers = append(trustUsers, user)
				foundMu.Unlock()
			}(u)
		}
		wg.Wait()
	}

	if len(trustUsers) > 0 {
		sort.Strings(trustUsers)
		res.Findings = append(res.Findings, Finding{
			Severity: "CRITICAL",
			Title:    "User(s) accept any password — trust authentication misconfiguration",
			Detail:   fmt.Sprintf("Random passwords were accepted for: %s. The server is not validating passwords for these users (typically 'trust' in pg_hba.conf, or an unset password hash). Anyone with network access can authenticate as these roles. Password bruteforce was skipped for them to avoid producing misleading 'valid credential' lists.", strings.Join(trustUsers, ", ")),
		})
	}

	// Phase 1: standard credential test, skipping users already cracked in Phase 0.
	// Stop probing a user once one password works (avoids redundant work and
	// account lockout on hardened servers).
	var credWg sync.WaitGroup
	credSem := make(chan struct{}, credThreads)
	for _, cred := range creds {
		if ctx.Err() != nil {
			break
		}
		foundMu.Lock()
		already := found[cred.User]
		foundMu.Unlock()
		if already {
			continue
		}

		credWg.Add(1)
		credSem <- struct{}{}
		go func(c Credential) {
			defer credWg.Done()
			defer func() { <-credSem }()

			foundMu.Lock()
			already := found[c.User]
			foundMu.Unlock()
			if already || ctx.Err() != nil {
				return
			}

			conn, err := dbConnect(host, port, c.User, c.Password, "postgres", timeout)
			if err != nil {
				return
			}
			conn.Close(context.Background())

			foundMu.Lock()
			if found[c.User] {
				foundMu.Unlock()
				return
			}
			found[c.User] = true
			foundCred[c.User] = c
			foundMu.Unlock()
		}(cred)
	}
	credWg.Wait()

	// Phase 2: recon + privesc for each cracked user (trust or password-found).
	// Iterate userOrder for deterministic output.
	for _, u := range userOrder {
		if ctx.Err() != nil {
			break
		}
		cred, ok := foundCred[u]
		if !ok {
			continue
		}
		// For trust users, the canary used a random password — connect with empty
		// (any password works for them).
		connPass := cred.Password
		if connPass == "<trust>" {
			connPass = ""
		}
		conn, err := dbConnect(host, port, u, connPass, "postgres", timeout)
		if err != nil {
			continue
		}
		res.Credentials = append(res.Credentials, cred)
		label := u + "@" + cred.Password
		res.Recon[label] = collectRecon(conn)
		res.Findings = append(res.Findings, checkPrivesc(conn)...)
		closeConn(conn)
		if doEnum {
			res.Enumeration[label] = enumerateAccess(host, port, u, connPass, timeout)
		}
	}
	return res
}

// ─── Output ───────────────────────────────────────────────────────────────────

func sortedFindings(findings []Finding) []Finding {
	sorted := make([]Finding, len(findings))
	copy(sorted, findings)
	sort.Slice(sorted, func(i, j int) bool {
		return sevOrder[sorted[i].Severity] < sevOrder[sorted[j].Severity]
	})
	return sorted
}

func isSuperuserResult(r HostResult) bool {
	for _, recon := range r.Recon {
		if rows, ok := recon["is_superuser"]; ok && len(rows) > 0 && rows[0][0] == true {
			return true
		}
	}
	return false
}

func printResult(r HostResult, verbose bool) {
	target := fmt.Sprintf("%s:%d", r.Host, r.Port)

	if !r.Open {
		if verbose {
			fmt.Printf("  [-] %s  port closed / filtered\n", target)
		}
		return
	}
	if len(r.Credentials) == 0 {
		if verbose {
			fmt.Printf("  [ ] %s  open — no valid credentials found\n", target)
		}
		return
	}

	if verbose {
		printResultVerbose(r, target)
	} else {
		printResultCompact(r, target)
	}
}

// printResultCompact prints one block per compromised host: creds, version, superuser,
// databases, and the findings list (no detail text).
func printResultCompact(r HostResult, target string) {
	su := isSuperuserResult(r)
	if su {
		fmt.Printf("\n%s[+] %s  *** SUPERUSER ***%s\n", colRed, target, colReset)
	} else {
		fmt.Printf("\n[+] %s\n", target)
	}

	for _, c := range r.Credentials {
		credStr := fmt.Sprintf("%s / %s", c.User, c.Password)
		if su {
			credStr = colorize("CRITICAL", credStr)
		}
		fmt.Printf("    cred      : %s\n", credStr)
	}

	// Pull first recon entry (one per unique working credential)
	for _, recon := range r.Recon {
		if rows, ok := recon["version"]; ok && len(rows) > 0 {
			v := fmt.Sprintf("%v", rows[0][0])
			if len(v) > 80 {
				v = v[:80]
			}
			fmt.Printf("    version   : %s\n", v)
		}
		if rows, ok := recon["is_superuser"]; ok && len(rows) > 0 {
			suStr := "no"
			if rows[0][0] == true {
				suStr = colorize("CRITICAL", "YES")
			}
			fmt.Printf("    superuser : %s\n", suStr)
		}
		if rows, ok := recon["databases"]; ok {
			var dbs []string
			for _, row := range rows {
				dbs = append(dbs, fmt.Sprintf("%v", row[0]))
			}
			fmt.Printf("    databases : %s\n", strings.Join(dbs, ", "))
		}
		break // compact shows one credential's recon only
	}

	if len(r.Findings) == 0 {
		fmt.Printf("    findings  : none\n")
		return
	}
	for _, f := range sortedFindings(r.Findings) {
		fmt.Printf("    %s %s\n", colorize(f.Severity, "["+f.Severity+"]"), f.Title)
	}
}

// printResultVerbose prints the full recon, enumeration, and findings with detail text.
func printResultVerbose(r HostResult, target string) {
	sep := strings.Repeat("=", 70)
	su := isSuperuserResult(r)
	header := "COMPROMISED"
	if su {
		header = colorize("CRITICAL", "COMPROMISED — SUPERUSER")
	}
	fmt.Printf("\n%s\n  [+] %s  %s\n%s\n", sep, target, header, sep)

	for _, c := range r.Credentials {
		credStr := fmt.Sprintf("%s / %s", c.User, c.Password)
		if su {
			credStr = colorize("CRITICAL", credStr)
		}
		fmt.Printf("      Credential: %s\n", credStr)
	}

	for label, recon := range r.Recon {
		user := strings.SplitN(label, "@", 2)[0]
		fmt.Printf("\n  --- Recon (%s) ---\n", user)

		if rows, ok := recon["version"]; ok && len(rows) > 0 {
			v := fmt.Sprintf("%v", rows[0][0])
			if len(v) > 80 {
				v = v[:80]
			}
			fmt.Printf("    Version       : %s\n", v)
		}
		if rows, ok := recon["current_user"]; ok && len(rows) > 0 {
			fmt.Printf("    Current user  : %v\n", rows[0][0])
		}
		if rows, ok := recon["is_superuser"]; ok && len(rows) > 0 {
			su := rows[0][0] == true
			suStr := "no"
			if su {
				suStr = colorize("CRITICAL", "YES")
			}
			fmt.Printf("    Superuser     : %s\n", suStr)
		}
		if rows, ok := recon["databases"]; ok {
			var dbs []string
			for _, row := range rows {
				dbs = append(dbs, fmt.Sprintf("%v", row[0]))
			}
			fmt.Printf("    Databases     : %s\n", strings.Join(dbs, ", "))
		}
		if rows, ok := recon["extensions"]; ok {
			var exts []string
			for _, row := range rows {
				exts = append(exts, fmt.Sprintf("%v", row[0]))
			}
			if len(exts) == 0 {
				fmt.Printf("    Extensions    : none\n")
			} else {
				fmt.Printf("    Extensions    : %s\n", strings.Join(exts, ", "))
			}
		}
		if rows, ok := recon["ssl"]; ok && len(rows) > 0 {
			fmt.Printf("    SSL           : %v\n", rows[0][0])
		}
		if rows, ok := recon["listen_addresses"]; ok && len(rows) > 0 {
			fmt.Printf("    Listen addr   : %v\n", rows[0][0])
		}
	}

	// Enumeration
	for label, tree := range r.Enumeration {
		user := strings.SplitN(label, "@", 2)[0]
		fmt.Printf("\n  --- DB/Table Enumeration (%s) ---\n", user)
		if len(tree) == 0 {
			fmt.Println("    (no accessible databases)")
			continue
		}
		dbNames := make([]string, 0, len(tree))
		for db := range tree {
			dbNames = append(dbNames, db)
		}
		sort.Strings(dbNames)
		for _, dbname := range dbNames {
			schemas := tree[dbname]
			if _, errDB := schemas["_error"]; errDB {
				fmt.Printf("    [%s]  <connect failed>\n", dbname)
				continue
			}
			total := 0
			for _, tables := range schemas {
				total += len(tables)
			}
			fmt.Printf("    [%s]  %d accessible table(s)\n", dbname, total)
			schemaNames := make([]string, 0, len(schemas))
			for s := range schemas {
				schemaNames = append(schemaNames, s)
			}
			sort.Strings(schemaNames)
			for _, schema := range schemaNames {
				tables := schemas[schema]
				if len(tables) == 0 {
					continue
				}
				fmt.Printf("      schema: %s\n", schema)
				for _, t := range tables {
					ttype := "table"
					if t.Type == "VIEW" {
						ttype = "view"
					}
					privStr := ""
					if t.Privileges != "" {
						privStr = "  [" + t.Privileges + "]"
					}
					fmt.Printf("        %s  %s%s\n", ttype, t.Table, privStr)
				}
			}
		}
	}

	// Findings with detail
	if len(r.Findings) > 0 {
		fmt.Printf("\n  --- Privilege Escalation / Security Findings ---\n")
		for _, f := range sortedFindings(r.Findings) {
			fmt.Printf("    %s %s\n", colorize(f.Severity, "["+f.Severity+"]"), f.Title)
			fmt.Printf("           %s\n", f.Detail)
		}
	} else {
		fmt.Println("\n  No privesc vectors found for tested credentials.")
	}
}

// ─── Input parsing ────────────────────────────────────────────────────────────

func parsePorts(s string) []int {
	var ports []int
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if n, err := strconv.Atoi(p); err == nil {
			ports = append(ports, n)
		}
	}
	return ports
}

func loadTargets(path string, defaultPorts []int) ([]scanTarget, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	seen := make(map[string]bool)
	var targets []scanTarget
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var host string
		var ports []int
		if idx := strings.LastIndex(line, ":"); idx != -1 {
			host = line[:idx]
			ports = parsePorts(line[idx+1:])
		} else {
			host = line
			ports = defaultPorts
		}
		for _, port := range ports {
			key := fmt.Sprintf("%s:%d", host, port)
			if !seen[key] {
				seen[key] = true
				targets = append(targets, scanTarget{host, port})
			}
		}
	}
	return targets, sc.Err()
}

func loadWordlist(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var words []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		words = append(words, strings.TrimRight(line, "\r"))
	}
	return words, sc.Err()
}

// buildCredentials produces a password-first ordering: try password #1 against every
// user, then password #2, etc. This is the standard "password spray" pattern — it
// finds the most common credentials fastest across the user set and limits the
// per-user failure rate (lockout-friendly).
func buildCredentials(users, passwords []string) []Credential {
	creds := make([]Credential, 0, len(users)*len(passwords))
	for _, p := range passwords {
		for _, u := range users {
			creds = append(creds, Credential{u, p})
		}
	}
	return creds
}

// ─── Main ─────────────────────────────────────────────────────────────────────

func main() {
	hostsFile   := flag.String("hosts", "", "File with target hosts (host, host:port, or host:port1,port2)")
	usersFile   := flag.String("users", "", "File with one username per line")
	passwdFile  := flag.String("passwords", "", "File with one password per line")
	portsFlag   := flag.String("ports", "5432", "Default port(s) for hosts with no port specified (comma-separated)")
	threads     := flag.Int("threads", 10, "Concurrent goroutines (hosts in parallel)")
	credThreads := flag.Int("cred-threads", 16, "Concurrent credential attempts per host")
	timeoutSec := flag.Float64("timeout", 5, "Connection timeout in seconds")
	outputFile := flag.String("output", "", "Write JSON report to this file")
	doEnum     := flag.Bool("enumerate", false, "Enumerate accessible databases, schemas, and tables per credential")
	verbose    := flag.Bool("verbose", false, "Show finding details and closed hosts")
	flag.Parse()

	if *hostsFile == "" || *usersFile == "" || *passwdFile == "" {
		fmt.Fprintln(os.Stderr, "usage: pgblast --hosts FILE --users FILE --passwords FILE [options]")
		flag.PrintDefaults()
		os.Exit(1)
	}

	timeout := time.Duration(*timeoutSec * float64(time.Second))
	defaultPorts := parsePorts(*portsFlag)

	targets, err := loadTargets(*hostsFile, defaultPorts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Cannot read hosts file: %v\n", err)
		os.Exit(1)
	}
	users, err := loadWordlist(*usersFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Cannot read users file: %v\n", err)
		os.Exit(1)
	}
	passwords, err := loadWordlist(*passwdFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Cannot read passwords file: %v\n", err)
		os.Exit(1)
	}
	creds := buildCredentials(users, passwords)

	fmt.Printf("[*] pgblast — PostgreSQL Security Scanner\n")
	fmt.Printf("[*] Started   : %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Printf("[*] Targets   : %d host:port pair(s)\n", len(targets))
	fmt.Printf("[*] Users     : %d\n", len(users))
	fmt.Printf("[*] Passwords : %d\n", len(passwords))
	fmt.Printf("[*] Combos    : %d\n", len(creds))
	fmt.Printf("[*] Threads   : %d hosts / %d creds\n", *threads, *credThreads)
	fmt.Printf("[*] Timeout   : %.1fs\n", *timeoutSec)
	enumStr := "no"
	if *doEnum {
		enumStr = "yes"
	}
	fmt.Printf("[*] Enumerate : %s\n\n", enumStr)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		fmt.Fprintln(os.Stderr, "\n[!] Interrupted — finishing in-flight scans, partial results will be saved.")
	}()

	// Open the JSON Lines output file once and stream each host as it finishes.
	// The full HostResult slice is NOT retained in memory — only lightweight
	// summary state (counters + critical findings list) is kept. This keeps
	// memory flat across very large target lists.
	var jsonEnc *json.Encoder
	if *outputFile != "" {
		f, err := os.Create(*outputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Cannot open output file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		jsonEnc = json.NewEncoder(f)
		fmt.Printf("[*] JSON Lines report → %s\n\n", *outputFile)
	}

	type critHit struct {
		host string
		port int
		user string
		f    Finding
	}
	var (
		statsProcessed   int
		statsOpen        int
		statsCompromised int
		statsCriticals   []critHit
	)
	var mu sync.Mutex
	sem := make(chan struct{}, *threads)
	var wg sync.WaitGroup

	for _, t := range targets {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(t scanTarget) {
			defer wg.Done()
			defer func() { <-sem }()
			result := scanHost(ctx, t.host, t.port, creds, *credThreads, timeout, *doEnum)

			mu.Lock()
			statsProcessed++
			if result.Open {
				statsOpen++
			}
			if len(result.Credentials) > 0 {
				statsCompromised++
			}
			for label, recon := range result.Recon {
				if rows, ok := recon["is_superuser"]; ok && len(rows) > 0 && rows[0][0] == true {
					user := strings.SplitN(label, "@", 2)[0]
					statsCriticals = append(statsCriticals, critHit{result.Host, result.Port, user, Finding{
						Severity: "CRITICAL",
						Title:    "Superuser session — account has full database and OS-level access",
						Detail:   fmt.Sprintf("User '%s' authenticated as PostgreSQL superuser.", user),
					}})
				}
			}
			for _, f := range result.Findings {
				if f.Severity == "CRITICAL" {
					user := ""
					if len(result.Credentials) > 0 {
						user = result.Credentials[0].User
					}
					statsCriticals = append(statsCriticals, critHit{result.Host, result.Port, user, f})
				}
			}
			printResult(result, *verbose)
			if jsonEnc != nil {
				_ = jsonEnc.Encode(result)
			}
			mu.Unlock()
			// `result` goes out of scope here; the GC can reclaim its recon data.
		}(t)
	}
	wg.Wait()

	sep := strings.Repeat("=", 70)
	fmt.Printf("\n%s\n  SUMMARY\n%s\n", sep, sep)
	fmt.Printf("    Targets scanned  : %d\n", statsProcessed)
	fmt.Printf("    Port open        : %d\n", statsOpen)
	fmt.Printf("    Credentials hit  : %d\n", statsCompromised)
	fmt.Printf("    Critical findings: %d\n", len(statsCriticals))

	if len(statsCriticals) > 0 {
		fmt.Printf("\n%s\n  %s\n%s\n", sep, colorize("CRITICAL", "CRITICAL FINDINGS"), sep)
		for _, c := range statsCriticals {
			fmt.Printf("  %s:%d  (%s)\n", c.host, c.port, c.user)
			fmt.Printf("    %s %s\n", colorize("CRITICAL", "[CRITICAL]"), c.f.Title)
			fmt.Printf("    %s\n\n", c.f.Detail)
		}
	}

	fmt.Printf("[*] Done: %s\n", time.Now().Format("2006-01-02 15:04:05"))
}
