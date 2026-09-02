// Package db — открытие SQLite (modernc, без cgo) и схема БД.
package db

import (
	"database/sql"
	"log"

	_ "modernc.org/sqlite"
)

// Open открывает БД с включённым WAL и таймаутом блокировки.
func Open(path string) (*sql.DB, error) {
	dsn := path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(NORMAL)&_pragma=cache_size(-4000)" +
		"&_pragma=temp_store(MEMORY)&_pragma=mmap_size(268435456)&_pragma=foreign_keys(ON)"
	d, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if err := d.Ping(); err != nil {
		d.Close()
		return nil, err
	}
	return d, nil
}

const schema = `
CREATE TABLE IF NOT EXISTS users (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    username  TEXT UNIQUE NOT NULL,
    full_name TEXT,
    email     TEXT,
    role      TEXT DEFAULT 'user',
    password_hash TEXT NOT NULL,
    is_active INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS devices (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname    TEXT NOT NULL,
    ip_address  TEXT,
    mac_address TEXT,
    os_type     TEXT,
    status      TEXT DEFAULT 'unknown',
    owner_id    INTEGER REFERENCES users(id),
    last_seen   TEXT,
    created_at  TEXT DEFAULT (datetime('now')),
    cpu_usage     REAL DEFAULT 0,
    ram_usage     REAL DEFAULT 0,
    disk_usage    REAL DEFAULT 0,
    device_type   TEXT DEFAULT '',
    manufacturer  TEXT DEFAULT '',
    model         TEXT DEFAULT '',
    serial_number TEXT DEFAULT '',
    location      TEXT DEFAULT '',
    notes         TEXT DEFAULT '',
    employee_id   INTEGER REFERENCES employees(id)
);
CREATE TABLE IF NOT EXISTS departments (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT UNIQUE NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS employees (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name     TEXT NOT NULL,
    position      TEXT,
    email         TEXT,
    phone         TEXT,
    department_id INTEGER REFERENCES departments(id),
    is_active     INTEGER DEFAULT 1,
    notes         TEXT,
    created_at    TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER,
    action     TEXT NOT NULL,
    target     TEXT,
    detail     TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS metrics_history (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id  INTEGER NOT NULL REFERENCES devices(id),
    ts         TEXT DEFAULT (datetime('now')),
    cpu_usage  REAL,
    ram_usage  REAL,
    disk_usage REAL
);
CREATE INDEX IF NOT EXISTS idx_metrics_device_ts ON metrics_history(device_id, ts);
CREATE TABLE IF NOT EXISTS events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id  INTEGER REFERENCES devices(id),
    hostname   TEXT,
    ts         TEXT DEFAULT (datetime('now')),
    source     TEXT,
    event_id   INTEGER,
    severity   TEXT DEFAULT 'info',
    category   TEXT,
    message    TEXT,
    detail     TEXT,
    status     TEXT DEFAULT 'new',
    assignee   TEXT,
    note       TEXT,
    updated_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_device_ts ON events(device_id, ts);
CREATE TABLE IF NOT EXISTS software (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id    INTEGER NOT NULL,
    name         TEXT,
    version      TEXT,
    install_date TEXT
);
CREATE INDEX IF NOT EXISTS idx_software_device ON software(device_id);
CREATE TABLE IF NOT EXISTS device_changes (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL,
    ts        TEXT DEFAULT (datetime('now')),
    field     TEXT,
    old_value TEXT,
    new_value TEXT
);
CREATE INDEX IF NOT EXISTS idx_devchg_device ON device_changes(device_id, ts);
CREATE TABLE IF NOT EXISTS service_checks (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT,
    type            TEXT,
    target          TEXT,
    interval_sec    INTEGER DEFAULT 60,
    enabled         INTEGER DEFAULT 1,
    last_status     TEXT,
    last_latency_ms INTEGER DEFAULT 0,
    last_check      TEXT,
    created_at      TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS service_check_history (
    check_id   INTEGER NOT NULL,
    ts         TEXT DEFAULT (datetime('now')),
    up         INTEGER,
    latency_ms INTEGER
);
CREATE INDEX IF NOT EXISTS idx_chkhist ON service_check_history(check_id, ts);
CREATE TABLE IF NOT EXISTS topology_links (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    parent_device_id INTEGER NOT NULL,
    child_device_id  INTEGER NOT NULL,
    link_type        TEXT DEFAULT 'manual',
    port             TEXT
);
CREATE INDEX IF NOT EXISTS idx_topo_parent ON topology_links(parent_device_id);
CREATE TABLE IF NOT EXISTS discovery_queue (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ip         TEXT,
    mac        TEXT UNIQUE,
    hostname   TEXT,
    vendor     TEXT,
    method     TEXT,
    first_seen TEXT DEFAULT (datetime('now')),
    last_seen  TEXT DEFAULT (datetime('now')),
    status     TEXT DEFAULT 'new'
);
CREATE TABLE IF NOT EXISTS forbidden_software (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern    TEXT,
    category   TEXT,
    note       TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS software_licenses (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT,
    vendor          TEXT,
    seats_purchased INTEGER DEFAULT 0,
    cost            REAL DEFAULT 0,
    note            TEXT,
    created_at      TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS services (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id    INTEGER NOT NULL,
    name         TEXT,
    display_name TEXT,
    start_type   TEXT,
    path         TEXT
);
CREATE INDEX IF NOT EXISTS idx_services_device ON services(device_id);
CREATE TABLE IF NOT EXISTS autoruns (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL,
    location  TEXT,
    name      TEXT,
    command   TEXT
);
CREATE INDEX IF NOT EXISTS idx_autoruns_device ON autoruns(device_id);
CREATE TABLE IF NOT EXISTS scheduled_tasks (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL,
    name      TEXT,
    path      TEXT,
    action    TEXT,
    state     TEXT
);
CREATE INDEX IF NOT EXISTS idx_schtasks_device ON scheduled_tasks(device_id);
CREATE TABLE IF NOT EXISTS disks (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id      INTEGER NOT NULL,
    model          TEXT,
    serial         TEXT,
    size_gb        INTEGER DEFAULT 0,
    media_type     TEXT,
    health         TEXT,
    temperature    INTEGER DEFAULT 0,
    power_on_hours INTEGER DEFAULT 0,
    wear_pct       INTEGER DEFAULT 0,
    read_errors    INTEGER DEFAULT 0,
    predict_fail   INTEGER DEFAULT 0,
    updated_at     TEXT
);
CREATE INDEX IF NOT EXISTS idx_disks_device ON disks(device_id);
CREATE TABLE IF NOT EXISTS packages (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT,
    filename      TEXT,
    original_name TEXT,
    kind          TEXT,
    size          INTEGER DEFAULT 0,
    sha256        TEXT,
    install_args  TEXT,
    created_by    INTEGER,
    created_at    TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS agent_tasks (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id  INTEGER NOT NULL,
    kind       TEXT,
    payload    TEXT,
    label      TEXT,
    status     TEXT DEFAULT 'pending',
    result     TEXT,
    exit_code  INTEGER DEFAULT 0,
    created_by INTEGER,
    created_at TEXT DEFAULT (datetime('now')),
    sent_at    TEXT,
    done_at    TEXT
);
CREATE INDEX IF NOT EXISTS idx_agent_tasks_device ON agent_tasks(device_id, status);
CREATE TABLE IF NOT EXISTS snmp_devices (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT,
    ip           TEXT,
    port         INTEGER DEFAULT 161,
    community    TEXT DEFAULT 'public',
    kind         TEXT DEFAULT 'auto',
    interval_sec INTEGER DEFAULT 120,
    enabled      INTEGER DEFAULT 1,
    last_status  TEXT,
    last_poll    TEXT,
    sys_name     TEXT,
    sys_descr    TEXT,
    uptime_sec   INTEGER DEFAULT 0,
    detail       TEXT,
    supply_alert INTEGER DEFAULT 0,
    created_at   TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS snmp_ports (
    snmp_device_id INTEGER NOT NULL,
    if_index       TEXT NOT NULL,
    name           TEXT,
    oper           INTEGER DEFAULT 0,
    in_octets      INTEGER DEFAULT 0,
    out_octets     INTEGER DEFAULT 0,
    in_rate_bps    INTEGER DEFAULT 0,
    out_rate_bps   INTEGER DEFAULT 0,
    speed          INTEGER DEFAULT 0,
    updated_at     TEXT,
    PRIMARY KEY (snmp_device_id, if_index)
);
CREATE TABLE IF NOT EXISTS tickets (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    code           TEXT UNIQUE,
    title          TEXT,
    description    TEXT,
    category       TEXT,
    priority       TEXT DEFAULT 'normal',
    status         TEXT DEFAULT 'new',
    employee_id    INTEGER,
    reporter_name  TEXT,
    reporter_email TEXT,
    reporter_phone TEXT,
    location       TEXT,
    device_id      INTEGER,
    assignee_id    INTEGER,
    created_at     TEXT DEFAULT (datetime('now')),
    updated_at     TEXT,
    closed_at      TEXT
);
CREATE INDEX IF NOT EXISTS idx_tickets_status ON tickets(status);
CREATE INDEX IF NOT EXISTS idx_tickets_created ON tickets(created_at);
CREATE TABLE IF NOT EXISTS ticket_comments (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id      INTEGER NOT NULL,
    author_user_id INTEGER,
    author_name    TEXT,
    body           TEXT,
    is_internal    INTEGER DEFAULT 0,
    created_at     TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_tcomments_ticket ON ticket_comments(ticket_id, created_at);
CREATE TABLE IF NOT EXISTS network_changes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT DEFAULT (datetime('now')),
    change_type TEXT,
    ip          TEXT,
    mac         TEXT,
    hostname    TEXT,
    vendor      TEXT,
    detail      TEXT
);
CREATE INDEX IF NOT EXISTS idx_netchanges_ts ON network_changes(ts);
CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac_address);
CREATE INDEX IF NOT EXISTS idx_devices_hostname ON devices(hostname);
CREATE INDEX IF NOT EXISTS idx_events_category ON events(category);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);
`

// metrics_rollup — агрегаты метрик (Epic 6): почасовые (>7 дней) и суточные (>30 дней).
const rollupSchema = `
CREATE TABLE IF NOT EXISTS metrics_rollup (
    device_id INTEGER NOT NULL,
    period    TEXT NOT NULL,
    bucket    TEXT NOT NULL,
    cpu_min REAL, cpu_avg REAL, cpu_max REAL,
    ram_min REAL, ram_avg REAL, ram_max REAL,
    disk_min REAL, disk_avg REAL, disk_max REAL,
    samples INTEGER,
    PRIMARY KEY (device_id, period, bucket)
);
CREATE INDEX IF NOT EXISTS idx_rollup_bucket ON metrics_rollup(bucket);
`

// InitSchema создаёт таблицы, индексы и применяет миграции (идемпотентно).
func InitSchema(d *sql.DB) error {
	if _, err := d.Exec(schema); err != nil {
		return err
	}
	if _, err := d.Exec(rollupSchema); err != nil {
		return err
	}
	// миграции колонок для существующих БД (созданных до добавления полей)
	for _, m := range []struct{ table, col, def string }{
		{"events", "detail", "TEXT"},
		{"events", "status", "TEXT DEFAULT 'new'"},
		{"events", "assignee", "TEXT"},
		{"events", "note", "TEXT"},
		{"events", "updated_at", "TEXT"},
		{"devices", "agent_token", "TEXT"},
		{"devices", "os_guess", "TEXT"},
		{"devices", "open_ports", "TEXT"},
		{"devices", "critical", "INTEGER DEFAULT 0"},
		{"devices", "down_streak", "INTEGER DEFAULT 0"},
		{"devices", "down_since", "TEXT"},
		{"devices", "cpu_model", "TEXT DEFAULT ''"},
		{"devices", "ram_total_gb", "INTEGER DEFAULT 0"},
		{"devices", "disk_total_gb", "INTEGER DEFAULT 0"},
		{"devices", "os_version", "TEXT DEFAULT ''"},
		{"devices", "agent_version", "TEXT DEFAULT ''"},
		{"agent_tasks", "package_id", "INTEGER DEFAULT 0"},
		{"sessions", "last_activity", "TEXT"},
		{"snmp_devices", "supply_alert", "INTEGER DEFAULT 0"},
	} {
		safeAddColumn(d, m.table, m.col, m.def)
	}
	return nil
}

// safeAddColumn добавляет колонку, если её ещё нет.
func safeAddColumn(d *sql.DB, table, col, def string) {
	rows, err := d.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt any
		if rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk) == nil && name == col {
			return // уже есть
		}
	}
	if err := rows.Err(); err != nil {
		log.Printf("safeAddColumn: %v", err)
	}
	d.Exec("ALTER TABLE " + table + " ADD COLUMN " + col + " " + def)
}
