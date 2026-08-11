// Package ingest — пакетная (батч) запись метрик и событий в SQLite.
// Снижает число дисковых транзакций при потоке heartbeat/логов от агентов.
package ingest

import (
	"database/sql"
	"fmt"
	"time"
)

// MetricRow — строка истории метрик устройства.
type MetricRow struct {
	DeviceID       int64
	CPU, RAM, Disk float64
}

// EventRow — событие безопасности (DeviceID==0 → NULL; Ts=="" → datetime('now')).
type EventRow struct {
	DeviceID                                       int64
	Hostname, Ts, Source                           string
	EventID                                        int
	Severity, Category, Message, Detail            string
}

// Writer принимает строки в каналы и пишет их пачками в фоне.
type Writer struct {
	db          *sql.DB
	metrics     chan MetricRow
	events      chan EventRow
	metricsDays int
	eventsDays  int
	auditDays   int
}

const (
	batchSize      = 100
	flushInterval  = 5 * time.Second
	pruneInterval  = 5 * time.Minute
	rollupInterval = time.Hour
	bufCap         = 2000
)

// New создаёт writer и запускает фоновый воркер.
func New(db *sql.DB, metricsDays, eventsDays, auditDays int) *Writer {
	w := &Writer{
		db:          db,
		metrics:     make(chan MetricRow, bufCap),
		events:      make(chan EventRow, bufCap),
		metricsDays: metricsDays,
		eventsDays:  eventsDays,
		auditDays:   auditDays,
	}
	go w.run()
	return w
}

// Metric ставит строку метрик в очередь (не блокирует; при переполнении — дроп).
func (w *Writer) Metric(r MetricRow) {
	select {
	case w.metrics <- r:
	default:
	}
}

// Event ставит событие в очередь (не блокирует; при переполнении — дроп).
func (w *Writer) Event(r EventRow) {
	select {
	case w.events <- r:
	default:
	}
}

func (w *Writer) run() {
	flushT := time.NewTicker(flushInterval)
	pruneT := time.NewTicker(pruneInterval)
	rollupT := time.NewTicker(rollupInterval)
	defer flushT.Stop()
	defer pruneT.Stop()
	defer rollupT.Stop()

	var mbuf []MetricRow
	var ebuf []EventRow
	flush := func() {
		if len(mbuf) == 0 && len(ebuf) == 0 {
			return
		}
		w.flush(mbuf, ebuf)
		mbuf = mbuf[:0]
		ebuf = ebuf[:0]
	}

	for {
		select {
		case m := <-w.metrics:
			mbuf = append(mbuf, m)
			if len(mbuf) >= batchSize {
				flush()
			}
		case e := <-w.events:
			ebuf = append(ebuf, e)
			if len(ebuf) >= batchSize {
				flush()
			}
		case <-flushT.C:
			flush()
		case <-pruneT.C:
			w.prune()
		case <-rollupT.C:
			w.rollup()
		}
	}
}

// rollup сворачивает старые метрики в агрегаты (Epic 6): сырьё >7 дней → почасовые
// агрегаты (min/avg/max) и удаляется; почасовые >30 дней → суточные. Сильно
// уменьшает размер БД, сохраняя историю для графиков.
func (w *Writer) rollup() {
	// сырые точки старше 7 дней → почасовые агрегаты
	w.db.Exec(`INSERT OR IGNORE INTO metrics_rollup
		(device_id, period, bucket, cpu_min,cpu_avg,cpu_max, ram_min,ram_avg,ram_max, disk_min,disk_avg,disk_max, samples)
		SELECT device_id, 'hour', strftime('%Y-%m-%d %H:00:00', ts),
		       MIN(cpu_usage),AVG(cpu_usage),MAX(cpu_usage),
		       MIN(ram_usage),AVG(ram_usage),MAX(ram_usage),
		       MIN(disk_usage),AVG(disk_usage),MAX(disk_usage), COUNT(*)
		FROM metrics_history WHERE ts < datetime('now','-7 days')
		GROUP BY device_id, strftime('%Y-%m-%d %H:00:00', ts)`)
	w.db.Exec(`DELETE FROM metrics_history WHERE ts < datetime('now','-7 days')`)

	// почасовые агрегаты старше 30 дней → суточные
	w.db.Exec(`INSERT OR IGNORE INTO metrics_rollup
		(device_id, period, bucket, cpu_min,cpu_avg,cpu_max, ram_min,ram_avg,ram_max, disk_min,disk_avg,disk_max, samples)
		SELECT device_id, 'day', substr(bucket,1,10)||' 00:00:00',
		       MIN(cpu_min),AVG(cpu_avg),MAX(cpu_max),
		       MIN(ram_min),AVG(ram_avg),MAX(ram_max),
		       MIN(disk_min),AVG(disk_avg),MAX(disk_max), SUM(samples)
		FROM metrics_rollup WHERE period='hour' AND bucket < datetime('now','-30 days')
		GROUP BY device_id, substr(bucket,1,10)`)
	w.db.Exec(`DELETE FROM metrics_rollup WHERE period='hour' AND bucket < datetime('now','-30 days')`)

	// ретеншн суточных агрегатов
	w.db.Exec(`DELETE FROM metrics_rollup WHERE period='day' AND bucket < datetime('now','-90 days')`)
}

func (w *Writer) flush(m []MetricRow, e []EventRow) {
	tx, err := w.db.Begin()
	if err != nil {
		return
	}
	for _, r := range m {
		tx.Exec(`INSERT INTO metrics_history (device_id, cpu_usage, ram_usage, disk_usage)
			VALUES (?,?,?,?)`, r.DeviceID, r.CPU, r.RAM, r.Disk)
	}
	for _, r := range e {
		var dev any
		if r.DeviceID > 0 {
			dev = r.DeviceID
		}
		var ts any
		if r.Ts != "" {
			ts = r.Ts
		}
		tx.Exec(`INSERT INTO events (device_id, hostname, ts, source, event_id, severity, category, message, detail)
			VALUES (?, ?, COALESCE(?, datetime('now')), ?, ?, ?, ?, ?, ?)`,
			dev, r.Hostname, ts, r.Source, r.EventID, r.Severity, r.Category, r.Message, r.Detail)
	}
	if err := tx.Commit(); err != nil {
		_ = tx.Rollback()
	}
}

// prune убирает устаревшие записи (вынесено из горячего пути запросов).
// Инциденты-корреляции (source='correlation') не удаляются.
func (w *Writer) prune() {
	w.db.Exec("DELETE FROM metrics_history WHERE ts < datetime('now', ?)",
		fmt.Sprintf("-%d days", w.metricsDays))
	w.db.Exec("DELETE FROM events WHERE ts < datetime('now', ?) AND COALESCE(source,'') <> 'correlation'",
		fmt.Sprintf("-%d days", w.eventsDays))
	w.db.Exec("DELETE FROM audit_log WHERE created_at < datetime('now', ?)",
		fmt.Sprintf("-%d days", w.auditDays))
	w.db.Exec("DELETE FROM network_changes WHERE ts < datetime('now', ?)",
		fmt.Sprintf("-%d days", w.eventsDays))
	w.db.Exec("DELETE FROM service_check_history WHERE ts < datetime('now', ?)",
		fmt.Sprintf("-%d days", w.metricsDays))
}
