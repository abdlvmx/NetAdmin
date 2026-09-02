package ingest

import (
	"path/filepath"
	"testing"

	"netadmin/internal/db"
)

// Метрики пишутся пачками — до сотни строк или до пяти секунд. Остановка
// должна дописать накопленное, иначе обычный перезапуск сервера теряет
// последние минуты истории.
func TestCloseFlushesPendingRows(t *testing.T) {
	d, err := db.Open(filepath.Join(t.TempDir(), "close.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer d.Close()
	if err := db.InitSchema(d); err != nil {
		t.Fatalf("schema: %v", err)
	}
	d.Exec(`INSERT INTO devices (id, hostname, status) VALUES (1,'d1','online')`)

	w := New(d, 90, 180, 365)
	// заведомо меньше batchSize, чтобы пачка сама не ушла в базу
	const n = 7
	for i := 0; i < n; i++ {
		w.Metric(MetricRow{DeviceID: 1, CPU: float64(i), RAM: 10, Disk: 20})
	}
	w.Event(EventRow{Hostname: "d1", Source: "test", Severity: "info", Category: "test", Message: "событие"})

	w.Close()

	var metrics, events int
	d.QueryRow("SELECT COUNT(*) FROM metrics_history").Scan(&metrics)
	d.QueryRow("SELECT COUNT(*) FROM events").Scan(&events)
	if metrics != n {
		t.Errorf("ожидалось %d метрик после остановки, записано %d", n, metrics)
	}
	if events != 1 {
		t.Errorf("ожидалось 1 событие после остановки, записано %d", events)
	}
}

// Повторный Close не должен паниковать на закрытии уже закрытого канала:
// остановку могут вызвать и по сигналу, и из defer.
func TestCloseIsIdempotent(t *testing.T) {
	d, err := db.Open(filepath.Join(t.TempDir(), "close2.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer d.Close()
	if err := db.InitSchema(d); err != nil {
		t.Fatalf("schema: %v", err)
	}
	w := New(d, 90, 180, 365)
	w.Close()
	w.Close()
}
