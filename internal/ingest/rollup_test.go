package ingest

import (
	"path/filepath"
	"testing"

	"netadmin/internal/db"
)

func TestRollup(t *testing.T) {
	d, err := db.Open(filepath.Join(t.TempDir(), "roll.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer d.Close()
	if err := db.InitSchema(d); err != nil {
		t.Fatalf("schema: %v", err)
	}

	// устройства (FK metrics_history.device_id -> devices.id)
	d.Exec(`INSERT INTO devices (id, hostname, status) VALUES (1,'d1','online'),(2,'d2','online')`)

	// 3 сырые точки одного часа, 10 дней назад (старше 7д) для устройства 1
	for _, cpu := range []float64{10, 20, 30} {
		d.Exec(`INSERT INTO metrics_history (device_id, cpu_usage, ram_usage, disk_usage, ts)
			VALUES (1, ?, 50, 50, datetime('now','-10 days'))`, cpu)
	}
	// свежая точка (сегодня) — НЕ должна сворачиваться
	d.Exec(`INSERT INTO metrics_history (device_id, cpu_usage, ram_usage, disk_usage, ts)
		VALUES (1, 99, 50, 50, datetime('now','-1 hours'))`)

	w := New(d, 90, 180, 365)
	w.rollup()

	// почасовой агрегат создан с правильными min/avg/max/samples
	var cmin, cavg, cmax float64
	var samples int
	err = d.QueryRow(`SELECT cpu_min, cpu_avg, cpu_max, samples FROM metrics_rollup
		WHERE device_id=1 AND period='hour'`).Scan(&cmin, &cavg, &cmax, &samples)
	if err != nil {
		t.Fatalf("нет почасового агрегата: %v", err)
	}
	if cmin != 10 || cavg != 20 || cmax != 30 || samples != 3 {
		t.Fatalf("агрегат неверный: min=%v avg=%v max=%v n=%d", cmin, cavg, cmax, samples)
	}

	// старое сырьё удалено, свежая точка осталась
	var rawOld, rawFresh int
	d.QueryRow(`SELECT COUNT(*) FROM metrics_history WHERE ts < datetime('now','-7 days')`).Scan(&rawOld)
	d.QueryRow(`SELECT COUNT(*) FROM metrics_history`).Scan(&rawFresh)
	if rawOld != 0 {
		t.Fatalf("старое сырьё не удалено: %d", rawOld)
	}
	if rawFresh != 1 {
		t.Fatalf("свежая точка должна остаться: %d", rawFresh)
	}

	// идемпотентность: повторный rollup не плодит дубликаты
	w.rollup()
	var hourCnt int
	d.QueryRow(`SELECT COUNT(*) FROM metrics_rollup WHERE period='hour'`).Scan(&hourCnt)
	if hourCnt != 1 {
		t.Fatalf("дубликат почасового агрегата: %d", hourCnt)
	}

	// почасовой агрегат старше 30 дней → суточный
	d.Exec(`INSERT INTO metrics_rollup (device_id, period, bucket, cpu_min,cpu_avg,cpu_max, ram_min,ram_avg,ram_max, disk_min,disk_avg,disk_max, samples)
		VALUES (2, 'hour', strftime('%Y-%m-%d %H:00:00', datetime('now','-40 days')), 5,15,25, 5,15,25, 5,15,25, 4)`)
	w.rollup()
	var dayCnt, oldHour int
	d.QueryRow(`SELECT COUNT(*) FROM metrics_rollup WHERE device_id=2 AND period='day'`).Scan(&dayCnt)
	d.QueryRow(`SELECT COUNT(*) FROM metrics_rollup WHERE device_id=2 AND period='hour'`).Scan(&oldHour)
	if dayCnt != 1 {
		t.Fatalf("суточный агрегат не создан: %d", dayCnt)
	}
	if oldHour != 0 {
		t.Fatalf("старый почасовой не удалён: %d", oldHour)
	}
}
