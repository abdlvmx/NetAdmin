package handlers

import (
	"os"
	"path/filepath"
	"testing"

	"netadmin/internal/db"
)

// newTestApp поднимает App с реальной схемой во временном файле БД.
//
// Каталог создаётся вручную (не t.TempDir): на Windows авто-очистка t.TempDir()
// падает с «directory is not empty», если фоновые notify-горутины или WAL-файлы
// SQLite ещё держат файлы в момент удаления — это помечает прошедший тест как
// FAIL. Здесь чистим сами, игнорируя такие гонки.
func newTestApp(t *testing.T) *App {
	t.Helper()
	dir, err := os.MkdirTemp("", "natest")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Setenv("NETADMIN_DATA_DIR", dir) // notify/config не лезут в реальный config.json
	d, err := db.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.InitSchema(d); err != nil {
		t.Fatalf("schema: %v", err)
	}
	t.Cleanup(func() {
		d.Close()
		_ = os.RemoveAll(dir) // ошибку игнорируем (фоновые горутины могли держать файл)
	})
	return &App{DB: d}
}
