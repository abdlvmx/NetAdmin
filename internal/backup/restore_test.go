package backup

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

// newDB создаёт базу с таблицей users — минимум, по которому Verify узнаёт
// базу NetAdmin.
func newDB(t *testing.T, path string, users int) {
	t.Helper()
	d, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("создание базы: %v", err)
	}
	defer d.Close()
	if _, err := d.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT)`); err != nil {
		t.Fatalf("схема: %v", err)
	}
	for i := 0; i < users; i++ {
		if _, err := d.Exec(`INSERT INTO users (username) VALUES (?)`, "u"); err != nil {
			t.Fatalf("вставка: %v", err)
		}
	}
}

// tempDir — каталог, который чистится вручную: на Windows авто-очистка
// t.TempDir() падает с «directory is not empty», если SQLite ещё держит файлы.
func tempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "backuptest")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// TestVerifyRejectsUnusableFiles — проверка копии стоит между «нажал кнопку» и
// «база заменена», поэтому она обязана отсеять всё, что базой не является.
func TestVerifyRejectsUnusableFiles(t *testing.T) {
	dir := tempDir(t)

	cases := []struct{ name, why string }{
		{"missing.db", "несуществующий файл"},
		{"empty.db", "пустой файл"},
		{"garbage.db", "не база SQLite"},
		{"other.db", "чужая база без таблицы users"},
		{"nousers.db", "база NetAdmin без учётных записей"},
	}

	if err := os.WriteFile(filepath.Join(dir, "empty.db"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "garbage.db"), []byte("это не база"), 0o600); err != nil {
		t.Fatal(err)
	}
	other, err := sql.Open("sqlite", filepath.Join(dir, "other.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Exec("CREATE TABLE notes (id INTEGER)"); err != nil {
		t.Fatal(err)
	}
	other.Close()
	newDB(t, filepath.Join(dir, "nousers.db"), 0)

	for _, c := range cases {
		if err := Verify(filepath.Join(dir, c.name)); err == nil {
			t.Errorf("Verify принял %s (%s) — восстановление затёрло бы рабочую базу", c.name, c.why)
		}
	}

	newDB(t, filepath.Join(dir, "good.db"), 2)
	if err := Verify(filepath.Join(dir, "good.db")); err != nil {
		t.Errorf("Verify отверг исправную базу: %v", err)
	}
}

// TestRestoreReplacesDatabaseAndKeepsPrevious — основной сценарий: подготовка,
// применение при запуске, сохранение прежней базы.
func TestRestoreReplacesDatabaseAndKeepsPrevious(t *testing.T) {
	dir := tempDir(t)
	dbPath := filepath.Join(dir, "netadmin.db")
	backupPath := filepath.Join(dir, "netadmin-2026-01-01-1200.db")

	newDB(t, dbPath, 1)     // рабочая база: одна учётная запись
	newDB(t, backupPath, 3) // копия: три

	// журналы прежней базы должны исчезнуть вместе с ней
	for _, sfx := range []string{"-wal", "-shm"} {
		if err := os.WriteFile(dbPath+sfx, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if Pending(dbPath) {
		t.Fatal("восстановление считается подготовленным до вызова StageRestore")
	}
	if err := StageRestore(dbPath, backupPath); err != nil {
		t.Fatalf("StageRestore: %v", err)
	}
	if !Pending(dbPath) {
		t.Fatal("после StageRestore восстановление не считается подготовленным")
	}

	saved, err := ApplyPending(dbPath)
	if err != nil {
		t.Fatalf("ApplyPending: %v", err)
	}
	if saved == "" {
		t.Fatal("прежняя база не сохранена — откатиться будет некуда")
	}
	if _, err := os.Stat(saved); err != nil {
		t.Errorf("сохранённая прежняя база недоступна: %v", err)
	}
	for _, sfx := range []string{"-wal", "-shm"} {
		if _, err := os.Stat(dbPath + sfx); err == nil {
			t.Errorf("журнал %s остался от прежней базы — восстановленная будет считаться повреждённой", sfx)
		}
	}
	if Pending(dbPath) {
		t.Error("подготовленный файл остался после применения")
	}

	// в восстановленной базе должны быть данные копии, а не прежние
	d, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("открытие восстановленной базы: %v", err)
	}
	defer d.Close()
	var n int
	if err := d.QueryRow("SELECT COUNT(*) FROM users").Scan(&n); err != nil {
		t.Fatalf("чтение: %v", err)
	}
	if n != 3 {
		t.Errorf("в базе %d учётных записей, ожидалось 3 (данные копии)", n)
	}
}

// TestStageRestoreRejectsBadBackup — негодная копия не должна доходить до
// подготовки: иначе она подменила бы базу при следующем запуске.
func TestStageRestoreRejectsBadBackup(t *testing.T) {
	dir := tempDir(t)
	dbPath := filepath.Join(dir, "netadmin.db")
	newDB(t, dbPath, 1)

	bad := filepath.Join(dir, "netadmin-bad.db")
	if err := os.WriteFile(bad, []byte("мусор"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := StageRestore(dbPath, bad); err == nil {
		t.Fatal("StageRestore принял негодную копию")
	}
	if Pending(dbPath) {
		t.Error("после отказа остался подготовленный файл")
	}
}

// TestApplyPendingRefusesCorruptedStage — файл мог испортиться между
// подготовкой и перезапуском; рабочая база при этом должна уцелеть.
func TestApplyPendingRefusesCorruptedStage(t *testing.T) {
	dir := tempDir(t)
	dbPath := filepath.Join(dir, "netadmin.db")
	newDB(t, dbPath, 1)

	if err := os.WriteFile(PendingPath(dbPath), []byte("испорчено"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyPending(dbPath); err == nil {
		t.Fatal("ApplyPending применил испорченный файл")
	}
	if Pending(dbPath) {
		t.Error("испорченный подготовленный файл не убран — он повторится при каждом запуске")
	}

	d, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("рабочая база пострадала: %v", err)
	}
	defer d.Close()
	var n int
	if err := d.QueryRow("SELECT COUNT(*) FROM users").Scan(&n); err != nil || n != 1 {
		t.Errorf("рабочая база изменилась: n=%d err=%v", n, err)
	}
}

// TestCancelPending — отмена до перезапуска.
func TestCancelPending(t *testing.T) {
	dir := tempDir(t)
	dbPath := filepath.Join(dir, "netadmin.db")
	backupPath := filepath.Join(dir, "netadmin-copy.db")
	newDB(t, dbPath, 1)
	newDB(t, backupPath, 5)

	if err := StageRestore(dbPath, backupPath); err != nil {
		t.Fatalf("StageRestore: %v", err)
	}
	if err := CancelPending(dbPath); err != nil {
		t.Fatalf("CancelPending: %v", err)
	}
	if Pending(dbPath) {
		t.Error("после отмены восстановление всё ещё подготовлено")
	}
	if err := CancelPending(dbPath); err != nil {
		t.Errorf("повторная отмена вернула ошибку: %v", err)
	}

	saved, err := ApplyPending(dbPath)
	if err != nil || saved != "" {
		t.Errorf("после отмены запуск всё равно подменил базу: saved=%q err=%v", saved, err)
	}
}
