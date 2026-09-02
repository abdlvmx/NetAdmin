package backup

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"netadmin/internal/db"
)

func testDB(t *testing.T) (*os.File, string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "bktest")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return nil, dir
}

// Копия должна открываться как полноценная база и содержать те же данные:
// простое копирование файла рядом с журналом WAL этого не гарантирует.
func TestCreateMakesUsableCopy(t *testing.T) {
	_, dir := testDB(t)
	d, err := db.Open(filepath.Join(dir, "src.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer d.Close()
	if err := db.InitSchema(d); err != nil {
		t.Fatalf("schema: %v", err)
	}
	for i := 0; i < 20; i++ {
		if _, err := d.Exec("INSERT INTO devices (hostname, status) VALUES (?, 'online')",
			"WS-"+string(rune('A'+i))); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	bdir, err := Dir(dir, "")
	if err != nil {
		t.Fatalf("dir: %v", err)
	}
	path, err := Create(d, bdir, 5)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	copyDB, err := db.Open(path)
	if err != nil {
		t.Fatalf("копия не открывается: %v", err)
	}
	defer copyDB.Close()
	var n int
	if err := copyDB.QueryRow("SELECT COUNT(*) FROM devices").Scan(&n); err != nil {
		t.Fatalf("чтение копии: %v", err)
	}
	if n != 20 {
		t.Fatalf("в копии %d устройств, ожидалось 20", n)
	}
}

// Копия содержит токены агентов, поэтому каталог и файл закрыты от чужих.
//
// Проверка только для систем с правами Unix: Windows режим файла не соблюдает
// (os.Chmod там переключает лишь признак «только чтение»), и доступ к каталогу
// копий приходится ограничивать средствами NTFS.
func TestBackupPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows не применяет права Unix к файлам")
	}
	_, dir := testDB(t)
	d, _ := db.Open(filepath.Join(dir, "src.db"))
	defer d.Close()
	db.InitSchema(d)

	bdir, _ := Dir(dir, "")
	di, err := os.Stat(bdir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if di.Mode().Perm()&0o077 != 0 {
		t.Errorf("каталог копий доступен посторонним: %v", di.Mode().Perm())
	}
	path, err := Create(d, bdir, 3)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat file: %v", err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		t.Errorf("файл копии доступен посторонним: %v", fi.Mode().Perm())
	}
}

// Ротация оставляет заданное число копий и не трогает посторонние файлы.
func TestPruneKeepsNewestAndSparesStrangers(t *testing.T) {
	_, dir := testDB(t)
	bdir, _ := Dir(dir, "")

	for _, n := range []string{
		"netadmin-2026-01-01-1000.db",
		"netadmin-2026-02-01-1000.db",
		"netadmin-2026-03-01-1000.db",
		"netadmin-2026-04-01-1000.db",
	} {
		if err := os.WriteFile(filepath.Join(bdir, n), []byte("x"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	stranger := filepath.Join(bdir, "README.txt")
	os.WriteFile(stranger, []byte("не трогать"), 0o600)

	if err := prune(bdir, 2); err != nil {
		t.Fatalf("prune: %v", err)
	}
	left := List(bdir)
	if len(left) != 2 {
		t.Fatalf("должно остаться 2 копии, осталось %d", len(left))
	}
	if left[0].Name != "netadmin-2026-04-01-1000.db" || left[1].Name != "netadmin-2026-03-01-1000.db" {
		t.Fatalf("оставлены не самые свежие: %v, %v", left[0].Name, left[1].Name)
	}
	if _, err := os.Stat(stranger); err != nil {
		t.Error("посторонний файл в каталоге не должен удаляться")
	}
}

// keep<=0 отключает ротацию: опечатка в настройках не должна стирать архив.
func TestPruneDisabledKeepsEverything(t *testing.T) {
	_, dir := testDB(t)
	bdir, _ := Dir(dir, "")
	for _, n := range []string{"netadmin-2026-01-01-1000.db", "netadmin-2026-02-01-1000.db"} {
		os.WriteFile(filepath.Join(bdir, n), []byte("x"), 0o600)
	}
	if err := prune(bdir, 0); err != nil {
		t.Fatalf("prune: %v", err)
	}
	if len(List(bdir)) != 2 {
		t.Fatal("при keep=0 копии удаляться не должны")
	}
}

// Заданный в настройках каталог имеет приоритет над каталогом по умолчанию.
func TestDirHonoursConfigured(t *testing.T) {
	_, dir := testDB(t)
	custom := filepath.Join(dir, "своё-место")
	got, err := Dir(dir, custom)
	if err != nil {
		t.Fatalf("dir: %v", err)
	}
	if got != custom {
		t.Fatalf("ожидался %q, получено %q", custom, got)
	}
	if _, err := os.Stat(custom); err != nil {
		t.Error("каталог должен создаваться")
	}
}
