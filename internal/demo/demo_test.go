package demo

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"netadmin/internal/auth"
	"netadmin/internal/db"
)

// newTestDB поднимает реальную схему во временном файле.
//
// Каталог чистится вручную, а не через t.TempDir(): на Windows авто-очистка
// падает с «directory is not empty», если WAL-файлы SQLite ещё держатся, и
// прошедший тест помечается как FAIL.
func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dir, err := os.MkdirTemp("", "demotest")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	d, err := db.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.InitSchema(d); err != nil {
		t.Fatalf("schema: %v", err)
	}
	t.Cleanup(func() {
		d.Close()
		_ = os.RemoveAll(dir)
	})
	return d
}

func count(t *testing.T, d *sql.DB, table string) int {
	t.Helper()
	var n int
	if err := d.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// TestSeedFillsEveryShowcasedSection — главная проверка демо-режима: разделы
// интерфейса должны открываться с данными. Пустая таблица здесь выглядит как
// недоделанная функция, а не как расхождение схемы и наполнения, поэтому
// перечислены все, на которые опирается витрина.
func TestSeedFillsEveryShowcasedSection(t *testing.T) {
	d := newTestDB(t)

	if err := Seed(d); err != nil {
		t.Fatalf("Seed: %v", err)
	}

	for _, table := range []string{
		"users", "departments", "employees", "devices", "metrics_history",
		"software", "service_checks", "service_check_history", "forbidden_software",
		"software_licenses", "disks", "tickets", "topology_links", "events", "audit_log",
	} {
		if n := count(t, d, table); n == 0 {
			t.Errorf("таблица %s пуста — соответствующий раздел откроется пустым", table)
		}
	}

	if n := count(t, d, "devices"); n != len(Hosts) {
		t.Errorf("устройств %d, ожидалось %d", n, len(Hosts))
	}
}

// TestSeedAdminCanLogIn — без рабочего пароля демо бесполезно: человек видит
// форму входа и не может пройти дальше.
func TestSeedAdminCanLogIn(t *testing.T) {
	d := newTestDB(t)
	if err := Seed(d); err != nil {
		t.Fatalf("Seed: %v", err)
	}

	var hash, role string
	err := d.QueryRow("SELECT password_hash, role FROM users WHERE username=?", AdminUser).
		Scan(&hash, &role)
	if err != nil {
		t.Fatalf("демо-администратор %q не заведён: %v", AdminUser, err)
	}
	if role != "admin" {
		t.Errorf("роль демо-администратора %q, ожидалась admin", role)
	}
	if !auth.VerifyPassword(AdminPassword, hash) {
		t.Error("пароль из AdminPassword не подходит к сохранённому хэшу")
	}
}

// TestIsEmpty стережёт защиту от наполнения чужой базы: seed и -demo решают
// по нему, можно ли заводить администратора с заведомо известным паролем.
func TestIsEmpty(t *testing.T) {
	d := newTestDB(t)

	empty, err := IsEmpty(d)
	if err != nil {
		t.Fatalf("IsEmpty: %v", err)
	}
	if !empty {
		t.Fatal("свежая база должна считаться пустой")
	}

	if err := Seed(d); err != nil {
		t.Fatalf("Seed: %v", err)
	}
	empty, err = IsEmpty(d)
	if err != nil {
		t.Fatalf("IsEmpty: %v", err)
	}
	if empty {
		t.Error("наполненная база не должна считаться пустой")
	}
}
