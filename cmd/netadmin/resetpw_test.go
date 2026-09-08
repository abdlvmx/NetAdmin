package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"netadmin/internal/auth"
	"netadmin/internal/db"
)

// Проверки сброса пароля с консоли. Команда трогает единственное, чем держится
// доступ ко всей панели, поэтому важны обе стороны: что она меняет пароль там,
// где надо, и что при любом сомнении не меняет ничего.

// resetEnv готовит временную базу с учётными записями и уводит от неё оба
// пути поиска: и каталог данных, и «установленную» службу. Настоящую базу на
// машине разработчика тест не должен видеть даже случайно.
func resetEnv(t *testing.T, users ...account) *sql.DB {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("NETADMIN_DATA_DIR", dir)

	missing := filepath.Join(dir, "нет-такой-службы", "netadmin.db")
	old := installedDBPath
	installedDBPath = func() string { return missing }
	t.Cleanup(func() { installedDBPath = old })

	d, err := db.Open(filepath.Join(dir, "netadmin.db"))
	if err != nil {
		t.Fatalf("создать базу: %v", err)
	}
	if err := db.InitSchema(d); err != nil {
		t.Fatalf("схема: %v", err)
	}
	t.Cleanup(func() { d.Close() })

	for _, u := range users {
		hash, _ := auth.HashPassword("Staryjparol1")
		active := 0
		if u.active {
			active = 1
		}
		if _, err := d.Exec(
			`INSERT INTO users (username, full_name, role, password_hash, is_active)
			 VALUES (?,?,?,?,?)`, u.username, u.fullName, u.role, hash, active); err != nil {
			t.Fatalf("завести %s: %v", u.username, err)
		}
	}
	return d
}

// withInput подменяет стандартный ввод заготовленными строками: диалог команды
// иначе не проверить.
func withInput(t *testing.T, lines ...string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("канал: %v", err)
	}
	if _, err := w.WriteString(strings.Join(lines, "\r\n") + "\r\n"); err != nil {
		t.Fatalf("запись ввода: %v", err)
	}
	w.Close()

	old := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = old; r.Close() })
}

func passwordHash(t *testing.T, d *sql.DB, login string) string {
	t.Helper()
	var hash string
	if err := d.QueryRow("SELECT password_hash FROM users WHERE username=?", login).
		Scan(&hash); err != nil {
		t.Fatalf("хеш %s: %v", login, err)
	}
	return hash
}

// Единственный администратор — выбирать не из чего, спрашивать нечего.
func TestResetPasswordSingleAdmin(t *testing.T) {
	d := resetEnv(t, account{username: "admin", role: "admin", active: true})
	withInput(t, "Novyjparol1", "Novyjparol1")

	if err := resetPassword(""); err != nil {
		t.Fatalf("сброс: %v", err)
	}
	if !auth.VerifyPassword("Novyjparol1", passwordHash(t, d, "admin")) {
		t.Error("новый пароль не подходит — записан не тот хеш")
	}
	if auth.VerifyPassword("Staryjparol1", passwordHash(t, d, "admin")) {
		t.Error("старый пароль всё ещё подходит")
	}
}

// Смена пароля закрывает все прежние сессии: иначе замок сменили, а старый
// ключ остался работать.
func TestResetPasswordClosesSessions(t *testing.T) {
	d := resetEnv(t, account{username: "admin", role: "admin", active: true})

	var id int64
	if err := d.QueryRow("SELECT id FROM users WHERE username='admin'").Scan(&id); err != nil {
		t.Fatalf("id: %v", err)
	}
	if _, err := auth.CreateSession(d, id); err != nil {
		t.Fatalf("сессия: %v", err)
	}

	withInput(t, "Novyjparol1", "Novyjparol1")
	if err := resetPassword(""); err != nil {
		t.Fatalf("сброс: %v", err)
	}

	var left int
	if err := d.QueryRow("SELECT COUNT(*) FROM sessions WHERE user_id=?", id).Scan(&left); err != nil {
		t.Fatalf("счёт сессий: %v", err)
	}
	if left != 0 {
		t.Errorf("осталось сессий: %d, ожидалось 0", left)
	}
}

// Действие попадает в журнал: сброс пароля мимо интерфейса — ровно то, что
// должно быть видно потом.
func TestResetPasswordIsLogged(t *testing.T) {
	d := resetEnv(t, account{username: "admin", role: "admin", active: true})
	withInput(t, "Novyjparol1", "Novyjparol1")
	if err := resetPassword(""); err != nil {
		t.Fatalf("сброс: %v", err)
	}

	var action, target string
	err := d.QueryRow("SELECT action, COALESCE(target,'') FROM audit_log ORDER BY id DESC LIMIT 1").
		Scan(&action, &target)
	if err != nil {
		t.Fatalf("журнал пуст: %v", err)
	}
	if action != "password_reset_console" || target != "admin" {
		t.Errorf("в журнале %q/%q, ожидалось password_reset_console/admin", action, target)
	}
}

// Несколько администраторов — команда обязана спросить, а не выбрать сама.
func TestResetPasswordAsksWhichAdmin(t *testing.T) {
	d := resetEnv(t,
		account{username: "anna", role: "admin", active: true},
		account{username: "boris", role: "admin", active: true},
	)
	withInput(t, "2", "Novyjparol1", "Novyjparol1") // список отсортирован по логину

	if err := resetPassword(""); err != nil {
		t.Fatalf("сброс: %v", err)
	}
	if !auth.VerifyPassword("Novyjparol1", passwordHash(t, d, "boris")) {
		t.Error("пароль второго администратора не изменился")
	}
	if !auth.VerifyPassword("Staryjparol1", passwordHash(t, d, "anna")) {
		t.Error("пароль первого администратора изменился, а его не выбирали")
	}
}

// Отказ и любой невнятный ответ не должны менять ничего.
func TestResetPasswordLeavesEverythingOnRefusal(t *testing.T) {
	cases := []struct {
		name  string
		input []string
	}{
		{"отмена в списке", []string{"0"}},
		{"непонятный выбор", []string{"пять"}},
		{"пароли не совпали", []string{"1", "Novyjparol1", "Drugojparol2"}},
		{"пароль слишком прост", []string{"1", "korotkij"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := resetEnv(t,
				account{username: "anna", role: "admin", active: true},
				account{username: "boris", role: "admin", active: true},
			)
			withInput(t, c.input...)

			if err := resetPassword(""); err == nil {
				t.Fatal("команда доложила об успехе, хотя менять пароль было не на что")
			}
			for _, u := range []string{"anna", "boris"} {
				if !auth.VerifyPassword("Staryjparol1", passwordHash(t, d, u)) {
					t.Errorf("пароль %s изменился, хотя действие не состоялось", u)
				}
			}
		})
	}
}

// Отключённая запись: сменить ей пароль мало — под ней всё равно не войти.
// Команда обязана это заметить и спросить, а не оставить человека с новым
// паролем и тем же отказом на входе.
func TestResetPasswordOffersToEnableAccount(t *testing.T) {
	d := resetEnv(t, account{username: "admin", role: "admin", active: false})
	withInput(t, "Novyjparol1", "Novyjparol1", "y")

	if err := resetPassword(""); err != nil {
		t.Fatalf("сброс: %v", err)
	}
	var active int
	if err := d.QueryRow("SELECT is_active FROM users WHERE username='admin'").
		Scan(&active); err != nil {
		t.Fatalf("is_active: %v", err)
	}
	if active != 1 {
		t.Error("учётная запись осталась отключённой, хотя включить согласились")
	}
}

// Отказались включать — запись остаётся отключённой, но пароль всё равно
// меняется: человек мог знать, что делает.
func TestResetPasswordKeepsAccountDisabledOnRefusal(t *testing.T) {
	d := resetEnv(t, account{username: "admin", role: "admin", active: false})
	withInput(t, "Novyjparol1", "Novyjparol1", "n")

	if err := resetPassword(""); err != nil {
		t.Fatalf("сброс: %v", err)
	}
	var active int
	if err := d.QueryRow("SELECT is_active FROM users WHERE username='admin'").
		Scan(&active); err != nil {
		t.Fatalf("is_active: %v", err)
	}
	if active != 0 {
		t.Error("учётная запись включена, хотя включать отказались")
	}
	if !auth.VerifyPassword("Novyjparol1", passwordHash(t, d, "admin")) {
		t.Error("пароль не изменился")
	}
}

// -user меняет пароль названной записи, в том числе не администратору:
// администратор со своим целым доступом должен уметь помочь коллеге.
func TestResetPasswordByName(t *testing.T) {
	d := resetEnv(t,
		account{username: "admin", role: "admin", active: true},
		account{username: "petrov", role: "user", active: true},
	)
	withInput(t, "Novyjparol1", "Novyjparol1")

	if err := resetPassword("petrov"); err != nil {
		t.Fatalf("сброс: %v", err)
	}
	if !auth.VerifyPassword("Novyjparol1", passwordHash(t, d, "petrov")) {
		t.Error("пароль названной записи не изменился")
	}
	if !auth.VerifyPassword("Staryjparol1", passwordHash(t, d, "admin")) {
		t.Error("изменился пароль не той записи")
	}
}

// Несуществующий логин — отказ, и в сообщении видно, из кого выбирать.
func TestResetPasswordUnknownUser(t *testing.T) {
	resetEnv(t, account{username: "admin", role: "admin", active: true})
	withInput(t, "Novyjparol1", "Novyjparol1")

	err := resetPassword("нетакого")
	if err == nil {
		t.Fatal("несуществующий логин принят")
	}
	if !strings.Contains(err.Error(), "admin") {
		t.Errorf("в сообщении нет подсказки со списком администраторов: %v", err)
	}
}

// Базы нет — команда обязана сказать об этом, а не завести пустую.
func TestResetPasswordWithoutDatabase(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("NETADMIN_DATA_DIR", dir)
	old := installedDBPath
	installedDBPath = func() string { return filepath.Join(dir, "нет", "netadmin.db") }
	t.Cleanup(func() { installedDBPath = old })

	if err := resetPassword(""); err == nil {
		t.Fatal("команда не заметила отсутствия базы")
	}
	if _, err := os.Stat(filepath.Join(dir, "netadmin.db")); err == nil {
		t.Error("команда завела пустую базу вместо отказа")
	}
}

// Аргументы для копии, запущенной через UAC: без -user повышенная копия
// спросила бы заново, а с ним — продолжит начатое.
func TestResetPasswordArgs(t *testing.T) {
	got := strings.Join(resetPasswordArgs(""), " ")
	if got != "-reset-password" {
		t.Errorf("без логина: %q", got)
	}
	got = strings.Join(resetPasswordArgs("anna"), " ")
	if got != "-reset-password -user=anna" {
		t.Errorf("с логином: %q", got)
	}
}
