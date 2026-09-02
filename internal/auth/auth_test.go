package auth

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"netadmin/internal/db"
)

func testDB(t *testing.T) *sql.DB {
	t.Helper()
	dir, err := os.MkdirTemp("", "authtest")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	d, err := db.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
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

func newUser(t *testing.T, d *sql.DB, name, role string) int64 {
	t.Helper()
	h, err := HashPassword("Parol12345")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	res, err := d.Exec("INSERT INTO users (username, role, password_hash) VALUES (?,?,?)", name, role, h)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	id, _ := res.LastInsertId()
	return id
}

// reqWith возвращает запрос с cookie сессии.
func reqWith(token string) *http.Request {
	r := httptest.NewRequest("GET", "/dashboard", nil)
	r.AddCookie(&http.Cookie{Name: "session", Value: token})
	return r
}

// Токен сессии не должен храниться в базе в открытом виде: доступ к файлу БД
// или к её копии не должен позволять выдать себя за вошедшего пользователя.
func TestSessionTokenStoredHashed(t *testing.T) {
	d := testDB(t)
	id := newUser(t, d, "admin", "admin")
	token, err := CreateSession(d, id)
	if err != nil {
		t.Fatalf("session: %v", err)
	}

	var stored string
	if err := d.QueryRow("SELECT token FROM sessions").Scan(&stored); err != nil {
		t.Fatalf("select: %v", err)
	}
	if stored == token {
		t.Fatal("токен сессии лежит в базе открытым текстом")
	}
	if len(stored) != 64 {
		t.Fatalf("ожидался hex sha256 (64 символа), получено %d", len(stored))
	}
	// значение из базы не должно работать как cookie
	if u := CurrentUser(d, reqWith(stored)); u != nil {
		t.Fatal("хеш из базы принят как действующий токен сессии")
	}
	// а настоящий токен — должен
	if u := CurrentUser(d, reqWith(token)); u == nil || u.ID != id {
		t.Fatal("настоящий токен сессии не распознан")
	}
}

// Отключение учётной записи должно немедленно лишать доступа, а не действовать
// только со следующего входа.
func TestDisabledUserLosesSession(t *testing.T) {
	d := testDB(t)
	id := newUser(t, d, "operator", "user")
	token, _ := CreateSession(d, id)

	if u := CurrentUser(d, reqWith(token)); u == nil {
		t.Fatal("активный пользователь должен распознаваться")
	}
	if _, err := d.Exec("UPDATE users SET is_active=0 WHERE id=?", id); err != nil {
		t.Fatalf("update: %v", err)
	}
	if u := CurrentUser(d, reqWith(token)); u != nil {
		t.Fatal("отключённый пользователь продолжает работать по старой сессии")
	}
}

func TestDeleteUserSessions(t *testing.T) {
	d := testDB(t)
	id := newUser(t, d, "temp", "viewer")
	token, _ := CreateSession(d, id)
	DeleteUserSessions(d, id)
	if u := CurrentUser(d, reqWith(token)); u != nil {
		t.Fatal("сессия должна была пропасть вместе с учётной записью")
	}
}

func TestLogoutDeletesSession(t *testing.T) {
	d := testDB(t)
	id := newUser(t, d, "bye", "admin")
	token, _ := CreateSession(d, id)
	DeleteSession(d, token)

	var n int
	d.QueryRow("SELECT COUNT(*) FROM sessions").Scan(&n)
	if n != 0 {
		t.Fatalf("сессия должна удаляться по настоящему токену, осталось %d", n)
	}
}

func TestPurgeExpiredSessions(t *testing.T) {
	d := testDB(t)
	id := newUser(t, d, "old", "admin")
	live, _ := CreateSession(d, id)
	d.Exec("INSERT INTO sessions (token, user_id, expires_at, last_activity) VALUES ('stale',?,datetime('now','-1 hour'),datetime('now'))", id)

	PurgeExpiredSessions(d)

	var n int
	d.QueryRow("SELECT COUNT(*) FROM sessions").Scan(&n)
	if n != 1 {
		t.Fatalf("должна остаться одна живая сессия, осталось %d", n)
	}
	if u := CurrentUser(d, reqWith(live)); u == nil {
		t.Fatal("живая сессия не должна вычищаться")
	}
}

func TestRoles(t *testing.T) {
	cases := []struct {
		role     string
		admin    bool
		canWrite bool
	}{
		{"admin", true, true},
		{"user", false, true},
		{"viewer", false, false},
	}
	for _, c := range cases {
		u := &User{Role: c.role}
		if u.IsAdmin() != c.admin {
			t.Errorf("%s: IsAdmin=%v, ожидалось %v", c.role, u.IsAdmin(), c.admin)
		}
		if u.CanWrite() != c.canWrite {
			t.Errorf("%s: CanWrite=%v, ожидалось %v", c.role, u.CanWrite(), c.canWrite)
		}
	}
	// nil-пользователь не должен давать прав: хендлеры полагаются на это
	var nilUser *User
	if nilUser.IsAdmin() || nilUser.CanWrite() {
		t.Error("nil-пользователь не должен иметь прав")
	}
}

func TestWeakPassword(t *testing.T) {
	weak := []string{"", "korotk1", "abcdefgh", "12345678", "паролик"}
	for _, pw := range weak {
		if !WeakPassword(pw) {
			t.Errorf("%q должен считаться слабым", pw)
		}
	}
	strong := []string{"Parol12345", "abcdefg1", "пароль1234"}
	for _, pw := range strong {
		if WeakPassword(pw) {
			t.Errorf("%q должен проходить политику", pw)
		}
	}
}

func TestVerifyPassword(t *testing.T) {
	h, err := HashPassword("Parol12345")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if !VerifyPassword("Parol12345", h) {
		t.Error("верный пароль должен проходить")
	}
	if VerifyPassword("Parol12346", h) {
		t.Error("неверный пароль не должен проходить")
	}
	if VerifyPassword("Parol12345", "не-хеш") {
		t.Error("битый хеш не должен давать доступ")
	}
}

// VerifyDummy существует ради постоянного времени ответа: она обязана
// отработать без паники и ничего не возвращать.
func TestVerifyDummy(t *testing.T) {
	VerifyDummy("что угодно")
}
