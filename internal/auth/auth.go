// Package auth — пароли (bcrypt), сессии, текущий пользователь, аудит.
package auth

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"net/http"
	"time"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

// WeakPassword — пароль не проходит политику (минимум 8 символов, есть буква и цифра).
func WeakPassword(pw string) bool {
	if len(pw) < 8 {
		return true
	}
	var hasLetter, hasDigit bool
	for _, r := range pw {
		switch {
		case unicode.IsLetter(r):
			hasLetter = true
		case unicode.IsDigit(r):
			hasDigit = true
		}
	}
	return !(hasLetter && hasDigit)
}

// формат времени, совместимый со строковым сравнением с datetime('now') в SQLite
const sqlTimeLayout = "2006-01-02 15:04:05"

// sessionIdle — максимум простоя сессии; touchInterval — как часто обновляем last_activity
const (
	sessionIdle   = 20 * time.Minute
	touchInterval = 60 * time.Second
)

// User — пользователь системы.
type User struct {
	ID       int64
	Username string
	FullName string
	Email    string
	Role     string
	IsActive int
}

// IsAdmin — полный доступ.
func (u *User) IsAdmin() bool { return u != nil && u.Role == "admin" }

// CanWrite — право изменять инвентарь/запускать скан (admin и user/operator,
// но не viewer).
func (u *User) CanWrite() bool { return u != nil && (u.Role == "admin" || u.Role == "user") }

func HashPassword(pw string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(b), err
}

func VerifyPassword(pw, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}

// CreateSession создаёт сессию (8ч жизни, idle-таймаут отдельно) и возвращает токен.
func CreateSession(db *sql.DB, userID int64) (string, error) {
	token := randomHex(32)
	now := time.Now().UTC()
	expires := now.Add(8 * time.Hour).Format(sqlTimeLayout)
	la := now.Format(sqlTimeLayout)
	_, err := db.Exec(
		"INSERT INTO sessions (token, user_id, expires_at, last_activity) VALUES (?,?,?,?)",
		token, userID, expires, la,
	)
	return token, err
}

// CurrentUser возвращает пользователя по cookie сессии или nil.
// Заодно проверяет idle-таймаут (20 мин бездействия) и продлевает активность.
func CurrentUser(db *sql.DB, r *http.Request) *User {
	c, err := r.Cookie("session")
	if err != nil || c.Value == "" {
		return nil
	}
	row := db.QueryRow(`
		SELECT u.id, u.username, u.full_name, u.email, u.role, u.is_active, COALESCE(s.last_activity,'')
		FROM sessions s JOIN users u ON s.user_id = u.id
		WHERE s.token = ? AND s.expires_at > datetime('now')`, c.Value)
	var u User
	var fullName, email sql.NullString
	var la string
	if err := row.Scan(&u.ID, &u.Username, &fullName, &email, &u.Role, &u.IsActive, &la); err != nil {
		return nil
	}
	u.FullName = fullName.String
	u.Email = email.String

	now := time.Now().UTC()
	if t, e := time.Parse(sqlTimeLayout, la); e == nil {
		if now.Sub(t) > sessionIdle {
			DeleteSession(db, c.Value) // простой превышен — гасим сессию
			return nil
		}
		if now.Sub(t) > touchInterval {
			db.Exec("UPDATE sessions SET last_activity=? WHERE token=?", now.Format(sqlTimeLayout), c.Value)
		}
	} else {
		// нет/битое last_activity (легаси-сессия) — проставляем текущее
		db.Exec("UPDATE sessions SET last_activity=? WHERE token=?", now.Format(sqlTimeLayout), c.Value)
	}
	return &u
}

// DeleteSession удаляет сессию по токену (выход).
func DeleteSession(db *sql.DB, token string) {
	_, _ = db.Exec("DELETE FROM sessions WHERE token = ?", token)
}

// HasUsers — есть ли хоть один пользователь (для мастера первого запуска).
func HasUsers(db *sql.DB) bool {
	var n int
	_ = db.QueryRow("SELECT COUNT(*) FROM users").Scan(&n)
	return n > 0
}

// LogAction пишет запись в журнал действий.
func LogAction(db *sql.DB, userID int64, action, target, detail string) {
	_, _ = db.Exec(
		"INSERT INTO audit_log (user_id, action, target, detail) VALUES (?,?,?,?)",
		userID, action, target, detail,
	)
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
