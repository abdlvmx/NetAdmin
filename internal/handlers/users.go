package handlers

import (
	"log"
	"net/http"
	"strconv"
	"strings"

	"netadmin/internal/auth"
	"netadmin/internal/tz"
	"netadmin/internal/web"
)

type userRow struct {
	ID        int64
	Username  string
	FullName  string
	Email     string
	Role      string
	IsActive  int
	CreatedAt string
}

type usersData struct {
	User     *auth.User
	Active   string
	AllUsers []userRow
}

// UsersPage — GET /users.
func (a *App) UsersPage(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	var all []userRow
	rows, err := a.DB.Query(`
		SELECT id, username, COALESCE(full_name,''), COALESCE(email,''), role, is_active,
		       COALESCE(created_at,'')
		FROM users ORDER BY created_at DESC`)
	if err != nil {
		log.Printf("список пользователей: %v", err)
	} else {
		defer rows.Close()
		for rows.Next() {
			var u userRow
			if rows.Scan(&u.ID, &u.Username, &u.FullName, &u.Email, &u.Role, &u.IsActive, &u.CreatedAt) == nil {
				u.CreatedAt = tz.DateTime(u.CreatedAt)
				all = append(all, u)
			}
		}
		// без этой проверки оборванная выборка молча показалась бы неполной
		if err := rows.Err(); err != nil {
			log.Printf("список пользователей: %v", err)
		}
	}
	web.RenderPage(w, "users", usersData{User: user, Active: "users", AllUsers: all})
}

// CreateUser — POST /users/create (admin).
func (a *App) CreateUser(w http.ResponseWriter, r *http.Request) {
	admin := auth.CurrentUser(a.DB, r)
	if admin == nil || admin.Role != "admin" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	_ = r.ParseForm()
	f := r.FormValue
	role := f("role")
	if role != "admin" && role != "viewer" {
		role = "user"
	}
	if auth.WeakPassword(f("password")) {
		// слабый пароль — не создаём (клиентский minlength=8 ловит большинство)
		http.Redirect(w, r, "/users", http.StatusSeeOther)
		return
	}
	hash, err := auth.HashPassword(f("password"))
	if err == nil {
		if _, err := a.DB.Exec(
			"INSERT INTO users (username, full_name, email, role, password_hash) VALUES (?,?,?,?,?)",
			strings.TrimSpace(f("username")), strings.TrimSpace(f("full_name")),
			strings.TrimSpace(f("email")), role, hash); err == nil {
			auth.LogAction(a.DB, admin.ID, "create_user", f("username"), "")
		}
		// дубликат username (UNIQUE) — молча игнорируем, как в Python-версии
	}
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

// ToggleUser — POST /users/{id}/toggle (admin).
func (a *App) ToggleUser(w http.ResponseWriter, r *http.Request) {
	admin := auth.CurrentUser(a.DB, r)
	if admin == nil || admin.Role != "admin" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var name string
	var active int
	if a.DB.QueryRow("SELECT username, is_active FROM users WHERE id=?", id).Scan(&name, &active) == nil {
		newStatus := 1 - active
		a.DB.Exec("UPDATE users SET is_active=? WHERE id=?", newStatus, id)
		auth.LogAction(a.DB, admin.ID, "toggle_user", name, "active="+strconv.Itoa(newStatus))
	}
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

// DeleteUser — POST /users/{id}/delete (admin, нельзя себя).
func (a *App) DeleteUser(w http.ResponseWriter, r *http.Request) {
	admin := auth.CurrentUser(a.DB, r)
	if admin == nil || admin.Role != "admin" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if id != admin.ID {
		var name string
		if a.DB.QueryRow("SELECT username FROM users WHERE id=?", id).Scan(&name) == nil {
			a.DB.Exec("DELETE FROM users WHERE id=?", id)
			auth.LogAction(a.DB, admin.ID, "delete_user", name, "")
		}
	}
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}
