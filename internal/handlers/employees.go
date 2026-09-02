package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"

	"netadmin/internal/auth"
	"netadmin/internal/web"
)

type empRow struct {
	ID             int64  `json:"id"`
	FullName       string `json:"full_name"`
	Position       string `json:"position"`
	Email          string `json:"email"`
	Phone          string `json:"phone"`
	Notes          string `json:"notes"`
	DepartmentID   int64  `json:"department_id"`
	DepartmentName string `json:"-"`
	IsActive       int    `json:"-"`
	DevicesCount   int    `json:"-"`
}

type deptRow struct {
	ID   int64
	Name string
}

type employeesData struct {
	User        *auth.User
	Active      string
	Employees   []empRow
	Departments []deptRow
	// EmployeesJSON — справочник для формы редактирования. Обычная строка:
	// значение уезжает в data-атрибут и разбирается через JSON.parse, а не
	// вставляется в тело скрипта. Прежний template.JS отключал экранирование
	// и держался на том, что json.Marshal сам экранирует «<» — незаметное
	// изменение сериализации открыло бы внедрение скрипта.
	EmployeesJSON string
}

// EmployeesPage — GET /employees.
func (a *App) EmployeesPage(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	emps := a.listEmployeesFull()
	raw, _ := json.Marshal(emps)
	web.RenderPage(w, "employees", employeesData{
		User:          user,
		Active:        "employees",
		Employees:     emps,
		Departments:   a.listDepartments(),
		EmployeesJSON: string(raw),
	})
}

func (a *App) listEmployeesFull() []empRow {
	rows, err := a.DB.Query(`
		SELECT e.id, e.full_name, COALESCE(e.position,''), COALESCE(e.email,''),
		       COALESCE(e.phone,''), COALESCE(e.notes,''), COALESCE(e.department_id,0),
		       COALESCE(d.name,''), e.is_active, COUNT(dev.id)
		FROM employees e
		LEFT JOIN departments d ON e.department_id=d.id
		LEFT JOIN devices dev ON dev.employee_id=e.id
		GROUP BY e.id
		ORDER BY e.is_active DESC, e.full_name`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []empRow
	for rows.Next() {
		var e empRow
		if rows.Scan(&e.ID, &e.FullName, &e.Position, &e.Email, &e.Phone, &e.Notes,
			&e.DepartmentID, &e.DepartmentName, &e.IsActive, &e.DevicesCount) == nil {
			out = append(out, e)
		}
	}
	if err := rows.Err(); err != nil {
		log.Printf("listEmployeesFull: %v", err)
	}
	return out
}

func (a *App) listDepartments() []deptRow {
	rows, err := a.DB.Query("SELECT id, name FROM departments ORDER BY name")
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []deptRow
	for rows.Next() {
		var d deptRow
		if rows.Scan(&d.ID, &d.Name) == nil {
			out = append(out, d)
		}
	}
	if err := rows.Err(); err != nil {
		log.Printf("listDepartments: %v", err)
	}
	return out
}

// CreateDepartment — POST /departments/create (admin).
func (a *App) CreateDepartment(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil || user.Role != "admin" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name != "" {
		if _, err := a.DB.Exec("INSERT INTO departments (name) VALUES (?)", name); err == nil {
			auth.LogAction(a.DB, user.ID, "create_department", name, "")
		}
	}
	http.Redirect(w, r, "/employees", http.StatusSeeOther)
}

// CreateEmployee — POST /employees/create (admin).
func (a *App) CreateEmployee(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil || user.Role != "admin" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	_ = r.ParseForm()
	f := r.FormValue
	_, err := a.DB.Exec(`
		INSERT INTO employees (full_name, position, email, phone, department_id, notes)
		VALUES (?,?,?,?,?,?)`,
		strings.TrimSpace(f("full_name")), strings.TrimSpace(f("position")),
		strings.TrimSpace(f("email")), strings.TrimSpace(f("phone")),
		employeeParam(f("department_id")), strings.TrimSpace(f("notes")))
	if err == nil {
		auth.LogAction(a.DB, user.ID, "create_employee", f("full_name"), "")
	}
	http.Redirect(w, r, "/employees", http.StatusSeeOther)
}

// UpdateEmployee — POST /employees/{id}/update (admin).
func (a *App) UpdateEmployee(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil || user.Role != "admin" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	_ = r.ParseForm()
	f := r.FormValue
	_, err := a.DB.Exec(`
		UPDATE employees SET full_name=?, position=?, email=?, phone=?, department_id=?, notes=?
		WHERE id=?`,
		strings.TrimSpace(f("full_name")), strings.TrimSpace(f("position")),
		strings.TrimSpace(f("email")), strings.TrimSpace(f("phone")),
		employeeParam(f("department_id")), strings.TrimSpace(f("notes")), id)
	if err == nil {
		auth.LogAction(a.DB, user.ID, "update_employee", f("full_name"), "")
	}
	http.Redirect(w, r, "/employees", http.StatusSeeOther)
}

// ToggleEmployee — POST /employees/{id}/toggle (admin).
func (a *App) ToggleEmployee(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil || user.Role != "admin" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var name string
	var active int
	if a.DB.QueryRow("SELECT full_name, is_active FROM employees WHERE id=?", id).
		Scan(&name, &active) == nil {
		newStatus := 1 - active
		a.DB.Exec("UPDATE employees SET is_active=? WHERE id=?", newStatus, id)
		auth.LogAction(a.DB, user.ID, "toggle_employee", name, "active="+strconv.Itoa(newStatus))
	}
	http.Redirect(w, r, "/employees", http.StatusSeeOther)
}
