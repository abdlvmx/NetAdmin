package handlers

import (
	"log"
	"net/http"
	"strconv"
	"strings"

	"netadmin/internal/auth"
	"netadmin/internal/web"
)

type licenseRow struct {
	ID                    int64
	Name, Vendor, Note    string
	Purchased, Used, Over int
	Cost                  float64
}

type licensesPageData struct {
	User      *auth.User
	Active    string
	Rows      []licenseRow
	Msg       string
	TotalCost float64
	TotalOver int
	OverCount int
}

// LicensesPage — GET /licenses : учёт лицензий ПО (куплено vs используется).
func (a *App) LicensesPage(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	data := licensesPageData{User: user, Active: "licenses", Msg: r.URL.Query().Get("message")}

	rows, err := a.DB.Query(`SELECT id, COALESCE(name,''), COALESCE(vendor,''),
		COALESCE(seats_purchased,0), COALESCE(cost,0), COALESCE(note,'')
		FROM software_licenses ORDER BY name`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var lr licenseRow
			if rows.Scan(&lr.ID, &lr.Name, &lr.Vendor, &lr.Purchased, &lr.Cost, &lr.Note) != nil {
				continue
			}
			lr.Used = a.licenseUsage(lr.Name)
			if lr.Used > lr.Purchased {
				lr.Over = lr.Used - lr.Purchased
				data.TotalOver += lr.Over
				data.OverCount++
			}
			data.TotalCost += lr.Cost
			data.Rows = append(data.Rows, lr)
		}
		if err := rows.Err(); err != nil {
			log.Printf("LicensesPage: %v", err)
		}
	}
	web.RenderPage(w, "licenses", data)
}

// licenseUsage — на скольких устройствах установлено ПО, совпадающее по имени.
func (a *App) licenseUsage(name string) int {
	name = strings.TrimSpace(name)
	if name == "" {
		return 0
	}
	var n int
	a.DB.QueryRow(`SELECT COUNT(DISTINCT device_id) FROM software
		WHERE LOWER(COALESCE(name,'')) LIKE '%'||LOWER(?)||'%'`, name).Scan(&n)
	return n
}

// AddLicense — POST /licenses/add (admin).
func (a *App) AddLicense(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil || !user.IsAdmin() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	_ = r.ParseForm()
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		http.Redirect(w, r, "/licenses?message=Укажите+название+ПО", http.StatusSeeOther)
		return
	}
	seats, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("seats_purchased")))
	cost, _ := strconv.ParseFloat(strings.TrimSpace(r.FormValue("cost")), 64)
	a.DB.Exec(`INSERT INTO software_licenses (name, vendor, seats_purchased, cost, note)
		VALUES (?,?,?,?,?)`, name, strings.TrimSpace(r.FormValue("vendor")), seats, cost,
		strings.TrimSpace(r.FormValue("note")))
	auth.LogAction(a.DB, user.ID, "license_add", name, "")
	http.Redirect(w, r, "/licenses?message=Лицензия+добавлена", http.StatusSeeOther)
}

// UpdateLicense — POST /licenses/{id}/update (admin) : правка мест/стоимости.
func (a *App) UpdateLicense(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil || !user.IsAdmin() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	_ = r.ParseForm()
	seats, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("seats_purchased")))
	cost, _ := strconv.ParseFloat(strings.TrimSpace(r.FormValue("cost")), 64)
	a.DB.Exec("UPDATE software_licenses SET seats_purchased=?, cost=? WHERE id=?", seats, cost, id)
	auth.LogAction(a.DB, user.ID, "license_update", strconv.FormatInt(id, 10), "")
	http.Redirect(w, r, "/licenses?message=Лицензия+обновлена", http.StatusSeeOther)
}

// DeleteLicense — POST /licenses/{id}/delete (admin).
func (a *App) DeleteLicense(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil || !user.IsAdmin() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	a.DB.Exec("DELETE FROM software_licenses WHERE id=?", id)
	auth.LogAction(a.DB, user.ID, "license_delete", strconv.FormatInt(id, 10), "")
	http.Redirect(w, r, "/licenses?message=Лицензия+удалена", http.StatusSeeOther)
}
