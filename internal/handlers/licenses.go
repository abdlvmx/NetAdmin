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
		for rows.Next() {
			var lr licenseRow
			if rows.Scan(&lr.ID, &lr.Name, &lr.Vendor, &lr.Purchased, &lr.Cost, &lr.Note) != nil {
				continue
			}
			data.Rows = append(data.Rows, lr)
		}
		if err := rows.Err(); err != nil {
			log.Printf("LicensesPage: %v", err)
		}
		rows.Close()
	}

	// Использование считаем одним проходом для всех лицензий сразу. Раньше на
	// каждую строку шёл отдельный запрос с `LIKE '%…%'`, то есть полный проход
	// по таблице ПО: на 300 машинах и 20 лицензиях страница отдавалась ~270 мс.
	names := make([]string, 0, len(data.Rows))
	for _, lr := range data.Rows {
		names = append(names, lr.Name)
	}
	usage := a.licenseUsageAll(names)
	for i := range data.Rows {
		lr := &data.Rows[i]
		lr.Used = usage[strings.ToLower(strings.TrimSpace(lr.Name))]
		if lr.Used > lr.Purchased {
			lr.Over = lr.Used - lr.Purchased
			data.TotalOver += lr.Over
			data.OverCount++
		}
		data.TotalCost += lr.Cost
	}
	web.RenderPage(w, "licenses", data)
}

// licenseUsageAll считает использование сразу для всех лицензий: сколько
// устройств несут ПО, подходящее под каждое название. Ключи результата —
// названия, приведённые к нижнему регистру и без крайних пробелов.
//
// Одна выборка вместо запроса на лицензию, а сопоставление — в Go: `LIKE '%…%'`
// в SQLite стоит около пяти миллисекунд на условие при 45 тысячах строк ПО,
// тогда как прочитать всю таблицу и сравнить строки в памяти — втрое дешевле.
// Подробности замеров — в комментарии к forbiddenScan.
func (a *App) licenseUsageAll(names []string) map[string]int {
	type key struct {
		name string
		dev  int64
	}
	seen := map[key]bool{}
	out := map[string]int{}

	clean := make([]string, 0, len(names))
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		low := strings.ToLower(n)
		if _, ok := out[low]; ok {
			continue // одно и то же название в двух строках — считаем один раз
		}
		out[low] = 0
		clean = append(clean, low)
	}
	if len(clean) == 0 {
		return out
	}

	rows, err := a.DB.Query(`SELECT device_id, LOWER(COALESCE(name,'')) FROM software`)
	if err != nil {
		log.Printf("licenseUsageAll: %v", err)
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var dev int64
		var sw string
		if rows.Scan(&dev, &sw) != nil {
			continue
		}
		for _, n := range clean {
			if !strings.Contains(sw, n) {
				continue
			}
			k := key{n, dev}
			if !seen[k] { // одно устройство считается один раз, как DISTINCT раньше
				seen[k] = true
				out[n]++
			}
		}
	}
	if err := rows.Err(); err != nil {
		log.Printf("licenseUsageAll: %v", err)
	}
	return out
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
