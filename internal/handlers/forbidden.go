package handlers

import (
	"log"
	"net/http"
	"strconv"
	"strings"

	"netadmin/internal/auth"
	"netadmin/internal/web"
)

// типовой набор запрещённого/нежелательного ПО для вузов (заполняется по кнопке).
var defaultForbidden = []struct{ pat, cat string }{
	{"utorrent", "Торренты"}, {"bittorrent", "Торренты"}, {"qbittorrent", "Торренты"}, {"mediaget", "Торренты"},
	{"steam", "Игры"}, {"epic games", "Игры"}, {"battle.net", "Игры"}, {"origin", "Игры"},
	{"gog galaxy", "Игры"}, {"roblox", "Игры"}, {"world of tanks", "Игры"},
	{"nicehash", "Майнеры"}, {"xmrig", "Майнеры"}, {"phoenixminer", "Майнеры"}, {"claymore", "Майнеры"}, {"cgminer", "Майнеры"},
}

type forbRule struct {
	ID                      int64
	Pattern, Category, Note string
}

type forbFinding struct {
	Hostname, Software, Category string
}

type forbiddenPageData struct {
	User          *auth.User
	Active        string
	Rules         []forbRule
	Findings      []forbFinding
	AffectedHosts int
	Msg           string
}

// ForbiddenPage — GET /forbidden : чёрный список ПО + отчёт «где найдено».
func (a *App) ForbiddenPage(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	data := forbiddenPageData{User: user, Active: "forbidden", Msg: r.URL.Query().Get("message")}
	data.Rules, data.Findings, data.AffectedHosts = a.forbiddenScan()
	web.RenderPage(w, "forbidden", data)
}

// forbiddenScan загружает правила и находит совпадения в инвентаре ПО.
func (a *App) forbiddenScan() ([]forbRule, []forbFinding, int) {
	var rules []forbRule
	if rows, err := a.DB.Query("SELECT id, COALESCE(pattern,''), COALESCE(category,''), COALESCE(note,'') FROM forbidden_software ORDER BY category, pattern"); err == nil {
		for rows.Next() {
			var fr forbRule
			if rows.Scan(&fr.ID, &fr.Pattern, &fr.Category, &fr.Note) == nil {
				rules = append(rules, fr)
			}
		}
		if err := rows.Err(); err != nil {
			log.Printf("forbiddenScan: %v", err)
		}
		rows.Close()
	}
	var findings []forbFinding
	hosts := map[string]bool{}
	for _, fr := range rules {
		if strings.TrimSpace(fr.Pattern) == "" {
			continue
		}
		frows, err := a.DB.Query(`SELECT d.hostname, s.name FROM software s
			JOIN devices d ON d.id=s.device_id
			WHERE LOWER(COALESCE(s.name,'')) LIKE '%'||LOWER(?)||'%'
			ORDER BY d.hostname`, fr.Pattern)
		if err != nil {
			continue
		}
		for frows.Next() {
			var host, sw string
			if frows.Scan(&host, &sw) == nil {
				findings = append(findings, forbFinding{Hostname: host, Software: sw, Category: fr.Category})
				hosts[host] = true
			}
		}
		if err := frows.Err(); err != nil {
			log.Printf("forbiddenScan: %v", err)
		}
		frows.Close()
	}
	return rules, findings, len(hosts)
}

// AddForbidden — POST /forbidden/add (admin).
func (a *App) AddForbidden(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil || !user.IsAdmin() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	_ = r.ParseForm()
	pat := strings.TrimSpace(r.FormValue("pattern"))
	if pat == "" {
		http.Redirect(w, r, "/forbidden?message=Укажите+название+ПО", http.StatusSeeOther)
		return
	}
	cat := strings.TrimSpace(r.FormValue("category"))
	if cat == "" {
		cat = "Прочее"
	}
	a.DB.Exec("INSERT INTO forbidden_software (pattern, category, note) VALUES (?,?,?)",
		pat, cat, strings.TrimSpace(r.FormValue("note")))
	auth.LogAction(a.DB, user.ID, "forbidden_add", pat, cat)
	http.Redirect(w, r, "/forbidden?message=Правило+добавлено", http.StatusSeeOther)
}

// DeleteForbidden — POST /forbidden/{id}/delete (admin).
func (a *App) DeleteForbidden(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil || !user.IsAdmin() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	a.DB.Exec("DELETE FROM forbidden_software WHERE id=?", id)
	http.Redirect(w, r, "/forbidden?message=Правило+удалено", http.StatusSeeOther)
}

// SeedForbidden — POST /forbidden/seed (admin) : добавить типовой набор (без дублей).
func (a *App) SeedForbidden(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil || !user.IsAdmin() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	for _, d := range defaultForbidden {
		var exists int
		a.DB.QueryRow("SELECT 1 FROM forbidden_software WHERE LOWER(pattern)=LOWER(?) LIMIT 1", d.pat).Scan(&exists)
		if exists != 1 {
			a.DB.Exec("INSERT INTO forbidden_software (pattern, category) VALUES (?,?)", d.pat, d.cat)
		}
	}
	auth.LogAction(a.DB, user.ID, "forbidden_seed", "", "")
	http.Redirect(w, r, "/forbidden?message=Типовой+набор+добавлен", http.StatusSeeOther)
}
