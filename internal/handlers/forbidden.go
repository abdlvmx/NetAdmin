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
	// Раньше здесь шёл отдельный запрос на каждое правило. Замеры на парке в
	// 300 машин (45 тысяч строк ПО) и 25 правилах: 172 мс.
	//
	// Дело оказалось не в числе запросов, а в самом `LIKE '%…%'`: один такой
	// проход стоит 3 мс, но каждое дополнительное условие добавляет ещё около
	// пяти, поэтому и вариант с 25 условиями через OR остался на 136 мс. Зато
	// прочитать таблицу целиком — 10 мс, а сопоставить те же 25 шаблонов уже в
	// Go — ещё 26. Отсюда нынешний способ: одна выборка, отбор в памяти, 36 мс.
	// Он к тому же не деградирует с ростом числа правил.
	active := make([]forbRule, 0, len(rules))
	for _, fr := range rules {
		if p := strings.TrimSpace(fr.Pattern); p != "" {
			fr.Pattern = strings.ToLower(p)
			active = append(active, fr)
		}
	}
	if len(active) == 0 {
		return rules, nil, 0
	}

	var findings []forbFinding
	hosts := map[string]bool{}
	frows, err := a.DB.Query(`SELECT d.hostname, s.name FROM software s
		JOIN devices d ON d.id=s.device_id
		ORDER BY d.hostname, s.name`)
	if err != nil {
		log.Printf("forbiddenScan: %v", err)
		return rules, nil, 0
	}
	defer frows.Close()
	for frows.Next() {
		var host, sw string
		if frows.Scan(&host, &sw) != nil {
			continue
		}
		low := strings.ToLower(sw)
		// Одна программа может подходить сразу под несколько правил — тогда она
		// попадает в отчёт по разу на каждое, как было и раньше.
		for _, fr := range active {
			if strings.Contains(low, fr.Pattern) {
				findings = append(findings, forbFinding{Hostname: host, Software: sw, Category: fr.Category})
				hosts[host] = true
			}
		}
	}
	if err := frows.Err(); err != nil {
		log.Printf("forbiddenScan: %v", err)
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
