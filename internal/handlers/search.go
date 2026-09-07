package handlers

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	"netadmin/internal/auth"
)

// searchItem — одна строка результата поиска.
type searchItem struct {
	Label string `json:"label"` // основное: имя машины, ФИО, название программы
	Sub   string `json:"sub"`   // уточнение: адрес, должность, где установлено
	Href  string `json:"href"`  // куда ведёт
}

// searchGroup — результаты одного раздела.
type searchGroup struct {
	Title string       `json:"title"`
	Items []searchItem `json:"items"`
}

// searchLimit — сколько строк показываем в каждой группе. Поиск нужен, чтобы
// быстро попасть в нужное место, а не просматривать выдачу: если совпадений
// больше, точнее сработает уточнённый запрос, а не длинный список.
const searchLimit = 6

// Search — GET /api/search?q=… : поиск сразу по всем разделам.
//
// Раньше искать можно было только внутри раздела, и это требовало заранее
// знать, где искомое лежит: программы — в карточке устройства, люди — в
// сотрудниках, машины — в устройствах. Вопрос «на какой машине стоит uTorrent»
// или «чей компьютер в 205-м» требовал обхода разделов.
//
// Сравнение идёт в Go, а не через LIKE в SQL: SQLite приводит регистр только
// для латиницы, поэтому «смирнова» не нашла бы «Смирнова» — в русском интерфейсе
// это половина запросов.
func (a *App) Search(w http.ResponseWriter, r *http.Request) {
	if auth.CurrentUser(a.DB, r) == nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	// По одному символу выдача бессмысленна: совпадёт почти всё.
	if len([]rune(q)) < 2 {
		writeJSON(w, map[string]any{"groups": []searchGroup{}})
		return
	}

	groups := []searchGroup{}
	add := func(title string, items []searchItem) {
		if len(items) > 0 {
			groups = append(groups, searchGroup{Title: title, Items: items})
		}
	}
	add("Устройства", a.searchDevices(q))
	add("Сотрудники", a.searchEmployees(q))
	add("Программы", a.searchSoftware(q))
	add("Заявки", a.searchTickets(q))

	writeJSON(w, map[string]any{"groups": groups})
}

// matches — совпадение без учёта регистра по любому из полей.
func matches(q string, fields ...string) bool {
	for _, f := range fields {
		if f != "" && strings.Contains(strings.ToLower(f), q) {
			return true
		}
	}
	return false
}

// joinParts склеивает непустые уточнения в одну строку.
func joinParts(parts ...string) string {
	var kept []string
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			kept = append(kept, s)
		}
	}
	return strings.Join(kept, " · ")
}

// searchDevices ищет по имени, адресам, расположению и владельцу.
func (a *App) searchDevices(q string) []searchItem {
	rows, err := a.DB.Query(`SELECT d.id, COALESCE(d.hostname,''), COALESCE(d.ip_address,''),
		COALESCE(d.mac_address,''), COALESCE(d.location,''), COALESCE(e.full_name,'')
		FROM devices d LEFT JOIN employees e ON e.id = d.employee_id
		ORDER BY d.hostname`)
	if err != nil {
		log.Printf("поиск (устройства): %v", err)
		return nil
	}
	defer rows.Close()
	var out []searchItem
	for rows.Next() && len(out) < searchLimit {
		var id int64
		var host, ip, mac, loc, owner string
		if rows.Scan(&id, &host, &ip, &mac, &loc, &owner) != nil {
			continue
		}
		if !matches(q, host, ip, mac, loc, owner) {
			continue
		}
		out = append(out, searchItem{
			Label: host,
			Sub:   joinParts(ip, loc, owner),
			Href:  fmt.Sprintf("/devices/%d", id),
		})
	}
	return out
}

// searchEmployees ищет людей по имени, должности и почте.
func (a *App) searchEmployees(q string) []searchItem {
	rows, err := a.DB.Query(`SELECT COALESCE(e.full_name,''), COALESCE(e.position,''),
		COALESCE(e.email,''), COALESCE(dep.name,'')
		FROM employees e LEFT JOIN departments dep ON dep.id = e.department_id
		ORDER BY e.full_name`)
	if err != nil {
		log.Printf("поиск (сотрудники): %v", err)
		return nil
	}
	defer rows.Close()
	var out []searchItem
	for rows.Next() && len(out) < searchLimit {
		var name, pos, mail, dept string
		if rows.Scan(&name, &pos, &mail, &dept) != nil {
			continue
		}
		if !matches(q, name, pos, mail) {
			continue
		}
		out = append(out, searchItem{Label: name, Sub: joinParts(pos, dept), Href: "/employees"})
	}
	return out
}

// searchSoftware отвечает на вопрос «где это установлено»: одна строка на
// программу, а не на каждую копию, иначе выдачу забьёт одно название.
//
// Группировка идёт в SQL: уникальных названий сотни, тогда как строк
// установленного ПО на парке — десятки тысяч.
func (a *App) searchSoftware(q string) []searchItem {
	rows, err := a.DB.Query(`SELECT s.name, COUNT(DISTINCT s.device_id) AS cnt
		FROM software s WHERE COALESCE(s.name,'')<>''
		GROUP BY s.name ORDER BY cnt DESC, s.name`)
	if err != nil {
		log.Printf("поиск (программы): %v", err)
		return nil
	}
	defer rows.Close()
	var out []searchItem
	for rows.Next() && len(out) < searchLimit {
		var name string
		var cnt int
		if rows.Scan(&name, &cnt) != nil || !matches(q, name) {
			continue
		}
		out = append(out, searchItem{
			Label: name,
			Sub:   fmt.Sprintf("установлено на %d ПК", cnt),
			Href:  "/devices?software=" + url.QueryEscape(name),
		})
	}
	return out
}

// searchTickets ищет заявки по коду, теме и заявителю.
func (a *App) searchTickets(q string) []searchItem {
	rows, err := a.DB.Query(`SELECT id, COALESCE(code,''), COALESCE(title,''),
		COALESCE(reporter_name,''), COALESCE(status,'')
		FROM tickets ORDER BY created_at DESC`)
	if err != nil {
		log.Printf("поиск (заявки): %v", err)
		return nil
	}
	defer rows.Close()
	var out []searchItem
	for rows.Next() && len(out) < searchLimit {
		var id int64
		var code, title, who, status string
		if rows.Scan(&id, &code, &title, &who, &status) != nil {
			continue
		}
		if !matches(q, code, title, who) {
			continue
		}
		out = append(out, searchItem{
			Label: joinParts(code, title),
			Sub:   joinParts(who, statusLabel(status)),
			Href:  fmt.Sprintf("/tickets/%d", id),
		})
	}
	return out
}
