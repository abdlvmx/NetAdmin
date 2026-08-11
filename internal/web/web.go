// Package web — встроенные (go:embed) шаблоны и помощники рендеринга.
//
// Две модели рендера:
//   - standalone: цельные страницы без layout (login, setup);
//   - layout-страницы: layout.html + страница, которая определяет {{define "content"}}.
package web

import (
	"embed"
	"html/template"
	"net/http"
	"strings"

	"netadmin/internal/tz"
)

//go:embed templates
var fsys embed.FS

var funcMap = template.FuncMap{
	"upper":       strings.ToUpper,
	"actionIcon":  actionIcon,
	"actionCat":   actionCat,
	"today":       tz.TodayRU,
	"statusRu":    statusRu,
	"statusBadge": statusBadge,
	"prioRu":      prioRu,
	"prioBadge":   prioBadge,
}

// statusRu/statusBadge/prioRu/prioBadge — подписи и классы бейджей для заявок helpdesk.
func statusRu(s string) string {
	switch s {
	case "new":
		return "Новая"
	case "in_progress":
		return "В работе"
	case "resolved":
		return "Решена"
	case "closed":
		return "Закрыта"
	}
	return s
}

func statusBadge(s string) string {
	switch s {
	case "new":
		return "badge-amber"
	case "in_progress":
		return "badge-accent"
	case "resolved":
		return "badge-green"
	case "closed":
		return "badge-gray"
	}
	return "badge-gray"
}

func prioRu(p string) string {
	switch p {
	case "low":
		return "Низкий"
	case "high":
		return "Высокий"
	default:
		return "Обычный"
	}
}

func prioBadge(p string) string {
	if p == "high" {
		return "badge-red"
	}
	return "badge-gray"
}

// actionIcon — эмодзи-иконка для записи журнала по типу действия.
func actionIcon(action string) string {
	switch {
	case strings.Contains(action, "login"), strings.Contains(action, "logout"):
		return "👤"
	case strings.Contains(action, "device"):
		return "💻"
	case strings.Contains(action, "scan"):
		return "📡"
	case strings.Contains(action, "employee"), strings.Contains(action, "department"):
		return "🪪"
	case strings.Contains(action, "user"):
		return "👥"
	default:
		return "⚙"
	}
}

// actionCat — категория действия для метки справа в ленте активности.
func actionCat(action string) string {
	switch {
	case strings.Contains(action, "login"), strings.Contains(action, "logout"), strings.Contains(action, "user"), strings.Contains(action, "password"):
		return "Пользователи"
	case strings.Contains(action, "device"), strings.Contains(action, "scan"):
		return "Устройства"
	case strings.Contains(action, "employee"), strings.Contains(action, "department"):
		return "Сотрудники"
	default:
		return "Система"
	}
}

// цельные страницы без общего layout
var standalone = template.Must(
	template.New("").Funcs(funcMap).
		ParseFS(fsys, "templates/login.html", "templates/setup.html",
			"templates/help.html", "templates/help_track.html"),
)

// страницы, отрисовываемые внутри layout.html
var layoutPages = map[string]*template.Template{}

func init() {
	for _, name := range []string{"dashboard", "devices", "device_detail", "employees", "users", "settings", "audit", "profile", "network_map", "network_changes", "licenses", "discovery",
		"servicemon", "sla", "capacity", "topology", "forbidden", "disk_health",
		"tickets", "ticket_detail", "snmp", "snmp_ports", "commands", "packages"} {
		layoutPages[name] = template.Must(
			template.New(name).Funcs(funcMap).
				ParseFS(fsys, "templates/layout.html", "templates/"+name+".html"),
		)
	}
}

// Render исполняет цельную страницу (login/setup).
func Render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := standalone.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
	}
}

// RenderPage исполняет layout-страницу по её имени (например "dashboard").
func RenderPage(w http.ResponseWriter, page string, data any) {
	t, ok := layoutPages[page]
	if !ok {
		http.Error(w, "unknown page: "+page, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, "layout.html", data); err != nil {
		http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
	}
}
