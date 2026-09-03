// Package web — встроенные (go:embed) шаблоны и помощники рендеринга.
//
// Две модели рендера:
//   - standalone: цельные страницы без layout (login, setup);
//   - layout-страницы: layout.html + страница, которая определяет {{define "content"}}.
package web

import (
	"embed"
	"html/template"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"time"

	"netadmin/internal/tz"
)

//go:embed templates
var fsys embed.FS

//go:embed static
var staticFS embed.FS

//go:embed assets
var assetsFS embed.FS

// AgentInstaller возвращает шаблон install_agent.bat со всеми заглушками.
// Сервер подставляет в него свой адрес и текущий enrollment-токен, чтобы
// администратору не приходилось вписывать их вручную на каждой машине.
//
// Файл — копия deploy/install_agent.bat; их совпадение проверяется тестом,
// иначе ручной и скачиваемый установщики со временем разошлись бы.
func AgentInstaller() ([]byte, error) {
	return assetsFS.ReadFile("assets/install_agent.bat")
}

// StaticFile возвращает содержимое встроенного файла статики. Нужен тестам:
// иначе вынесенный из шаблона скрипт нечем проверить.
func StaticFile(name string) ([]byte, error) {
	return staticFS.ReadFile("static/" + name)
}

// Static отдаёт встроенные скрипты. Вынесены из HTML, чтобы политика
// безопасности могла запретить исполняемый код внутри страницы: без этого
// в script-src приходится держать unsafe-inline, который снимает основную
// защиту от внедрения скриптов.
func Static() http.Handler {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic("web: встроенная статика недоступна: " + err.Error())
	}
	srv := http.FileServer(http.FS(sub))
	return http.StripPrefix("/static/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// файлы меняются только вместе с бинарником, но пусть браузер сверяется
		w.Header().Set("Cache-Control", "no-cache")
		srv.ServeHTTP(w, r)
	}))
}

var funcMap = template.FuncMap{
	"upper":       strings.ToUpper,
	"actionIcon":  actionIcon,
	"actionCat":   actionCat,
	"today":       tz.TodayRU,
	"statusRu":    statusRu,
	"statusBadge": statusBadge,
	"prioRu":      prioRu,
	"prioBadge":   prioBadge,
	"sizeMB":      sizeMB,
	"dateTime":    dateTime,
}

// sizeMB — размер файла в мегабайтах для таблиц.
func sizeMB(b int64) string {
	return strconv.FormatFloat(float64(b)/(1<<20), 'f', 1, 64) + " МБ"
}

// dateTime — момент времени в московской зоне, как и остальные даты.
func dateTime(t time.Time) string {
	return t.In(tz.Loc).Format("02.01.2006 15:04")
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

// actionIcon — идентификатор значка в спрайте (layout.html) для записи журнала.
// Возвращается имя символа, а не эмодзи: набор значков общий для всего
// интерфейса и не зависит от того, как система рисует эмодзи.
func actionIcon(action string) string {
	switch {
	case strings.Contains(action, "login"), strings.Contains(action, "logout"):
		return "key"
	case strings.Contains(action, "device"):
		return "devices"
	case strings.Contains(action, "scan"):
		return "search"
	case strings.Contains(action, "employee"), strings.Contains(action, "department"):
		return "people"
	case strings.Contains(action, "user"):
		return "shield"
	default:
		return "settings"
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
