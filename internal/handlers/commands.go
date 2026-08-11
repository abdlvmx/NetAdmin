package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"netadmin/internal/auth"
	"netadmin/internal/tz"
	"netadmin/internal/web"
)

// cmdDef — запись готовой библиотеки команд. Сами скрипты живут в АГЕНТЕ
// (commands_windows.go): сервер передаёт только ключ, агент исполняет лишь
// известные ключи — произвольное выполнение исключено.
type cmdDef struct {
	Key    string
	Name   string
	Desc   string
	Danger bool // действие прерывает работу пользователя → подтверждение в UI
}

var commandLibrary = []cmdDef{
	{"flushdns", "Очистить кэш DNS", "ipconfig /flushdns", false},
	{"ipconfig", "Сетевая конфигурация", "Вывод ipconfig /all (диагностика)", false},
	{"systeminfo", "Сведения о системе", "Вывод systeminfo (диагностика)", false},
	{"list_users", "Кто в системе", "Список вошедших пользователей", false},
	{"restart_spooler", "Перезапустить службу печати", "Restart-Service Spooler", false},
	{"clear_print_queue", "Очистить очередь печати", "Остановить спулер, удалить задания, запустить", true},
	{"clear_temp", "Очистить временные файлы", "Очистка %TEMP% и Windows\\Temp", false},
	{"restart_dnscache", "Перезапустить DNS-клиент", "Restart-Service Dnscache", false},
	{"restart_explorer", "Перезапустить Проводник", "Закрывает и запускает explorer.exe", true},
	{"winupdate_scan", "Проверить обновления Windows", "Запуск поиска обновлений", false},
	{"gpupdate", "Обновить групповые политики", "gpupdate /force", false},
}

func cmdByKey(key string) (cmdDef, bool) {
	for _, c := range commandLibrary {
		if c.Key == key {
			return c, true
		}
	}
	return cmdDef{}, false
}

type cmdRunRow struct {
	Device  string
	Command string
	Status  string
	Result  string
	Created string
}

type commandsData struct {
	User    *auth.User
	Active  string
	Library []cmdDef
	Devices []employeeOpt // устройства с агентом (id, hostname)
	Recent  []cmdRunRow
	Msg     string
}

// CommandsPage — GET /commands : библиотека команд, запуск на группу, история.
func (a *App) CommandsPage(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	data := commandsData{User: user, Active: "commands", Library: commandLibrary, Msg: r.URL.Query().Get("message")}

	if rows, err := a.DB.Query(`SELECT id, hostname FROM devices
		WHERE COALESCE(agent_token,'')<>'' ORDER BY hostname`); err == nil {
		for rows.Next() {
			var o employeeOpt
			if rows.Scan(&o.ID, &o.Name) == nil {
				data.Devices = append(data.Devices, o)
			}
		}
		rows.Close()
	}

	if rows, err := a.DB.Query(`SELECT COALESCE(d.hostname,''), COALESCE(t.label,''),
		COALESCE(t.status,''), COALESCE(t.result,''), COALESCE(t.created_at,'')
		FROM agent_tasks t LEFT JOIN devices d ON d.id=t.device_id
		WHERE t.kind='command' ORDER BY t.id DESC LIMIT 80`); err == nil {
		for rows.Next() {
			var row cmdRunRow
			var created string
			if rows.Scan(&row.Device, &row.Command, &row.Status, &row.Result, &created) == nil {
				row.Created = tz.DateTime(created)
				data.Recent = append(data.Recent, row)
			}
		}
		rows.Close()
	}
	web.RenderPage(w, "commands", data)
}

// RunCommand — POST /commands/run : запуск команды из библиотеки на выбранных ПК (CanWrite).
func (a *App) RunCommand(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if !user.CanWrite() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	_ = r.ParseForm()
	def, ok := cmdByKey(strings.TrimSpace(r.FormValue("cmd")))
	if !ok {
		http.Redirect(w, r, "/commands?message=Неизвестная+команда", http.StatusSeeOther)
		return
	}
	// цели: либо все ПК с агентом, либо отмеченные
	var targets []int64
	if r.FormValue("all") != "" {
		rows, _ := a.DB.Query(`SELECT id FROM devices WHERE COALESCE(agent_token,'')<>''`)
		for rows.Next() {
			var id int64
			if rows.Scan(&id) == nil {
				targets = append(targets, id)
			}
		}
		rows.Close()
	} else {
		for _, s := range r.Form["device"] {
			if id, err := strconv.ParseInt(s, 10, 64); err == nil {
				targets = append(targets, id)
			}
		}
	}
	if len(targets) == 0 {
		http.Redirect(w, r, "/commands?message=Не+выбраны+устройства", http.StatusSeeOther)
		return
	}
	for _, id := range targets {
		a.enqueueTask(id, "command", def.Key, "Команда: "+def.Name, user.ID)
	}
	auth.LogAction(a.DB, user.ID, "command_run", def.Key, strconv.Itoa(len(targets))+" устройств")
	http.Redirect(w, r, "/commands?message=Команда+поставлена+на+"+strconv.Itoa(len(targets))+"+ПК", http.StatusSeeOther)
}

// RunDeviceCommand — POST /devices/{id}/run-command : запуск команды на одном ПК (JSON, CanWrite).
func (a *App) RunDeviceCommand(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if !user.CanWrite() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	def, ok := cmdByKey(strings.TrimSpace(r.FormValue("cmd")))
	if !ok {
		writeJSON(w, map[string]any{"ok": false, "error": "неизвестная команда"})
		return
	}
	var token string
	if a.DB.QueryRow("SELECT COALESCE(agent_token,'') FROM devices WHERE id=?", id).Scan(&token) != nil || token == "" {
		writeJSON(w, map[string]any{"ok": false, "error": "на устройстве не установлен агент"})
		return
	}
	a.enqueueTask(id, "command", def.Key, "Команда: "+def.Name, user.ID)
	auth.LogAction(a.DB, user.ID, "command_run", def.Key, strconv.FormatInt(id, 10))
	writeJSON(w, map[string]any{"ok": true, "message": def.Name + ": задача поставлена"})
}
