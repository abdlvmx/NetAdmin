package handlers

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"netadmin/internal/auth"
	"netadmin/internal/backup"
	"netadmin/internal/config"
	"netadmin/internal/netaccess"
)

// Сетевые настройки и восстановление из копии — то, что читается только при
// старте сервера. Обе страницы живут здесь, потому что обе заканчиваются
// одинаково: изменения применяет перезапуск.

// UpdateNetwork — POST /settings/network (admin): адрес прослушивания и
// разрешённые подсети.
//
// Заведено потому, что служба Windows не наследует окружение консоли: указание
// «задайте NETADMIN_ALLOW перед запуском» для установленной службы молча не
// срабатывало, и сузить доступ было негде, кроме машинных переменных.
func (a *App) UpdateNetwork(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil || !user.IsAdmin() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	_ = r.ParseForm()
	addr := strings.TrimSpace(r.FormValue("listen_addr"))
	allowSpec := strings.TrimSpace(r.FormValue("allow_subnets"))

	if err := validListenAddr(addr); err != nil {
		settingsError(w, r, "Адрес прослушивания: "+err.Error())
		return
	}
	allow, err := netaccess.Parse(allowSpec)
	if err != nil {
		settingsError(w, r, "Разрешённые подсети: "+err.Error())
		return
	}

	// Защита от самоблокировки: список, не включающий адрес того, кто его
	// задаёт, после перезапуска отрежет доступ к интерфейсу — и вернуть его
	// можно будет только правкой config.json на самой машине.
	//
	// Администратора, работающего на самом сервере, это больше не задевает:
	// петля разрешена всегда, каким бы ни был список (см. internal/netaccess).
	// Прежде он не мог задать подсеть организации — проверка отвергала
	// совершенно нормальный случай.
	if ip := clientIP(r); !allow.Allows(ip) {
		settingsError(w, r, fmt.Sprintf(
			"Этот список не включает ваш адрес %s — после перезапуска вы потеряете доступ "+
				"к интерфейсу. Добавьте свой адрес или его подсеть в список.", ip))
		return
	}

	cfg := config.Load()
	cfg.ListenAddr, cfg.AllowSubnets = addr, allowSpec
	if err := config.Save(cfg); err != nil {
		settingsError(w, r, "Не удалось сохранить настройки: "+err.Error())
		return
	}
	auth.LogAction(a.DB, user.ID, "update_settings", "network",
		"адрес="+addr+" подсети="+allowSpec)
	http.Redirect(w, r, "/settings?message=network_saved", http.StatusSeeOther)
}

// validListenAddr проверяет адрес вида host:port, ":8765" или пустую строку.
func validListenAddr(addr string) error {
	if addr == "" {
		return nil // пусто = значение по умолчанию
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("нужен вид «адрес:порт», например 0.0.0.0:8765 или :9000")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("порт %q вне диапазона 1–65535", port)
	}
	return nil
}

// RestoreBackup — POST /settings/backup/restore (admin): подготовка
// восстановления базы из выбранной копии.
//
// Подмена происходит не здесь, а при следующем запуске: файл работающей базы
// подменить нельзя (см. internal/backup).
func (a *App) RestoreBackup(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil || !user.IsAdmin() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	_ = r.ParseForm()
	name := strings.TrimSpace(r.FormValue("name"))

	cfg := config.Load()
	dir, err := backupDir(cfg)
	if err != nil {
		settingsError(w, r, "Каталог копий недоступен: "+err.Error())
		return
	}

	// Имя приходит из формы, поэтому путь не собирается из него напрямую:
	// копия ищется среди уже известных: так «..\..\чужой.db» не подставить.
	var path string
	for _, b := range backup.List(dir) {
		if b.Name == name {
			path = b.Path
			break
		}
	}
	if path == "" {
		settingsError(w, r, "Копия не найдена: "+name)
		return
	}

	if err := backup.StageRestore(config.DBPath(), path); err != nil {
		settingsError(w, r, "Восстановление отклонено: "+err.Error())
		return
	}
	auth.LogAction(a.DB, user.ID, "restore_backup", name, "подготовлено")

	if a.Restart == nil {
		// Консольный запуск: перезапускает человек.
		http.Redirect(w, r, "/settings?message=restore_staged", http.StatusSeeOther)
		return
	}
	if err := a.Restart(); err != nil {
		http.Redirect(w, r, "/settings?message=restore_staged", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/settings?message=restore_restarting", http.StatusSeeOther)
}

// CancelRestore — POST /settings/backup/restore/cancel (admin): отмена
// подготовленного восстановления, пока сервер не перезапущен.
func (a *App) CancelRestore(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil || !user.IsAdmin() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := backup.CancelPending(config.DBPath()); err != nil {
		settingsError(w, r, "Не удалось отменить: "+err.Error())
		return
	}
	auth.LogAction(a.DB, user.ID, "restore_backup", "отменено", "")
	http.Redirect(w, r, "/settings?message=restore_cancelled", http.StatusSeeOther)
}

// settingsError возвращает на страницу настроек с текстом ошибки.
func settingsError(w http.ResponseWriter, r *http.Request, msg string) {
	http.Redirect(w, r, "/settings?error="+url.QueryEscape(msg), http.StatusSeeOther)
}

// RestartServer — POST /settings/restart (admin): перезапуск сервера, чтобы
// применились настройки, которые читаются только при старте.
func (a *App) RestartServer(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil || !user.IsAdmin() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if a.Restart == nil {
		settingsError(w, r, "Перезапуск из интерфейса доступен, только когда сервер установлен службой.")
		return
	}
	auth.LogAction(a.DB, user.ID, "restart_server", "settings", "")
	if err := a.Restart(); err != nil {
		settingsError(w, r, "Не удалось перезапустить: "+err.Error())
		return
	}
	http.Redirect(w, r, "/settings?message=restarting", http.StatusSeeOther)
}

// InstallLocalAgent — POST /settings/agent-install-local (admin): поставить
// агента на машину, где работает сервер.
func (a *App) InstallLocalAgent(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil || !user.IsAdmin() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if a.InstallAgent == nil {
		settingsError(w, r, "Установка с этой страницы недоступна: сервер собран без встроенного агента.")
		return
	}
	cfg := config.Load()
	if strings.TrimSpace(cfg.AgentToken) == "" {
		settingsError(w, r, "Не задан токен агента.")
		return
	}

	// Локальному агенту адрес сервера нужен через петлю, а не через адрес
	// интерфейса: машина та же, и смена IP не должна разрывать связь.
	if _, err := a.InstallAgent(localServerURL(r), cfg.AgentToken); err != nil {
		settingsError(w, r, "Не удалось установить агента: "+err.Error())
		return
	}
	auth.LogAction(a.DB, user.ID, "install_agent_local", "settings", "")
	http.Redirect(w, r, "/settings?message=agent_installed", http.StatusSeeOther)
}

// localServerURL — адрес сервера для агента на этой же машине.
func localServerURL(r *http.Request) string {
	_, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		return "http://127.0.0.1:8765"
	}
	return "http://" + net.JoinHostPort("127.0.0.1", port)
}
