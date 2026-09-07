// Package handlers — HTTP-хендлеры NetAdmin.
package handlers

import (
	"database/sql"
	"log"
	"net/http"

	"netadmin/internal/ingest"
	"netadmin/internal/netaccess"
	"netadmin/internal/web"
)

// App держит общие зависимости хендлеров.
type App struct {
	DB     *sql.DB
	Ingest *ingest.Writer
	// Allow — подсети, которым разрешён доступ. Нулевое значение означает
	// «только локальные и частные сети», поэтому пустая конфигурация
	// не открывает сервер наружу.
	Allow netaccess.List
	// Demo — режим витрины (`netadmin -demo`): активные действия в сети
	// запрещены, чтобы показ продукта не трогал сеть смотрящего.
	Demo bool
	// Restart перезапускает сервер, если это умеет текущий способ запуска
	// (служба Windows). nil означает, что перезапустить должен человек, —
	// интерфейс тогда показывает, что именно сделать.
	Restart func() error
	// InstallAgent ставит агента на машину сервера. Возвращает вывод
	// установщика. nil — возможность недоступна (сервер собран без агента
	// или запущен не в Windows).
	InstallAgent func(serverURL, token string) (string, error)
}

// Routes собирает маршруты приложения (с security-обёрткой).
func (a *App) Routes() http.Handler {
	mux := http.NewServeMux()

	// встроенные скрипты; доступны без сессии — страница входа тоже их грузит
	mux.Handle("GET /static/", web.Static())

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	// Аутентификация и мастер первого запуска
	mux.HandleFunc("GET /{$}", a.Root)
	mux.HandleFunc("GET /login", a.LoginPage)
	mux.HandleFunc("POST /login", a.Login)
	mux.HandleFunc("GET /setup", a.SetupPage)
	mux.HandleFunc("POST /setup", a.Setup)
	mux.HandleFunc("POST /logout", a.Logout)

	mux.HandleFunc("GET /dashboard", a.Dashboard)

	// Устройства
	mux.HandleFunc("GET /devices", a.DevicesPage)
	mux.HandleFunc("GET /devices/{id}", a.DeviceDetailPage)
	mux.HandleFunc("POST /devices/create", a.CreateDevice)
	mux.HandleFunc("POST /devices/{id}/update", a.UpdateDevice)
	mux.HandleFunc("POST /devices/{id}/delete", a.DeleteDevice)
	// одно действие над несколькими устройствами сразу
	mux.HandleFunc("POST /devices/bulk", a.BulkDevices)
	mux.HandleFunc("GET /devices/export", a.ExportDevices)
	mux.HandleFunc("POST /devices/{id}/agent-token/revoke", a.RevokeAgentToken)
	mux.HandleFunc("POST /devices/{id}/scan-ports", a.ScanPorts)
	// Удалённые действия (RMM): питание и подключение к рабочему столу
	mux.HandleFunc("POST /devices/{id}/power", a.DevicePower)
	mux.HandleFunc("POST /devices/{id}/selfcheck", a.DeviceSelfCheck)
	mux.HandleFunc("GET /devices/{id}/rdp", a.DeviceRDP)
	mux.HandleFunc("POST /devices/{id}/run-command", a.RunDeviceCommand)
	// Команды из готовой библиотеки (RMM)
	mux.HandleFunc("GET /commands", a.CommandsPage)
	mux.HandleFunc("POST /commands/run", a.RunCommand)
	// Push-установка ПО (RMM)
	mux.HandleFunc("GET /packages", a.PackagesPage)
	mux.HandleFunc("POST /packages/upload", a.UploadPackage)
	mux.HandleFunc("POST /packages/deploy", a.DeployPackage)
	mux.HandleFunc("POST /packages/{id}/delete", a.DeletePackage)
	// раскатка новой сборки агента на весь парк
	mux.HandleFunc("POST /packages/agent-update", a.DeployAgentUpdate)

	// Сотрудники и отделы
	mux.HandleFunc("GET /employees", a.EmployeesPage)
	mux.HandleFunc("POST /departments/create", a.CreateDepartment)
	mux.HandleFunc("POST /employees/create", a.CreateEmployee)
	mux.HandleFunc("POST /employees/{id}/update", a.UpdateEmployee)
	mux.HandleFunc("POST /employees/{id}/toggle", a.ToggleEmployee)
	mux.HandleFunc("GET /employees/export", a.ExportEmployees)

	// Пользователи
	mux.HandleFunc("GET /users", a.UsersPage)
	mux.HandleFunc("POST /users/create", a.CreateUser)
	mux.HandleFunc("POST /users/{id}/toggle", a.ToggleUser)
	mux.HandleFunc("POST /users/{id}/delete", a.DeleteUser)

	// Настройки
	mux.HandleFunc("GET /settings", a.SettingsPage)
	mux.HandleFunc("POST /settings/organization", a.UpdateOrganization)
	mux.HandleFunc("POST /settings/agent-token/rotate", a.RotateAgentToken)
	mux.HandleFunc("GET /settings/agent-installer", a.AgentInstaller)
	// Установка агента одной командой: скрипт и сборка отдаются без сессии —
	// команда выполняется на машине, где сессии нет (см. enroll.go).
	mux.HandleFunc("GET /enroll.ps1", a.EnrollScript)
	mux.HandleFunc("GET /agent.exe", a.AgentBinary)
	mux.HandleFunc("POST /settings/password", a.ChangePassword)
	mux.HandleFunc("POST /settings/notifications", a.UpdateNotifications)
	mux.HandleFunc("POST /settings/notifications/test", a.TestNotification)
	mux.HandleFunc("POST /settings/scan", a.UpdateScan)
	mux.HandleFunc("POST /settings/helpdesk", a.UpdateHelpdesk)
	mux.HandleFunc("POST /settings/backup", a.UpdateBackup)
	mux.HandleFunc("POST /settings/backup/now", a.BackupNow)
	// Восстановление применяется при следующем запуске — см. netsettings.go
	mux.HandleFunc("POST /settings/backup/restore", a.RestoreBackup)
	mux.HandleFunc("POST /settings/backup/restore/cancel", a.CancelRestore)
	mux.HandleFunc("POST /settings/network", a.UpdateNetwork)
	mux.HandleFunc("POST /settings/restart", a.RestartServer)
	mux.HandleFunc("POST /settings/agent-install-local", a.InstallLocalAgent)
	// Одноразовые коды регистрации агентов — см. enrollcodes.go
	mux.HandleFunc("POST /settings/enroll-code", a.CreateEnrollCode)
	mux.HandleFunc("POST /settings/enroll-code/{id}/revoke", a.RevokeEnrollCode)

	// Мониторинг сервисов (HTTP/TCP/DNS/…)
	mux.HandleFunc("GET /monitoring", a.ServiceMonitorPage)
	mux.HandleFunc("POST /monitoring/add", a.AddServiceCheck)
	mux.HandleFunc("POST /monitoring/{id}/toggle", a.ToggleServiceCheck)
	mux.HandleFunc("POST /monitoring/{id}/delete", a.DeleteServiceCheck)
	// Доступность (SLA)
	mux.HandleFunc("GET /sla", a.SLAPage)
	// Прогноз ёмкости
	mux.HandleFunc("GET /capacity", a.CapacityPage)
	// Здоровье дисков (SMART) по всему парку
	mux.HandleFunc("GET /disk-health", a.DiskHealthPage)
	// SNMP-мониторинг сетевого оборудования
	mux.HandleFunc("GET /snmp", a.SNMPDevicesPage)
	mux.HandleFunc("POST /snmp/add", a.AddSNMPDevice)
	mux.HandleFunc("POST /snmp/{id}/toggle", a.ToggleSNMPDevice)
	mux.HandleFunc("POST /snmp/{id}/delete", a.DeleteSNMPDevice)
	mux.HandleFunc("POST /snmp/{id}/poll", a.PollSNMPNow)
	mux.HandleFunc("GET /snmp/{id}/ports", a.SNMPPortsPage)
	// Топология и зависимости
	mux.HandleFunc("GET /topology", a.TopologyPage)
	mux.HandleFunc("POST /topology/add", a.AddTopologyLink)
	mux.HandleFunc("POST /topology/{id}/delete", a.DeleteTopologyLink)

	// Лицензии ПО (учёт)
	mux.HandleFunc("GET /licenses", a.LicensesPage)
	mux.HandleFunc("POST /licenses/add", a.AddLicense)
	mux.HandleFunc("POST /licenses/{id}/update", a.UpdateLicense)
	mux.HandleFunc("POST /licenses/{id}/delete", a.DeleteLicense)

	// Аудит запрещённого/нежелательного ПО
	mux.HandleFunc("GET /forbidden", a.ForbiddenPage)
	mux.HandleFunc("POST /forbidden/add", a.AddForbidden)
	mux.HandleFunc("POST /forbidden/seed", a.SeedForbidden)
	mux.HandleFunc("POST /forbidden/{id}/delete", a.DeleteForbidden)

	// Заявки (HelpDesk) — сторона ИТ-службы (за логином)
	mux.HandleFunc("GET /tickets", a.TicketsPage)
	mux.HandleFunc("GET /tickets/{id}", a.TicketDetailPage)
	mux.HandleFunc("POST /tickets/{id}/update", a.TicketUpdate)
	mux.HandleFunc("POST /tickets/{id}/status", a.TicketStatus)
	mux.HandleFunc("POST /tickets/{id}/comment", a.TicketComment)

	// Портал заявок для сотрудников (БЕЗ логина)
	mux.HandleFunc("GET /help", a.HelpPage)
	mux.HandleFunc("POST /help/submit", a.HelpSubmit)
	mux.HandleFunc("GET /help/track", a.HelpTrack)
	mux.HandleFunc("POST /help/track/reply", a.HelpReply)

	// Профиль (доступен всем залогиненным)
	mux.HandleFunc("GET /profile", a.ProfilePage)

	// Журнал действий
	mux.HandleFunc("GET /audit", a.AuditPage)

	// Приём от агента (защищено токеном агента, без сессии)
	mux.HandleFunc("POST /api/agent-heartbeat", a.AgentHeartbeat)
	mux.HandleFunc("POST /api/agent-software", a.AgentSoftware)
	// Инвентарь конфигурации хоста (службы/автозагрузка/задачи) — это учёт, не СЗИ.
	// Изменения пишутся в историю устройства; security-события — только в security-редакции.
	mux.HandleFunc("POST /api/agent-services", a.AgentServices)
	mux.HandleFunc("POST /api/agent-autoruns", a.AgentAutoruns)
	mux.HandleFunc("POST /api/agent-schtasks", a.AgentSchTasks)
	// Здоровье дисков (SMART) — мониторинг состояния оборудования.
	mux.HandleFunc("POST /api/agent-disks", a.AgentDisks)
	// Очередь удалённых задач (RMM): агент забирает и рапортует результат.
	mux.HandleFunc("POST /api/agent-tasks/poll", a.AgentTasksPoll)
	mux.HandleFunc("POST /api/agent-tasks/result", a.AgentTasksResult)
	// Скачивание дистрибутива агентом (по токену; CSRF-exempt по префиксу /api/agent-)
	mux.HandleFunc("GET /api/agent-package", a.AgentPackageDownload)

	// JSON (инвентарь/мониторинг)
	mux.HandleFunc("GET /api/metrics/fleet", a.FleetMetrics)
	mux.HandleFunc("GET /api/devices/status", a.DevicesStatus)
	mux.HandleFunc("GET /api/devices/{id}/metrics", a.DeviceMetrics)
	mux.HandleFunc("GET /api/devices/{id}/software", a.DeviceSoftware)
	mux.HandleFunc("GET /api/devices/{id}/changes", a.DeviceChanges)
	mux.HandleFunc("GET /api/devices/{id}/services", a.DeviceServices)
	mux.HandleFunc("GET /api/devices/{id}/autoruns", a.DeviceAutoruns)
	mux.HandleFunc("GET /api/devices/{id}/schtasks", a.DeviceSchTasks)
	mux.HandleFunc("GET /api/devices/{id}/disks", a.DeviceDisks)
	mux.HandleFunc("GET /api/devices/{id}/tasks", a.DeviceTasks)
	mux.HandleFunc("POST /api/ping", a.Ping)
	mux.HandleFunc("POST /api/scan", a.Scan)

	// Карта сети
	mux.HandleFunc("GET /network-map", a.NetworkMapPage)
	mux.HandleFunc("GET /api/network-map", a.NetworkMapAPI)
	mux.HandleFunc("GET /api/search", a.Search)

	// История изменений сети
	mux.HandleFunc("GET /network-changes", a.NetworkChangesPage)

	// Пассивное обнаружение устройств
	mux.HandleFunc("GET /discovery", a.DiscoveryPage)
	mux.HandleFunc("POST /discovery/{id}/action", a.DiscoveryAction)

	return withRecover(a.withSecurity(mux))
}

// agentDeviceIDs возвращает id всех устройств с установленным агентом —
// цели для команд и раздачи ПО «на все ПК».
func (a *App) agentDeviceIDs() []int64 {
	rows, err := a.DB.Query(`SELECT id FROM devices WHERE COALESCE(agent_token,'')<>''`)
	if err != nil {
		log.Printf("выбор устройств с агентом: %v", err)
		return nil
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	if err := rows.Err(); err != nil {
		log.Printf("выбор устройств с агентом: %v", err)
	}
	return ids
}

// setSessionCookie ставит httponly cookie сессии на 8 часов.
func setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   28800,
		SameSite: http.SameSiteLaxMode,
	})
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:   "session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
}
