// Package handlers — HTTP-хендлеры NetAdmin.
package handlers

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"netadmin/internal/auth"
	"netadmin/internal/config"
	"netadmin/internal/ingest"
	"netadmin/internal/netaccess"
	"netadmin/internal/version"
	"netadmin/internal/web"
)

// App держит общие зависимости хендлеров.
type App struct {
	DB     *sql.DB
	Events eventsStore
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
	// IsService — сервер запущен диспетчером служб, а не из консоли.
	// Чек-лист первых шагов спрашивает об этом первым делом: запущенный
	// из окна сервер закрывается вместе с ним.
	IsService bool
	// scope is set only on a per-request copy; workers and other requests never
	// share it. Restricted routes use an explicit allowlist and SQL predicates.
	scope *auth.User
}

func (a *App) mfa() *auth.MFA {
	return &auth.MFA{DB: a.DB, KeyPath: filepath.Join(config.DataDir(), "mfa.key")}
}

// Routes собирает маршруты приложения (с security-обёрткой).
func (a *App) Routes() http.Handler {
	mux := http.NewServeMux()
	a.registerEventsRoutes(mux)

	// встроенные скрипты; доступны без сессии — страница входа тоже их грузит
	mux.Handle("GET /static/", web.Static())

	// Значок вкладки по корневому пути: браузер просит его сам и до входа тоже.
	mux.HandleFunc("GET /favicon.ico", web.Favicon())

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if a.DB == nil || a.DB.PingContext(ctx) != nil {
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("X-NetAdmin-Version", version.Value)
		w.Header().Set("X-NetAdmin-PID", strconv.Itoa(os.Getpid()))
		_, _ = w.Write([]byte("ok"))
	})

	// Аутентификация и мастер первого запуска
	mux.HandleFunc("GET /{$}", a.deviceScoped((*App).Root))
	mux.HandleFunc("GET /login", a.deviceScoped((*App).LoginPage))
	mux.HandleFunc("POST /login", a.deviceScoped((*App).Login))
	mux.HandleFunc("GET /login/mfa", a.deviceScoped((*App).MFALoginPage))
	mux.HandleFunc("POST /login/mfa", a.deviceScoped((*App).MFALogin))
	mux.HandleFunc("GET /setup", a.deviceScoped((*App).SetupPage))
	mux.HandleFunc("POST /setup", a.deviceScoped((*App).Setup))
	mux.HandleFunc("POST /logout", a.deviceScoped((*App).Logout))
	mux.HandleFunc("POST /profile/mfa/{operation}", a.deviceScoped((*App).MFAAction))

	mux.HandleFunc("GET /dashboard", a.deviceScoped((*App).Dashboard))
	// чек-лист первых шагов: убрать с дашборда или вернуть
	mux.HandleFunc("POST /dashboard/onboarding", a.deviceScoped((*App).HideOnboarding))

	// Устройства
	mux.HandleFunc("GET /devices", a.deviceScoped((*App).DevicesPage))
	mux.HandleFunc("GET /devices/{id}", a.deviceScoped((*App).DeviceDetailPage))
	mux.HandleFunc("POST /devices/create", a.deviceScoped((*App).CreateDevice))
	mux.HandleFunc("POST /devices/{id}/update", a.deviceScoped((*App).UpdateDevice))
	mux.HandleFunc("POST /devices/{id}/delete", a.deviceScoped((*App).DeleteDevice))
	// одно действие над несколькими устройствами сразу
	mux.HandleFunc("POST /devices/bulk", a.deviceScoped((*App).BulkDevices))
	mux.HandleFunc("GET /devices/export", a.deviceScoped((*App).ExportDevices))
	mux.HandleFunc("POST /devices/{id}/agent-token/revoke", a.deviceScoped((*App).RevokeAgentToken))
	mux.HandleFunc("POST /devices/{id}/scan-ports", a.deviceScoped((*App).ScanPorts))
	// Удалённые действия (RMM): питание и подключение к рабочему столу
	mux.HandleFunc("POST /devices/{id}/power", a.deviceScoped((*App).DevicePower))
	mux.HandleFunc("POST /devices/{id}/selfcheck", a.deviceScoped((*App).DeviceSelfCheck))
	mux.HandleFunc("GET /devices/{id}/rdp", a.deviceScoped((*App).DeviceRDP))
	mux.HandleFunc("POST /devices/{id}/run-command", a.deviceScoped((*App).RunDeviceCommand))
	// Команды из готовой библиотеки (RMM)
	mux.HandleFunc("GET /commands", a.deviceScoped((*App).CommandsPage))
	mux.HandleFunc("GET /jobs", a.deviceScoped((*App).JobsPage))
	mux.HandleFunc("GET /jobs/{id}", a.deviceScoped((*App).JobPage))
	mux.HandleFunc("GET /jobs/{id}/tasks/{task}", a.deviceScoped((*App).JobTaskPage))
	mux.HandleFunc("GET /api/jobs/{id}", a.deviceScoped((*App).JobStatus))
	mux.HandleFunc("POST /jobs/{id}/cancel", a.deviceScoped((*App).CancelJob))
	mux.HandleFunc("POST /jobs/{id}/retry", a.deviceScoped((*App).RetryJob))
	mux.HandleFunc("POST /commands/run", a.deviceScoped((*App).RunCommand))
	// Push-установка ПО (RMM)
	mux.HandleFunc("GET /packages", a.deviceScoped((*App).PackagesPage))
	mux.HandleFunc("POST /packages/upload", a.deviceScoped((*App).UploadPackage))
	mux.HandleFunc("POST /packages/deploy", a.deviceScoped((*App).DeployPackage))
	mux.HandleFunc("POST /packages/{id}/delete", a.deviceScoped((*App).DeletePackage))
	// раскатка новой сборки агента на весь парк
	mux.HandleFunc("POST /packages/agent-update", a.deviceScoped((*App).DeployAgentUpdate))

	// Сотрудники и отделы
	mux.HandleFunc("GET /employees", a.deviceScoped((*App).EmployeesPage))
	mux.HandleFunc("POST /departments/create", a.deviceScoped((*App).CreateDepartment))
	mux.HandleFunc("POST /employees/create", a.deviceScoped((*App).CreateEmployee))
	mux.HandleFunc("POST /employees/{id}/update", a.deviceScoped((*App).UpdateEmployee))
	mux.HandleFunc("POST /employees/{id}/toggle", a.deviceScoped((*App).ToggleEmployee))
	mux.HandleFunc("GET /employees/export", a.deviceScoped((*App).ExportEmployees))

	// Пользователи
	mux.HandleFunc("GET /users", a.deviceScoped((*App).UsersPage))
	mux.HandleFunc("POST /users/create", a.deviceScoped((*App).CreateUser))
	mux.HandleFunc("POST /users/{id}/toggle", a.deviceScoped((*App).ToggleUser))
	mux.HandleFunc("POST /users/{id}/delete", a.deviceScoped((*App).DeleteUser))
	mux.HandleFunc("GET /users/{id}/access", a.deviceScoped((*App).UserDeviceAccessPage))
	mux.HandleFunc("POST /users/{id}/access", a.deviceScoped((*App).UpdateUserDeviceAccess))
	mux.HandleFunc("GET /device-groups", a.deviceScoped((*App).DeviceGroupsPage))
	mux.HandleFunc("POST /device-groups/create", a.deviceScoped((*App).CreateDeviceGroup))
	mux.HandleFunc("GET /device-groups/{id}", a.deviceScoped((*App).DeviceGroupPage))
	mux.HandleFunc("POST /device-groups/{id}/update", a.deviceScoped((*App).UpdateDeviceGroup))
	mux.HandleFunc("POST /device-groups/{id}/delete", a.deviceScoped((*App).DeleteDeviceGroup))

	// Настройки
	mux.HandleFunc("GET /settings", a.deviceScoped((*App).SettingsPage))
	mux.HandleFunc("POST /settings/organization", a.deviceScoped((*App).UpdateOrganization))
	mux.HandleFunc("POST /settings/agent-token/rotate", a.deviceScoped((*App).RotateAgentToken))
	mux.HandleFunc("GET /settings/agent-installer", a.deviceScoped((*App).AgentInstaller))
	// готовый установщик: агент с уже вписанными адресом и ключом
	mux.HandleFunc("GET /settings/agent-setup.exe", a.deviceScoped((*App).AgentSetupExe))
	// Установка агента одной командой: скрипт и сборка отдаются без сессии —
	// команда выполняется на машине, где сессии нет (см. enroll.go).
	mux.HandleFunc("GET /enroll.ps1", a.deviceScoped((*App).EnrollScript))
	mux.HandleFunc("GET /agent.exe", a.deviceScoped((*App).AgentBinary))
	mux.HandleFunc("POST /settings/password", a.deviceScoped((*App).ChangePassword))
	mux.HandleFunc("POST /settings/notifications", a.deviceScoped((*App).UpdateNotifications))
	mux.HandleFunc("POST /settings/notifications/test", a.deviceScoped((*App).TestNotification))
	mux.HandleFunc("POST /settings/scan", a.deviceScoped((*App).UpdateScan))
	mux.HandleFunc("POST /settings/helpdesk", a.deviceScoped((*App).UpdateHelpdesk))
	mux.HandleFunc("POST /settings/backup", a.deviceScoped((*App).UpdateBackup))
	mux.HandleFunc("POST /settings/backup/now", a.deviceScoped((*App).BackupNow))
	// Восстановление применяется при следующем запуске — см. netsettings.go
	mux.HandleFunc("POST /settings/backup/restore", a.deviceScoped((*App).RestoreBackup))
	mux.HandleFunc("POST /settings/backup/restore/cancel", a.deviceScoped((*App).CancelRestore))
	mux.HandleFunc("POST /settings/network", a.deviceScoped((*App).UpdateNetwork))
	mux.HandleFunc("POST /settings/restart", a.deviceScoped((*App).RestartServer))
	mux.HandleFunc("GET /settings/diagnostics", a.deviceScoped((*App).DiagnosticsPage))
	mux.HandleFunc("GET /api/diagnostics/archive", a.deviceScoped((*App).DiagnosticsArchive))
	mux.HandleFunc("POST /settings/agent-install-local", a.deviceScoped((*App).InstallLocalAgent))
	// Одноразовые коды регистрации агентов — см. enrollcodes.go
	mux.HandleFunc("POST /settings/enroll-code", a.deviceScoped((*App).CreateEnrollCode))
	mux.HandleFunc("POST /settings/enroll-code/{id}/revoke", a.deviceScoped((*App).RevokeEnrollCode))
	mux.HandleFunc("GET /settings/enroll-code/{id}/installer", a.deviceScoped((*App).EnrollCodeInstaller))

	// Мониторинг сервисов (HTTP/TCP/DNS/…)
	mux.HandleFunc("GET /monitoring", a.deviceScoped((*App).ServiceMonitorPage))
	mux.HandleFunc("POST /monitoring/add", a.deviceScoped((*App).AddServiceCheck))
	mux.HandleFunc("POST /monitoring/{id}/toggle", a.deviceScoped((*App).ToggleServiceCheck))
	mux.HandleFunc("POST /monitoring/{id}/delete", a.deviceScoped((*App).DeleteServiceCheck))
	// Доступность (SLA)
	mux.HandleFunc("GET /sla", a.deviceScoped((*App).SLAPage))
	// Прогноз ёмкости
	mux.HandleFunc("GET /capacity", a.deviceScoped((*App).CapacityPage))
	// Здоровье дисков (SMART) по всему парку
	mux.HandleFunc("GET /disk-health", a.deviceScoped((*App).DiskHealthPage))
	// SNMP-мониторинг сетевого оборудования
	mux.HandleFunc("GET /snmp", a.deviceScoped((*App).SNMPDevicesPage))
	mux.HandleFunc("POST /snmp/add", a.deviceScoped((*App).AddSNMPDevice))
	mux.HandleFunc("POST /snmp/{id}/toggle", a.deviceScoped((*App).ToggleSNMPDevice))
	mux.HandleFunc("POST /snmp/{id}/delete", a.deviceScoped((*App).DeleteSNMPDevice))
	mux.HandleFunc("POST /snmp/{id}/poll", a.deviceScoped((*App).PollSNMPNow))
	mux.HandleFunc("GET /snmp/{id}/ports", a.deviceScoped((*App).SNMPPortsPage))
	// Топология и зависимости
	mux.HandleFunc("GET /topology", a.deviceScoped((*App).TopologyPage))
	mux.HandleFunc("POST /topology/add", a.deviceScoped((*App).AddTopologyLink))
	mux.HandleFunc("POST /topology/{id}/delete", a.deviceScoped((*App).DeleteTopologyLink))

	// Лицензии ПО (учёт)
	mux.HandleFunc("GET /licenses", a.deviceScoped((*App).LicensesPage))
	mux.HandleFunc("POST /licenses/add", a.deviceScoped((*App).AddLicense))
	mux.HandleFunc("POST /licenses/{id}/update", a.deviceScoped((*App).UpdateLicense))
	mux.HandleFunc("POST /licenses/{id}/delete", a.deviceScoped((*App).DeleteLicense))

	// Аудит запрещённого/нежелательного ПО
	mux.HandleFunc("GET /forbidden", a.deviceScoped((*App).ForbiddenPage))
	mux.HandleFunc("POST /forbidden/add", a.deviceScoped((*App).AddForbidden))
	mux.HandleFunc("POST /forbidden/seed", a.deviceScoped((*App).SeedForbidden))
	mux.HandleFunc("POST /forbidden/{id}/delete", a.deviceScoped((*App).DeleteForbidden))

	// Заявки (HelpDesk) — сторона ИТ-службы (за логином)
	mux.HandleFunc("GET /tickets", a.deviceScoped((*App).TicketsPage))
	mux.HandleFunc("GET /tickets/{id}", a.deviceScoped((*App).TicketDetailPage))
	mux.HandleFunc("POST /tickets/{id}/update", a.deviceScoped((*App).TicketUpdate))
	mux.HandleFunc("POST /tickets/{id}/status", a.deviceScoped((*App).TicketStatus))
	mux.HandleFunc("POST /tickets/{id}/comment", a.deviceScoped((*App).TicketComment))

	// Портал заявок для сотрудников (БЕЗ логина)
	mux.HandleFunc("GET /help", a.deviceScoped((*App).HelpPage))
	mux.HandleFunc("POST /help/submit", a.deviceScoped((*App).HelpSubmit))
	mux.HandleFunc("GET /help/track", a.deviceScoped((*App).HelpTrack))
	mux.HandleFunc("POST /help/track/reply", a.deviceScoped((*App).HelpReply))

	// Профиль (доступен всем залогиненным)
	mux.HandleFunc("GET /profile", a.deviceScoped((*App).ProfilePage))

	// Журнал действий
	mux.HandleFunc("GET /audit", a.deviceScoped((*App).AuditPage))

	// Приём от агента (защищено токеном агента, без сессии)
	mux.HandleFunc("POST /api/agent-heartbeat", a.deviceScoped((*App).AgentHeartbeat))
	mux.HandleFunc("POST /api/agent-software", a.deviceScoped((*App).AgentSoftware))
	// Инвентарь конфигурации хоста (службы/автозагрузка/задачи) — это учёт, не СЗИ.
	// Изменения пишутся в историю устройства; security-события — только в security-редакции.
	mux.HandleFunc("POST /api/agent-services", a.deviceScoped((*App).AgentServices))
	mux.HandleFunc("POST /api/agent-autoruns", a.deviceScoped((*App).AgentAutoruns))
	mux.HandleFunc("POST /api/agent-schtasks", a.deviceScoped((*App).AgentSchTasks))
	// Здоровье дисков (SMART) — мониторинг состояния оборудования.
	mux.HandleFunc("POST /api/agent-disks", a.deviceScoped((*App).AgentDisks))
	// Очередь удалённых задач (RMM): агент забирает и рапортует результат.
	mux.HandleFunc("POST /api/agent-tasks/poll", a.deviceScoped((*App).AgentTasksPoll))
	mux.HandleFunc("POST /api/agent-tasks/result", a.deviceScoped((*App).AgentTasksResult))
	mux.HandleFunc("POST /api/agent-tasks/start", a.deviceScoped((*App).AgentTaskStart))
	mux.HandleFunc("POST /api/agent-tasks/state", a.deviceScoped((*App).AgentTaskState))
	mux.HandleFunc("POST /api/tasks/{id}/cancel", a.deviceScoped((*App).CancelTask))
	// Скачивание дистрибутива агентом (по токену; CSRF-exempt по префиксу /api/agent-)
	mux.HandleFunc("GET /api/agent-package", a.deviceScoped((*App).AgentPackageDownload))

	// JSON (инвентарь/мониторинг)
	mux.HandleFunc("GET /api/metrics/fleet", a.deviceScoped((*App).FleetMetrics))
	mux.HandleFunc("GET /api/devices/status", a.deviceScoped((*App).DevicesStatus))
	// сколько машин уже с агентом: страница настроек ждёт первого подключения
	mux.HandleFunc("GET /api/agents/enrolled", a.deviceScoped((*App).EnrolledAgents))
	mux.HandleFunc("GET /api/devices/{id}/metrics", a.deviceScoped((*App).DeviceMetrics))
	mux.HandleFunc("GET /api/devices/{id}/software", a.deviceScoped((*App).DeviceSoftware))
	mux.HandleFunc("GET /api/devices/{id}/changes", a.deviceScoped((*App).DeviceChanges))
	mux.HandleFunc("GET /api/devices/{id}/services", a.deviceScoped((*App).DeviceServices))
	mux.HandleFunc("GET /api/devices/{id}/autoruns", a.deviceScoped((*App).DeviceAutoruns))
	mux.HandleFunc("GET /api/devices/{id}/schtasks", a.deviceScoped((*App).DeviceSchTasks))
	mux.HandleFunc("GET /api/devices/{id}/disks", a.deviceScoped((*App).DeviceDisks))
	mux.HandleFunc("GET /api/devices/{id}/tasks", a.deviceScoped((*App).DeviceTasks))
	mux.HandleFunc("POST /api/ping", a.deviceScoped((*App).Ping))
	mux.HandleFunc("POST /api/scan", a.deviceScoped((*App).Scan))

	// Карта сети
	mux.HandleFunc("GET /network-map", a.deviceScoped((*App).NetworkMapPage))
	mux.HandleFunc("GET /api/network-map", a.deviceScoped((*App).NetworkMapAPI))
	mux.HandleFunc("GET /api/search", a.deviceScoped((*App).Search))

	// История изменений сети
	mux.HandleFunc("GET /network-changes", a.deviceScoped((*App).NetworkChangesPage))

	// Пассивное обнаружение устройств
	mux.HandleFunc("GET /discovery", a.deviceScoped((*App).DiscoveryPage))
	mux.HandleFunc("POST /discovery/{id}/action", a.deviceScoped((*App).DiscoveryAction))

	return withRecover(a.withSecurity(mux))
}

// agentDeviceIDs возвращает id всех устройств с установленным агентом —
// цели для команд и раздачи ПО «на все ПК».
func (a *App) agentDeviceIDs() []int64 {
	rows, err := a.DB.Query(`SELECT id FROM devices WHERE COALESCE(agent_token,'')<>'' AND ` + a.deviceScopeSQL("devices.id"))
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
func setSessionCookie(w http.ResponseWriter, token string, request ...*http.Request) {
	secure := len(request) > 0 && request[0].TLS != nil
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		MaxAge:   28800,
		SameSite: http.SameSiteLaxMode,
	})
}

func clearSessionCookie(w http.ResponseWriter, request ...*http.Request) {
	secure := len(request) > 0 && request[0].TLS != nil
	http.SetCookie(w, &http.Cookie{
		Name:   "session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
		Secure: secure,
	})
}
