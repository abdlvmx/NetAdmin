// Package diagnostics collects a small, read-only support snapshot. It deliberately
// exports classifications and counters rather than configuration, logs or errors.
package diagnostics

import (
	"archive/zip"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"netadmin/internal/config"
	"netadmin/internal/netaccess"
)

const (
	MaxArchiveBytes   = 64 << 10
	maxNetworkBytes   = 8 << 10
	maxBackupEntries  = 2048
	ConfigOK          = "ok"
	ConfigMissing     = "missing"
	ConfigInvalid     = "invalid"
	ConfigUnavailable = "unavailable"
	ConfigBusy        = "busy"
	ConfigTimeout     = "timeout"
)

// Input contains only the settings needed for checks. Never pass request data,
// credentials, error strings or log lines to a report.
type Input struct {
	DB                  *sql.DB
	Version             string
	ConfigState         string
	Listen              config.NetworkSetting
	Allow               config.NetworkSetting
	DataDir             string
	DBPath              string
	BackupDir           string
	BackupIntervalHours int
	IsService           bool
	Demo                bool
}

type Summary struct {
	FormatVersion     int       `json:"format_version"`
	CreatedAt         time.Time `json:"created_at"`
	Version           string    `json:"version"`
	OS                string    `json:"os"`
	Architecture      string    `json:"architecture"`
	Mode              string    `json:"mode"`
	DatabaseAvailable bool      `json:"database_available"`
	Agents            Agents    `json:"agents"`
	Tasks             Tasks     `json:"tasks"`
	Network           Network   `json:"network"`
	Backup            Backup    `json:"backup"`
}

type Agents struct {
	Known  bool  `json:"known"`
	Total  int64 `json:"total"`
	Online int64 `json:"online"`
}

type Tasks struct {
	Known             bool  `json:"known"`
	Pending           int64 `json:"pending"`
	FailedLast24Hours int64 `json:"failed_last_24_hours"`
}

type Network struct {
	ListenValid  bool   `json:"listen_valid"`
	ListenScope  string `json:"listen_scope"`
	ListenSource string `json:"listen_source"`
	AllowValid   bool   `json:"allow_valid"`
	AllowMode    string `json:"allow_mode"`
	AllowSource  string `json:"allow_source"`
}

type Backup struct {
	Scheduled           bool       `json:"scheduled"`
	Known               bool       `json:"known"`
	Count               int        `json:"count"`
	Latest              *time.Time `json:"latest,omitempty"`
	ListingLimited      bool       `json:"listing_limited"`
	PendingRestore      bool       `json:"pending_restore"`
	PendingRestoreKnown bool       `json:"pending_restore_known"`
}

type Check struct {
	Code     string `json:"code"`
	Level    string `json:"level"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	NextStep string `json:"next_step,omitempty"`
	Href     string `json:"href,omitempty"`
}

func (c Check) Label() string {
	switch c.Level {
	case "ok":
		return "В порядке"
	case "warning":
		return "Проверьте"
	case "error":
		return "Нужна помощь"
	case "info":
		return "К сведению"
	default:
		return "Не проверено"
	}
}

func (c Check) Badge() string {
	switch c.Level {
	case "ok":
		return "badge-green"
	case "warning":
		return "badge-amber"
	case "error":
		return "badge-red"
	case "info":
		return "badge-accent"
	default:
		return "badge-gray"
	}
}

type Report struct {
	Summary Summary `json:"summary"`
	Checks  []Check `json:"checks"`
}

func (r Report) AttentionCount() int {
	n := 0
	for _, c := range r.Checks {
		if c.Level == "warning" || c.Level == "error" {
			n++
		}
	}
	return n
}

func (r Report) UncheckedCount() int {
	n := 0
	for _, c := range r.Checks {
		if c.Level == "unknown" {
			n++
		}
	}
	return n
}

var safeVersion = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+\-]{0,63}$`)
var backupName = regexp.MustCompile(`^netadmin-[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{4}(-[0-9]{2})?\.db$`)

// Collect performs no writes, shell commands or outgoing network requests.
// Database operations share a three-second deadline and filesystem listings
// are capped. Raw paths, addresses and underlying errors are never exported.
func Collect(ctx context.Context, in Input) Report {
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	ver := in.Version
	if !safeVersion.MatchString(ver) {
		ver = "unknown"
	}
	r := Report{Summary: Summary{FormatVersion: 1, CreatedAt: time.Now().UTC(), Version: ver,
		OS: runtime.GOOS, Architecture: runtime.GOARCH, Mode: "console"}, Checks: []Check{}}
	if in.IsService {
		r.Summary.Mode = "service"
	}
	if in.Demo {
		r.Summary.Mode = "demo"
	}
	r.database(ctx, in.DB)
	r.configuration(in)
	r.network(in)
	r.backups(ctx, in)
	switch r.Summary.Mode {
	case "service":
		r.add("mode", "ok", "Сервер работает как служба", "Закрытие браузера не остановит сервер.", "", "")
	case "demo":
		r.add("mode", "info", "Открыт демонстрационный режим", "Здесь используются демонстрационные данные. Активные проверки сети отключены.", "Для своих компьютеров запустите обычный режим из комплекта NetAdmin.", "")
	default:
		r.add("mode", "info", "Сервер запущен из окна", "После закрытия процесса сервер и панель станут недоступны.", "Для постоянной работы используйте установку сервера как службы из комплекта NetAdmin.", "")
	}
	return r
}

func (r *Report) add(code, level, title, detail, next, href string) {
	r.Checks = append(r.Checks, Check{Code: code, Level: level, Title: title, Detail: detail, NextStep: next, Href: href})
}

func (r *Report) database(ctx context.Context, db *sql.DB) {
	if db == nil || db.PingContext(ctx) != nil {
		if db != nil && ctx.Err() != nil {
			r.add("database", "unknown", "База данных не проверена", "Общее время диагностики истекло до завершения проверки базы.", "Повторите диагностику после проверки доступности каталога данных.", "")
		} else {
			r.add("database", "error", "База данных недоступна", "Проверка соединения с базой не завершилась успешно.", "Проверьте место на диске и работу службы. Перед восстановлением сохраните текущие файлы данных.", "/settings#settings-backup")
		}
		r.add("agents", "unknown", "Подключение компьютеров не проверено", "Без базы нельзя получить достоверные сведения об агентах.", "Сначала восстановите доступ к базе данных.", "")
		r.add("tasks", "unknown", "Удалённые задачи не проверены", "История выполнения задач сейчас недоступна.", "Сначала восстановите доступ к базе данных.", "")
		return
	}
	r.Summary.DatabaseAvailable = true
	r.add("database", "ok", "База данных отвечает", "Сервер может выполнить запрос к базе. Полная проверка целостности в эту диагностику не входит.", "", "")
	ag := &r.Summary.Agents
	err := db.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(CASE WHEN last_seen >= datetime('now','-2 minutes') THEN 1 ELSE 0 END),0)
		FROM devices WHERE COALESCE(agent_token,'')<>''`).Scan(&ag.Total, &ag.Online)
	if err != nil {
		*ag = Agents{}
		r.add("agents", "unknown", "Сведения об агентах недоступны", "Не удалось получить количество подключённых компьютеров.", "Повторите проверку. Если проблема повторяется, сохраните архив диагностики.", "")
	} else {
		ag.Known = true
		switch {
		case ag.Total == 0:
			r.add("agents", "info", "Компьютеры ещё не подключены", "На сервере нет зарегистрированных агентов.", "В настройках скачайте подготовленный агент и запустите его на нужном компьютере.", "/settings#settings-agents")
		case ag.Online < ag.Total:
			r.add("agents", "warning", "Часть компьютеров не выходит на связь", "У некоторых агентов не было обращений за последние две минуты. Компьютер может быть выключен.", "Откройте список устройств и проверьте питание, сеть и службу агента на недоступных компьютерах.", "/devices")
		default:
			r.add("agents", "ok", "Все зарегистрированные агенты на связи", "Каждый агент обращался к серверу за последние две минуты.", "", "")
		}
	}
	ta := &r.Summary.Tasks
	err = db.QueryRowContext(ctx, `SELECT COALESCE(SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN status='failed' AND COALESCE(done_at,created_at)>=datetime('now','-1 day') THEN 1 ELSE 0 END),0) FROM agent_tasks`).Scan(&ta.Pending, &ta.FailedLast24Hours)
	if err != nil {
		*ta = Tasks{}
		r.add("tasks", "unknown", "Удалённые задачи не проверены", "Не удалось получить сводку истории задач.", "Повторите проверку. Если проблема повторяется, сохраните архив диагностики.", "")
	} else {
		ta.Known = true
		if ta.FailedLast24Hours > 0 {
			r.add("tasks", "warning", "Есть неудачные удалённые задачи", "За последние сутки агенты сообщили об ошибках выполнения.", "Откройте нужное устройство и прочитайте результат задачи перед повторным запуском.", "/devices")
		} else {
			r.add("tasks", "ok", "Ошибок удалённых задач за сутки нет", "В сохранённой истории нет задач со статусом ошибки за последние 24 часа. Ожидающие задачи ещё не завершены.", "", "")
		}
	}
}

func (r *Report) configuration(in Input) {
	switch in.ConfigState {
	case ConfigMissing:
		r.add("configuration", "info", "Файл настроек ещё не создан", "Для проверки используются значения по умолчанию и сетевые настройки окружения.", "Завершите первоначальную настройку приложения.", "/settings")
	case ConfigInvalid:
		r.add("configuration", "error", "Не удалось разобрать файл настроек", "Файл слишком большой или содержит некорректные данные. Значения из него не проверялись.", "Сохраните копию файла и проверьте настройки на компьютере сервера.", "")
	case ConfigUnavailable:
		r.add("configuration", "error", "Файл настроек недоступен", "Не удалось прочитать настройки сервера.", "Проверьте доступ службы к каталогу данных на компьютере сервера.", "")
	case ConfigBusy:
		r.add("configuration", "unknown", "Проверка файлов уже выполняется", "Предыдущая проверка файлов ещё не завершилась. Новая проверка не запущена, чтобы сервер продолжал отвечать.", "Подождите и повторите диагностику. Если состояние сохраняется, проверьте доступность диска или сетевого каталога данных.", "")
	case ConfigTimeout:
		r.add("configuration", "unknown", "Чтение настроек не завершилось вовремя", "Каталог данных не ответил за отведённое время. Это может произойти при недоступности сетевого диска.", "Проверьте доступность каталога данных и повторите диагностику.", "")
	default:
		r.add("configuration", "ok", "Файл настроек читается", "Сохранённые настройки удалось прочитать.", "", "")
	}
}

func source(s string) string {
	switch s {
	case config.SourceEnv:
		return "environment"
	case config.SourceConfig:
		return "settings"
	default:
		return "default"
	}
}

func (r *Report) network(in Input) {
	n := &r.Summary.Network
	n.ListenSource, n.AllowSource = source(in.Listen.Source), source(in.Allow.Source)
	if unavailableConfig(in.ConfigState) {
		r.add("listen", "unknown", "Адрес подключения не проверен", "Сохранённые сетевые настройки недоступны.", "Сначала проверьте файл настроек.", "")
		r.add("access", "unknown", "Правила доступа не проверены", "Сохранённые правила доступа недоступны.", "Сначала проверьте файл настроек.", "")
		return
	}
	addr := strings.TrimSpace(in.Listen.Value)
	if addr == "" {
		addr = "0.0.0.0:8765"
	}
	host, port, err := net.SplitHostPort(addr)
	p, pe := strconv.Atoi(port)
	if len(addr) > maxNetworkBytes || err != nil || pe != nil || p < 1 || p > 65535 {
		n.ListenScope = "invalid"
		r.add("listen", "error", "Адрес подключения задан неверно", "Адрес должен содержать имя или IP и порт от 1 до 65535.", "Исправьте адрес прослушивания в сетевых настройках и перезапустите сервер.", "/settings#settings-network")
	} else {
		n.ListenValid = true
		ip := net.ParseIP(host)
		switch {
		case strings.EqualFold(host, "localhost") || ip != nil && ip.IsLoopback():
			n.ListenScope = "loopback"
			r.add("listen", "info", "Подключение доступно только на сервере", "Адрес прослушивания ограничен этим компьютером. Агенты на других компьютерах через него не подключатся.", "Для подключения компьютеров сети выберите доступный сетевой адрес в настройках.", "/settings#settings-network")
		case host == "" || ip != nil && ip.IsUnspecified():
			n.ListenScope = "all_interfaces"
			r.add("listen", "ok", "Адрес прослушивания задан корректно", "Сервер настроен принимать подключения на сетевых интерфейсах. Доступ из другого компьютера и брандмауэр этой проверкой не проверяются.", "", "")
		default:
			n.ListenScope = "specific_interface"
			r.add("listen", "ok", "Адрес прослушивания задан корректно", "Указаны отдельный адрес и допустимый порт. Доступность адреса из сети этой проверкой не проверяется.", "", "")
		}
	}
	var allow netaccess.List
	var allowErr error
	if len(in.Allow.Value) <= maxNetworkBytes {
		allow, allowErr = netaccess.Parse(in.Allow.Value)
	}
	if len(in.Allow.Value) > maxNetworkBytes || allowErr != nil {
		n.AllowMode = "invalid"
		r.add("access", "error", "Список разрешённых сетей задан неверно", "Не удалось разобрать правила доступа к серверу.", "Исправьте список разрешённых подсетей в настройках и перезапустите сервер.", "/settings#settings-network")
	} else {
		n.AllowValid = true
		if allow.Unrestricted() {
			n.AllowMode = "unrestricted"
			r.add("access", "warning", "Ограничение доступа по сети снято", "Настройка разрешает обращения с любых адресов.", "Укажите подсети организации в сетевых настройках.", "/settings#settings-network")
		} else {
			n.AllowMode = "restricted"
			r.add("access", "ok", "Доступ ограничен разрешёнными сетями", "Правила доступа удалось разобрать. Конкретные адреса не включаются в архив.", "", "")
		}
	}
	if n.ListenSource == "environment" || n.AllowSource == "environment" {
		r.add("network_override", "info", "Окружение задаёт сетевые настройки", "Некоторые сетевые значения имеют приоритет над настройками в интерфейсе.", "Если изменение в интерфейсе не применяется, проверьте сетевые переменные окружения службы.", "/settings#settings-network")
	}
}

func unavailableConfig(state string) bool {
	return state == ConfigInvalid || state == ConfigUnavailable || state == ConfigBusy || state == ConfigTimeout
}

type backupSnapshot struct {
	count        int
	latest       time.Time
	limited      bool
	backupErr    error
	pending      bool
	pendingKnown bool
}

func (r *Report) backups(ctx context.Context, in Input) {
	b := &r.Summary.Backup
	b.Scheduled = in.BackupIntervalHours > 0
	if unavailableConfig(in.ConfigState) {
		r.add("backups", "unknown", "Резервные копии не проверены", "Нельзя определить каталог копий без сохранённых настроек.", "Сначала проверьте файл настроек.", "")
		r.add("restore", "unknown", "Подготовленное восстановление не проверено", "Доступность каталога данных сейчас не подтверждена.", "Повторите диагностику после проверки каталога данных.", "")
		return
	}
	dir := strings.TrimSpace(in.BackupDir)
	if dir == "" {
		if in.DataDir == "" {
			r.add("backups", "unknown", "Каталог копий не определён", "Путь к каталогу данных недоступен.", "Проверьте настройки сервера.", "/settings#settings-backup")
			return
		}
		dir = filepath.Join(in.DataDir, "backups")
	}
	snapshot, probeErr := Filesystem(ctx, func() (backupSnapshot, error) {
		var snapshot backupSnapshot
		if ctx.Err() != nil {
			return snapshot, ErrFilesystemTimeout
		}
		if in.DBPath != "" {
			st, err := os.Stat(in.DBPath + ".restore")
			snapshot.pendingKnown = err == nil || errors.Is(err, os.ErrNotExist)
			snapshot.pending = err == nil && st.Mode().IsRegular()
		}
		if ctx.Err() != nil {
			return snapshot, ErrFilesystemTimeout
		}
		snapshot.count, snapshot.latest, snapshot.limited, snapshot.backupErr = scanBackupsContext(ctx, dir, maxBackupEntries)
		return snapshot, nil
	})
	if probeErr != nil {
		if errors.Is(probeErr, ErrFilesystemBusy) {
			r.add("backups", "unknown", "Проверка файлов уже выполняется", "Каталог копий сейчас не проверялся: предыдущая файловая операция ещё не завершилась.", "Подождите и повторите диагностику. Если состояние сохраняется, проверьте диск или сетевой каталог копий.", "/settings#settings-backup")
		} else {
			r.add("backups", "unknown", "Проверка копий не завершилась вовремя", "Каталог данных или копий не ответил за отведённое время. Результат не считается успешным.", "Проверьте доступность диска или сетевого каталога и повторите диагностику.", "/settings#settings-backup")
		}
		r.add("restore", "unknown", "Подготовленное восстановление не проверено", "Файловая проверка не завершилась. Наличие файла восстановления пока неизвестно.", "Повторите диагностику после проверки каталога данных.", "")
		return
	}
	b.PendingRestore, b.PendingRestoreKnown = snapshot.pending, snapshot.pendingKnown
	if !b.PendingRestoreKnown {
		r.add("restore", "unknown", "Подготовленное восстановление не проверено", "Не удалось проверить файл восстановления в каталоге данных.", "Проверьте доступ службы к каталогу данных.", "")
	} else if b.PendingRestore {
		r.add("restore", "warning", "Подготовлено восстановление базы", "При следующем запуске сервер применит выбранную ранее резервную копию.", "Проверьте, что восстановление нужно, или отмените его до перезапуска.", "/settings#settings-backup")
	}
	count, latest, limited, err := snapshot.count, snapshot.latest, snapshot.limited, snapshot.backupErr
	b.ListingLimited = limited
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			b.Known = true
			r.add("backups", "info", "Резервных копий пока нет", "Каталог резервных копий ещё не создан.", "Создайте первую копию в настройках резервного копирования.", "/settings#settings-backup")
		} else {
			r.add("backups", "error", "Каталог копий недоступен", "Не удалось прочитать содержимое каталога. Пути и системные сообщения не включаются в архив.", "Проверьте, доступен ли диск и есть ли у службы права на каталог копий.", "/settings#settings-backup")
		}
		return
	}
	if limited {
		r.add("backups", "unknown", "Слишком много файлов в каталоге копий", "Достигнут предел безопасного просмотра каталога. Полное количество и свежесть копий не определены.", "Используйте отдельный каталог для копий и настройте их хранение.", "/settings#settings-backup")
		return
	}
	b.Known, b.Count = true, count
	if !latest.IsZero() {
		latest = latest.UTC()
		b.Latest = &latest
	}
	switch {
	case count == 0:
		r.add("backups", "info", "Резервных копий пока нет", "В каталоге не найдены файлы резервных копий NetAdmin.", "Создайте первую копию в настройках резервного копирования.", "/settings#settings-backup")
	case !b.Scheduled:
		r.add("backups", "info", "Копии есть, расписание выключено", "Для появления новых копий требуется ручной запуск.", "Включите расписание, если сервер используется постоянно.", "/settings#settings-backup")
	default:
		// Match the backup alarm's grace period; cap corrupted integer values.
		hours := in.BackupIntervalHours
		if hours > 8760 {
			hours = 8760
		}
		d := 2 * time.Duration(hours) * time.Hour
		if d < 24*time.Hour {
			d = 24 * time.Hour
		}
		if time.Since(latest) > d {
			r.add("backups", "warning", "Резервная копия давно не обновлялась", "Последний файл старше двух интервалов расписания или суток.", "Создайте копию вручную и проверьте результат. Затем проверьте работу расписания.", "/settings#settings-backup")
		} else {
			r.add("backups", "ok", "Есть свежая резервная копия", "Найден недавний файл копии. Его содержимое и возможность восстановления этой проверкой не проверяются.", "", "")
		}
	}
}

func scanBackups(dir string, limit int) (int, time.Time, bool, error) {
	return scanBackupsContext(context.Background(), dir, limit)
}

func scanBackupsContext(ctx context.Context, dir string, limit int) (int, time.Time, bool, error) {
	if ctx.Err() != nil {
		return 0, time.Time{}, false, ctx.Err()
	}
	f, err := os.Open(dir)
	if err != nil {
		return 0, time.Time{}, false, err
	}
	defer f.Close()
	if ctx.Err() != nil {
		return 0, time.Time{}, false, ctx.Err()
	}
	entries, err := f.ReadDir(limit + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return 0, time.Time{}, false, err
	}
	if len(entries) > limit {
		return 0, time.Time{}, true, nil
	}
	count := 0
	var latest time.Time
	for _, e := range entries {
		if ctx.Err() != nil {
			return 0, time.Time{}, false, ctx.Err()
		}
		if !e.Type().IsRegular() || !backupName.MatchString(e.Name()) {
			continue
		}
		st, err := e.Info()
		if err != nil {
			return 0, time.Time{}, false, err
		}
		if !st.Mode().IsRegular() || st.Size() == 0 {
			continue
		}
		count++
		if st.ModTime().After(latest) {
			latest = st.ModTime()
		}
	}
	return count, latest, false, nil
}

// Archive writes exactly three allowlisted files. Limits apply before
// compression so a small ZIP cannot hide a huge uncompressed report.
func Archive(r Report) ([]byte, error) {
	if len(r.Checks) > 32 {
		return nil, errors.New("diagnostic report too large")
	}
	for _, c := range r.Checks {
		if len(c.Code) > 64 || len(c.Level) > 16 || len(c.Title) > 256 || len(c.Detail) > 2048 || len(c.NextStep) > 2048 || len(c.Href) > 128 {
			return nil, errors.New("diagnostic report too large")
		}
	}
	if len(r.Summary.Version) > 64 || len(r.Summary.OS) > 32 || len(r.Summary.Architecture) > 32 || len(r.Summary.Mode) > 32 ||
		len(r.Summary.Network.ListenScope) > 32 || len(r.Summary.Network.ListenSource) > 32 || len(r.Summary.Network.AllowMode) > 32 || len(r.Summary.Network.AllowSource) > 32 {
		return nil, errors.New("diagnostic report too large")
	}
	summary, err := json.MarshalIndent(r.Summary, "", "  ")
	if err != nil {
		return nil, err
	}
	checks, err := json.MarshalIndent(r.Checks, "", "  ")
	if err != nil {
		return nil, err
	}
	readme := []byte("NetAdmin — диагностика\r\n\r\nsummary.json: версия, режим запуска и обезличенные количества.\r\nchecks.json: результаты проверок и следующие шаги.\r\n\r\nАрхив не содержит конфигурации, журналов, переменных окружения, паролей, токенов, IP-адресов, имён компьютеров, пользователей, адресов почты, текста команд и результатов их выполнения.\r\n\r\nПроверка не выполняет сетевые запросы, не изменяет настройки и не проверяет целостность базы или резервных копий. Сетевые настройки описывают сохранённые значения с учётом окружения; после изменения может требоваться перезапуск.\r\n\r\nВремя указано в UTC. Ошибки удалённых задач подсчитываются за 24 часа. Наличие связи означает обращение агента за последние две минуты.\r\n\r\nПеред отправкой можно открыть JSON-файлы и проверить содержимое. Отправка выполняется вами самостоятельно.\r\n")
	if len(summary)+len(checks)+len(readme) > MaxArchiveBytes {
		return nil, errors.New("diagnostic report too large")
	}
	var out bytes.Buffer
	z := zip.NewWriter(&out)
	for _, file := range []struct {
		name string
		data []byte
	}{{"summary.json", summary}, {"checks.json", checks}, {"README.txt", readme}} {
		w, err := z.Create(file.name)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(file.data); err != nil {
			return nil, err
		}
	}
	if err := z.Close(); err != nil {
		return nil, err
	}
	if out.Len() > MaxArchiveBytes {
		return nil, errors.New("diagnostic archive too large")
	}
	return out.Bytes(), nil
}
