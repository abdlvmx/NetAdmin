// Package config — пути, константы и чтение/запись config.json.
package config

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	MetricsRetentionDays = 90  // история метрик
	EventsRetentionDays  = 180 // события (инциденты-корреляции не удаляются)
	AuditRetentionDays   = 365 // журнал действий
	DefaultOrgName       = "Local organization"
	// HeartbeatTimeoutMin — через сколько минут без единого обращения агента
	// устройство считается offline.
	//
	// Отсчёт идёт от ЛЮБОГО запроса агента, а не от heartbeat: за задачами
	// агент обращается каждые 15 секунд, поэтому двух минут хватает с запасом
	// в восемь пропущенных опросов. Привязывать этот срок к heartbeat нельзя —
	// он адаптивный и при стабильной нагрузке приходит раз в 5 минут, из-за
	// чего спокойные машины мигали online/offline.
	HeartbeatTimeoutMin = 2
)

// DataDir — каталог для записываемых данных (БД, config.json): рядом с
// бинарником, либо NETADMIN_DATA_DIR, либо текущая директория.
func DataDir() string {
	if d := os.Getenv("NETADMIN_DATA_DIR"); d != "" {
		return d
	}
	if exe, err := os.Executable(); err == nil {
		return filepath.Dir(exe)
	}
	wd, _ := os.Getwd()
	return wd
}

func DBPath() string     { return filepath.Join(DataDir(), "netadmin.db") }
func ConfigPath() string { return filepath.Join(DataDir(), "config.json") }

// Config — локальные настройки приложения.
type Config struct {
	OrganizationName string `json:"organization_name"`
	AgentToken       string `json:"agent_token"`
	// Email-уведомления (SMTP)
	SMTPHost          string `json:"smtp_host"`
	SMTPPort          int    `json:"smtp_port"`
	SMTPUser          string `json:"smtp_user"`
	SMTPPass          string `json:"smtp_pass"`
	SMTPFrom          string `json:"smtp_from"`
	SMTPTo            string `json:"smtp_to"`             // получатели через запятую
	ScanIntervalHours int    `json:"scan_interval_hours"` // 0 = автоскан выключен
	// Резервные копии базы. BackupIntervalHours=0 отключает расписание,
	// ручное копирование остаётся доступным. BackupKeep=0 отключает ротацию.
	BackupIntervalHours int    `json:"backup_interval_hours"`
	BackupKeep          int    `json:"backup_keep"`
	BackupDir           string `json:"backup_dir"`       // пусто = <каталог данных>/backups
	HelpdeskEnabled     bool   `json:"helpdesk_enabled"` // приём заявок сотрудников через портал /help
	// Timezone — часовой пояс для показа времени, имя IANA
	// («Asia/Yekaterinburg»). Пусто — зона самой машины сервера. В базе
	// время всегда UTC, пояс применяется только на вывод.
	Timezone string `json:"timezone"`
	// Сетевые настройки. Пустое значение означает «не задано»: тогда берётся
	// одноимённая переменная окружения, а если нет и её — умолчание.
	//
	// Заведены потому, что служба Windows не наследует окружение консоли, из
	// которой её ставили: указание задать NETADMIN_ALLOW перед запуском для
	// установленной службы молча не срабатывало, и сузить доступ было негде.
	ListenAddr   string `json:"listen_addr"`   // пусто = 0.0.0.0:8765
	AllowSubnets string `json:"allow_subnets"` // пусто = локальные и частные сети
	// OnboardingHidden — чек-лист первых шагов убран с дашборда вручную.
	// Хранится здесь, а не у пользователя: чек-лист описывает состояние
	// установки, а не личный прогресс, и скрытый одним скрыт для всех.
	OnboardingHidden bool `json:"onboarding_hidden"`
}

// NetworkSetting — действующее значение сетевой настройки и его источник.
type NetworkSetting struct {
	Value  string
	Source string // SourceEnv, SourceConfig или SourceDefault
}

// Источники сетевых настроек — показываются в интерфейсе, чтобы «задал, а не
// применилось» не превращалось в поиск вслепую.
const (
	SourceEnv     = "переменная окружения"
	SourceConfig  = "настройки"
	SourceDefault = "по умолчанию"
)

// resolveNet выбирает действующее значение: переменная окружения важнее
// настройки из файла.
//
// Такой порядок сохраняет поведение развёртываний, где всё задано окружением
// (контейнеры, запуск из консоли), — они продолжают работать в точности как
// раньше. Чтобы «задал в интерфейсе, а работает старое» не оставалось
// незамеченным, страница настроек показывает, что значение перекрыто
// переменной, и какой именно.
func resolveNet(env, fromFile string) NetworkSetting {
	if v := strings.TrimSpace(os.Getenv(env)); v != "" {
		return NetworkSetting{Value: v, Source: SourceEnv}
	}
	if v := strings.TrimSpace(fromFile); v != "" {
		return NetworkSetting{Value: v, Source: SourceConfig}
	}
	return NetworkSetting{Source: SourceDefault}
}

// ListenAddrSetting — адрес прослушивания с учётом всех источников.
func (c Config) ListenAddrSetting() NetworkSetting {
	return resolveNet("NETADMIN_ADDR", c.ListenAddr)
}

// AllowSubnetsSetting — разрешённые подсети с учётом всех источников.
func (c Config) AllowSubnetsSetting() NetworkSetting {
	return resolveNet("NETADMIN_ALLOW", c.AllowSubnets)
}

// Кэш прочитанной конфигурации.
//
// Load вызывается на каждом запросе портала заявок, при каждой регистрации
// агента и раз в минуту в планировщике — читать файл с диска каждый раз
// незачем. Кэш обновляется, когда меняются путь, время правки или размер
// файла, а Save заполняет его сразу: изменения из самого приложения
// подхватываются точно, без оглядки на разрешение времени файловой системы.
var (
	cacheMu   sync.RWMutex
	cached    Config
	cachedKey string // путь + время правки + размер
	cachedOK  bool
)

// cacheKey описывает состояние файла: при любом расхождении конфигурация
// перечитывается. Путь входит в ключ, потому что каталог данных задаётся
// переменной окружения и может смениться.
func cacheKey(path string) string {
	st, err := os.Stat(path)
	if err != nil {
		return path + "|absent"
	}
	return path + "|" + st.ModTime().UTC().Format(time.RFC3339Nano) + "|" + strconv.FormatInt(st.Size(), 10)
}

// Load читает config.json, подставляя дефолты и генерируя токен агента при
// его отсутствии (с сохранением на диск).
func Load() Config {
	path := ConfigPath()
	key := cacheKey(path)

	cacheMu.RLock()
	if cachedOK && cachedKey == key {
		c := cached
		cacheMu.RUnlock()
		return c
	}
	cacheMu.RUnlock()

	c := Config{OrganizationName: DefaultOrgName}
	if data, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(data, &c)
	}
	if c.OrganizationName == "" {
		c.OrganizationName = DefaultOrgName
	}
	if c.BackupIntervalHours == 0 && c.BackupKeep == 0 {
		// свежая установка: сутки между копиями, храним неделю
		c.BackupIntervalHours, c.BackupKeep = 24, 7
	}
	if c.AgentToken == "" {
		c.AgentToken = randomToken()
		c.HelpdeskEnabled = true // свежая установка: портал заявок включён по умолчанию
		_ = Save(c)              // Save сам обновит кэш
		return c
	}

	cacheMu.Lock()
	cached, cachedKey, cachedOK = c, key, true
	cacheMu.Unlock()
	return c
}

// Save пишет config.json и обновляет кэш.
func Save(c Config) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	path := ConfigPath()
	// в файле лежат enrollment-токен и пароль SMTP — доступ только владельцу
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return err
	}
	cacheMu.Lock()
	cached, cachedKey, cachedOK = c, cacheKey(path), true
	cacheMu.Unlock()
	return nil
}

// GenerateToken возвращает новый токен агента (для ротации в настройках).
func GenerateToken() string { return randomToken() }

func randomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
