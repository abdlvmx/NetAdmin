// Package config — пути, константы и чтение/запись config.json.
package config

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
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
	HelpdeskEnabled   bool   `json:"helpdesk_enabled"`    // приём заявок сотрудников через портал /help
}

// Load читает config.json, подставляя дефолты и генерируя токен агента при
// его отсутствии (с сохранением на диск).
func Load() Config {
	c := Config{OrganizationName: DefaultOrgName}
	if data, err := os.ReadFile(ConfigPath()); err == nil {
		_ = json.Unmarshal(data, &c)
	}
	if c.OrganizationName == "" {
		c.OrganizationName = DefaultOrgName
	}
	if c.AgentToken == "" {
		c.AgentToken = randomToken()
		c.HelpdeskEnabled = true // свежая установка: портал заявок включён по умолчанию
		_ = Save(c)
	}
	return c
}

// Save пишет config.json.
func Save(c Config) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	// в файле лежат enrollment-токен и пароль SMTP — доступ только владельцу
	return os.WriteFile(ConfigPath(), data, 0o600)
}

// GenerateToken возвращает новый токен агента (для ротации в настройках).
func GenerateToken() string { return randomToken() }

func randomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
