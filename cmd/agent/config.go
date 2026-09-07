package main

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
)

// agentConfig — постоянные настройки, которые записывает `agent -install`.
//
// Раньше адрес и токен уезжали в машинные переменные окружения (`setx /M` в
// install_agent.bat). Это работало, но enrollment-токен оставался в окружении
// каждого процесса на машине навсегда — даже спустя год после регистрации,
// когда он уже не нужен. Файл рядом с агентом решает и это: после успешной
// регистрации токен из него стирается (см. clearEnrollToken).
type agentConfig struct {
	ServerURL   string `json:"server_url"`
	EnrollToken string `json:"enroll_token,omitempty"`
}

// Источники настроек — для журнала и для `-check`: когда адрес неверный, первым
// делом нужно знать, откуда агент его взял.
const (
	sourceConfig  = "agent_config.json"
	sourceEnv     = "переменные окружения"
	sourceDefault = "значения по умолчанию"
)

// settingsSource — откуда взялись действующие настройки, заполняется в
// loadSettings.
var settingsSource = sourceDefault

// rawServerURL — адрес до достраивания до полного вида, как его задали.
var rawServerURL string

func exeDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
}

func configPathIn(dir string) string { return filepath.Join(dir, "agent_config.json") }
func configPath() string             { return configPathIn(exeDir()) }

func loadAgentConfigFrom(dir string) agentConfig {
	var c agentConfig
	if b, err := os.ReadFile(configPathIn(dir)); err == nil {
		_ = json.Unmarshal(b, &c)
	}
	return c
}

// saveAgentConfigTo пишет настройки рядом с агентом.
//
// Токен ложится в открытом виде намеренно: DPAPI здесь не годится — установщик
// работает от администратора, а служба от SYSTEM, и пользовательский ключ
// второй учётной записи не расшифровывается. Машинная область DPAPI сводится к
// сокрытию от беглого взгляда, поскольку расшифровать сможет любой процесс той
// же машины. Вместо этого токен живёт в файле считаные секунды — до первой
// удачной регистрации.
func saveAgentConfigTo(dir string, c agentConfig) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configPathIn(dir), b, 0o600)
}

// clearEnrollToken убирает enrollment-токен из файла настроек: после выдачи
// персонального токена устройства он больше не нужен, а лежать и ждать своего
// злоупотребления — нужен ещё меньше.
func clearEnrollToken() {
	path := configPath()
	c := loadAgentConfigFrom(exeDir())
	if c.EnrollToken == "" {
		return
	}
	c.EnrollToken = ""
	if err := saveAgentConfigTo(exeDir(), c); err != nil {
		log.Printf("не удалось стереть enrollment-токен из %s: %v", path, err)
	}
}

// loadSettings определяет действующие адрес сервера и enrollment-токен.
//
// Порядок: файл настроек, затем переменные окружения, затем умолчание. Файл
// стоит первым, потому что его пишет установщик этой машины, а переменные
// могли остаться от прошлой установки через install_agent.bat — и тогда
// переустановка агента на новый сервер молча не срабатывала бы.
func loadSettings() {
	c := loadAgentConfigFrom(exeDir())
	envURL, envTok := os.Getenv("NETADMIN_SERVER_URL"), os.Getenv("NETADMIN_AGENT_TOKEN")

	switch {
	case c.ServerURL != "":
		rawServerURL, settingsSource = c.ServerURL, sourceConfig
	case envURL != "":
		rawServerURL, settingsSource = envURL, sourceEnv
	default:
		rawServerURL, settingsSource = "", sourceDefault
	}
	serverURL = normalizeServerURL(rawServerURL)

	if c.EnrollToken != "" {
		token = c.EnrollToken
	} else {
		token = envTok
	}
}
