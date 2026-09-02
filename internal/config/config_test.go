package config

import (
	"os"
	"testing"
)

// Первый Load на пустом каталоге создаёт конфигурацию и enrollment-токен.
func TestLoadCreatesTokenOnFirstRun(t *testing.T) {
	t.Setenv("NETADMIN_DATA_DIR", t.TempDir())

	c := Load()
	if c.AgentToken == "" {
		t.Fatal("enrollment-токен должен создаваться при первом запуске")
	}
	if !c.HelpdeskEnabled {
		t.Error("на свежей установке портал заявок включён по умолчанию")
	}
	if _, err := os.Stat(ConfigPath()); err != nil {
		t.Fatalf("config.json должен появиться на диске: %v", err)
	}
	if got := Load(); got.AgentToken != c.AgentToken {
		t.Error("повторный Load не должен перевыпускать токен")
	}
}

// Save должен немедленно отражаться в Load, не дожидаясь смены времени файла:
// у файловой системы разрешение времени грубее, чем частота правок настроек.
func TestSaveIsVisibleImmediately(t *testing.T) {
	t.Setenv("NETADMIN_DATA_DIR", t.TempDir())

	c := Load()
	c.OrganizationName = "ООО Ромашка"
	c.SMTPHost = "mail.local"
	if err := Save(c); err != nil {
		t.Fatalf("save: %v", err)
	}
	got := Load()
	if got.OrganizationName != "ООО Ромашка" || got.SMTPHost != "mail.local" {
		t.Fatalf("сохранённые настройки должны читаться сразу, получено %+v", got)
	}
}

// Кэш не должен переезжать между каталогами данных: путь входит в ключ.
func TestCacheIsPerDataDir(t *testing.T) {
	first := t.TempDir()
	t.Setenv("NETADMIN_DATA_DIR", first)
	c := Load()
	c.OrganizationName = "Первая"
	if err := Save(c); err != nil {
		t.Fatalf("save: %v", err)
	}

	// другой каталог — своя конфигурация, а не остаток от прежней
	t.Setenv("NETADMIN_DATA_DIR", t.TempDir())
	other := Load()
	if other.OrganizationName == "Первая" {
		t.Fatal("конфигурация одного каталога данных подтянулась в другой")
	}
	if other.AgentToken == c.AgentToken {
		t.Fatal("в новом каталоге должен быть свой enrollment-токен")
	}
}

// Правка файла со стороны подхватывается — размер меняется, ключ кэша тоже.
func TestExternalEditIsPickedUp(t *testing.T) {
	t.Setenv("NETADMIN_DATA_DIR", t.TempDir())
	_ = Load()

	if err := os.WriteFile(ConfigPath(),
		[]byte(`{"organization_name":"Правка снаружи","agent_token":"EXTERNALTOKEN"}`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := Load()
	if got.OrganizationName != "Правка снаружи" || got.AgentToken != "EXTERNALTOKEN" {
		t.Fatalf("изменение файла должно подхватываться, получено %+v", got)
	}
}
