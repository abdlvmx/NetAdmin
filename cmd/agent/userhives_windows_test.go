//go:build windows

package main

import (
	"strings"
	"testing"

	"golang.org/x/sys/windows/registry"
)

func TestIsUserSID(t *testing.T) {
	// учётные записи людей
	for _, sid := range []string{
		"S-1-5-21-1234567890-1234567890-1234567890-1001",
		"S-1-5-21-0-0-0-500",
	} {
		if !isUserSID(sid) {
			t.Errorf("%s — учётная запись пользователя, должна проходить", sid)
		}
	}
	// служебные кусты и шаблоны
	for _, sid := range []string{
		"S-1-5-18",                    // SYSTEM — под ним и работает агент
		"S-1-5-19",                    // LOCAL SERVICE
		"S-1-5-20",                    // NETWORK SERVICE
		".DEFAULT",                    // шаблон профиля
		"S-1-5-21-1-2-3-1001_Classes", // дубль основного куста
		"",
	} {
		if isUserSID(sid) {
			t.Errorf("%q не должен считаться профилем пользователя", sid)
		}
	}
}

// Интеграция: на машине, где кто-то вошёл, должен найтись хотя бы один профиль
// с корректным путём.
func TestUserHivesReal(t *testing.T) {
	hives := userHives()
	if len(hives) == 0 {
		t.Skip("ни один пользовательский куст не загружен — в этом окружении проверять нечего")
	}
	for _, h := range hives {
		if !isUserSID(h.SID) {
			t.Errorf("в списке оказался служебный куст: %s", h.SID)
		}
		if h.Name == "" {
			t.Errorf("%s: пустое имя профиля", h.SID)
		}
		if h.Profile != "" && !strings.Contains(strings.ToLower(h.Profile), ":\\") {
			t.Errorf("%s: путь профиля не похож на путь: %q", h.SID, h.Profile)
		}
	}
	t.Logf("найдено профилей: %d", len(hives))
}

// Инвентарь ПО должен включать программы, установленные «только для себя».
// Раньше собиралось только HKLM, и такие программы пропадали целиком.
func TestCollectSoftwareIncludesPerUser(t *testing.T) {
	if len(userHives()) == 0 {
		t.Skip("нет загруженных пользовательских кустов")
	}
	sw := collectSoftware()
	if len(sw) == 0 {
		t.Fatal("инвентарь ПО пуст")
	}
	// Считаем, сколько имён взято из пользовательских веток: сверяем список с
	// тем, что вернул бы сбор только по машинным веткам.
	perUser := perUserSoftwareNames(t)
	if len(perUser) == 0 {
		t.Skip("на этой машине нет ПО, установленного per-user")
	}
	got := map[string]bool{}
	for _, s := range sw {
		if n, ok := s["name"].(string); ok {
			got[strings.ToLower(n)] = true
		}
	}
	missing := []string{}
	for _, want := range perUser {
		if !got[strings.ToLower(want)] {
			missing = append(missing, want)
		}
	}
	if len(missing) > 0 {
		t.Errorf("ПО из пользовательских веток не попало в инвентарь: %v", missing)
	}
	t.Logf("всего программ: %d, из них per-user: %d", len(sw), len(perUser))
}

// perUserSoftwareNames читает пользовательские Uninstall-ветки напрямую, минуя
// collectSoftware: тест должен сверяться с независимым источником, иначе он
// проверял бы код сам собой.
func perUserSoftwareNames(t *testing.T) []string {
	t.Helper()
	var names []string
	for _, h := range userHives() {
		for _, p := range []string{
			`\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
			`\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
		} {
			k, err := registry.OpenKey(registry.USERS, h.SID+p, registry.READ)
			if err != nil {
				continue
			}
			subs, _ := k.ReadSubKeyNames(-1)
			for _, s := range subs {
				sk, err := registry.OpenKey(registry.USERS, h.SID+p+`\`+s, registry.READ)
				if err != nil {
					continue
				}
				name, _, _ := sk.GetStringValue("DisplayName")
				sysComp, _, _ := sk.GetIntegerValue("SystemComponent")
				sk.Close()
				if name != "" && sysComp != 1 {
					names = append(names, name)
				}
			}
			k.Close()
		}
	}
	return names
}
