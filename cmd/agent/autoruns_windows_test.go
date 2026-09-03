//go:build windows

package main

import (
	"testing"

	"golang.org/x/sys/windows/registry"
)

// Проверяет, что сбор автозагрузки работает на реальной системе и заполняет поля.
func TestCollectAutorunsReal(t *testing.T) {
	ar := collectAutoruns()
	t.Logf("найдено точек автозагрузки: %d", len(ar))
	for _, e := range ar {
		loc, _ := e["location"].(string)
		name, _ := e["name"].(string)
		if loc == "" || name == "" {
			t.Fatalf("запись с пустым location/name: %+v", e)
		}
		if _, ok := e["command"]; !ok {
			t.Fatalf("нет поля command: %+v", e)
		}
	}
}

// Автозапуск сотрудника должен попадать в инвентарь. Пока читались только HKLM
// и HKCU агента (то есть профиль SYSTEM), Telegram и Discord в автозагрузке
// оставались невидимыми — а именно они администратору и интересны.
func TestCollectAutorunsIncludesUserProfiles(t *testing.T) {
	hives := userHives()
	if len(hives) == 0 {
		t.Skip("нет загруженных пользовательских кустов")
	}
	ar := collectAutoruns()
	if len(ar) == 0 {
		t.Fatal("автозагрузка пуста")
	}

	// то, что реально прописано в кустах пользователей — читаем напрямую
	want := map[string]bool{}
	for _, h := range hives {
		for _, p := range []string{
			`\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
			`\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
		} {
			k, err := registry.OpenKey(registry.USERS, h.SID+p, registry.READ)
			if err != nil {
				continue
			}
			names, _ := k.ReadValueNames(-1)
			for _, n := range names {
				if v, _, err := k.GetStringValue(n); err == nil && !(n == "" && v == "") {
					want[n] = true
				}
			}
			k.Close()
		}
	}
	if len(want) == 0 {
		t.Skip("у пользователей ничего не прописано в автозапуске")
	}

	got := map[string]bool{}
	for _, a := range ar {
		if n, ok := a["name"].(string); ok {
			got[n] = true
		}
	}
	for n := range want {
		if !got[n] {
			t.Errorf("запись автозапуска %q не попала в инвентарь", n)
		}
	}
	t.Logf("всего записей: %d, из них пользовательских: %d", len(ar), len(want))
}
