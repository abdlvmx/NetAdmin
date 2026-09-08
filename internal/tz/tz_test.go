package tz

import (
	"os"
	"strings"
	"testing"
	"time"
)

// Время в базе — UTC, и весь показ держится на этом. Ошибка здесь тихая: метки
// выглядят обычно, просто относятся не к тому часу, и заметить это можно
// только зная, который час на самом деле.

// withZone временно ставит зону показа.
func withZone(t *testing.T, name string) {
	t.Helper()
	prev := Loc()
	if err := Set(name); err != nil {
		t.Fatalf("зона %q: %v", name, err)
	}
	t.Cleanup(func() { current.Store(prev) })
}

// Одна и та же отметка в базе показывается по-разному в разных зонах — ровно
// это и было сломано, пока зона была прибита к московской.
func TestSameInstantInDifferentZones(t *testing.T) {
	const utc = "2026-06-02 09:00:00" // полдень в Москве
	cases := map[string]string{
		"Europe/Kaliningrad": "11:00",
		"Europe/Moscow":      "12:00",
		"Asia/Yekaterinburg": "14:00",
		"Asia/Novosibirsk":   "16:00",
		"Asia/Kamchatka":     "21:00",
	}
	for zone, want := range cases {
		t.Run(zone, func(t *testing.T) {
			withZone(t, zone)
			if got := Time(utc); got != want {
				t.Errorf("%s: %q, ожидалось %q", zone, got, want)
			}
		})
	}
}

// Разбираются все три вида отметок, которыми пользуется база, и все три — как
// UTC. Строку, которую разобрать не удалось, отдаём как есть: показать сырое
// значение честнее, чем выдумать время.
func TestParseFormats(t *testing.T) {
	withZone(t, "Europe/Moscow")
	for _, in := range []string{
		"2026-06-02 09:00:00",
		"2026-06-02T09:00:00Z",
		"2026-06-02 09:00",
	} {
		if got := Time(in); got != "12:00" {
			t.Errorf("%q → %q, ожидалось 12:00", in, got)
		}
	}
	if got := DateTime("не время"); got != "не время" {
		t.Errorf("неразобранное изменено: %q", got)
	}
	if got := Full(""); got != "" {
		t.Errorf("пустая строка изменена: %q", got)
	}
}

func TestDateTimeAndFull(t *testing.T) {
	withZone(t, "Asia/Yekaterinburg")
	if got := DateTime("2026-06-02 09:00:00"); got != "02.06 14:00" {
		t.Errorf("DateTime = %q", got)
	}
	if got := Full("2026-06-02 09:00:00"); got != "2026-06-02 14:00:00" {
		t.Errorf("Full = %q", got)
	}
}

// Пустое имя возвращает к зоне самого сервера — это же и значение по умолчанию.
func TestSetEmptyReturnsToLocal(t *testing.T) {
	withZone(t, "Asia/Magadan")
	if err := Set(""); err != nil {
		t.Fatalf("сброс зоны: %v", err)
	}
	if Loc() != time.Local {
		t.Errorf("после сброса зона %v, ожидалась зона сервера", Loc())
	}
}

// Опечатка в имени зоны не должна молча оставлять чужое время.
func TestSetRejectsUnknownZone(t *testing.T) {
	withZone(t, "Europe/Moscow")
	before := Loc()
	err := Set("Asia/Ekaterinburg") // на одну букву мимо
	if err == nil {
		t.Fatal("неизвестная зона принята")
	}
	if !strings.Contains(err.Error(), "Asia/Ekaterinburg") {
		t.Errorf("в сообщении нет самого имени: %v", err)
	}
	if Loc() != before {
		t.Error("после отказа зона всё-таки сменилась")
	}
}

// Пояса из списка настроек обязаны существовать: список набран руками, и
// опечатка в нём означала бы пункт, который нельзя выбрать.
func TestZonesAreLoadable(t *testing.T) {
	if len(Zones) < 10 {
		t.Fatalf("в списке всего %d поясов — похоже, он потерялся", len(Zones))
	}
	seen := map[string]bool{}
	for _, z := range Zones {
		if _, err := time.LoadLocation(z.Name); err != nil {
			t.Errorf("%s (%s): %v", z.Name, z.Title, err)
		}
		if seen[z.Name] {
			t.Errorf("%s в списке дважды", z.Name)
		}
		seen[z.Name] = true
		if ZoneOffset(z.Name) == "" {
			t.Errorf("%s: смещение не посчиталось", z.Name)
		}
	}
}

// База часовых поясов должна лежать внутри бинарника.
//
// Проверка идёт по исходнику, а не по вызову LoadLocation: тесты гоняются там,
// где установлен Go, и зоны находятся в его каталоге даже без импорта. Сломать
// это можно только у пользователя — на машине без Go, где своей копии базы у
// Windows нет и выбор пояса откажет молча, откатившись к зоне сервера.
func TestTZDataIsEmbedded(t *testing.T) {
	src, err := os.ReadFile("tz.go")
	if err != nil {
		t.Fatalf("чтение tz.go: %v", err)
	}
	if !strings.Contains(string(src), `_ "time/tzdata"`) {
		t.Error(`в internal/tz пропал импорт _ "time/tzdata" — на машине без Go ` +
			"выбор часового пояса перестанет работать, и заметить это здесь будет нечем")
	}
}

func TestOffsetFormat(t *testing.T) {
	cases := map[int]string{
		0:                "UTC+0",
		3 * 3600:         "UTC+3",
		5*3600 + 1800:    "UTC+5:30",
		-3 * 3600:        "UTC-3",
		-(3*3600 + 1800): "UTC-3:30",
	}
	for sec, want := range cases {
		if got := offsetOf(sec); got != want {
			t.Errorf("offsetOf(%d) = %q, ожидалось %q", sec, got, want)
		}
	}
}
