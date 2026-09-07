//go:build windows

package main

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows/registry"
)

// collectAutoruns собирает точки автозапуска: ключи реестра Run/RunOnce
// (HKLM + кусты пользователей, включая Wow6432Node) и ярлыки в папках
// автозагрузки — общей и каждого профиля.
func collectAutoruns() []map[string]any {
	var out []map[string]any

	type regSpot struct {
		root        registry.Key
		path, label string
	}
	regSpots := []regSpot{
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, `HKLM\Run`},
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, `HKLM\RunOnce`},
		{registry.LOCAL_MACHINE, `SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`, `HKLM\Run (Wow64)`},
		{registry.LOCAL_MACHINE, `SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce`, `HKLM\RunOnce (Wow64)`},
	}
	// Автозапуск сотрудника прописывается в его кусте, а не в HKLM. От SYSTEM
	// свой HKCU пуст, поэтому идём по профилям: именно здесь видны Telegram,
	// Discord и торрент-клиенты, ради которых раздел и нужен. В метке указываем
	// имя профиля — администратору важно, у кого именно это в автозапуске.
	hives := userHives()
	for _, h := range hives {
		regSpots = append(regSpots,
			regSpot{registry.USERS, h.SID + `\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
				`Run (` + h.Name + `)`},
			regSpot{registry.USERS, h.SID + `\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
				`RunOnce (` + h.Name + `)`},
			regSpot{registry.USERS, h.SID + `\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`,
				`Run Wow64 (` + h.Name + `)`},
		)
	}
	// Свой HKCU — последним и только как запасной путь: при обычной работе от
	// SYSTEM он пуст, а при ручном запуске повторяет куст того же пользователя,
	// уже прочитанный выше. Дедупликация ниже оставит запись с именем профиля.
	regSpots = append(regSpots,
		regSpot{registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, `HKCU\Run`},
		regSpot{registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, `HKCU\RunOnce`},
	)

	// Одна и та же точка автозапуска не должна попадать в отчёт дважды.
	// Ключ — имя и команда, разделённые переводом строки: в них он не
	// встречается, поэтому склейки разных пар не выйдет.
	seen := map[string]bool{}
	dup := func(name, cmd string) bool {
		key := name + "\n" + cmd
		if seen[key] {
			return true
		}
		seen[key] = true
		return false
	}

	for _, s := range regSpots {
		k, err := registry.OpenKey(s.root, s.path, registry.READ)
		if err != nil {
			continue
		}
		names, _ := k.ReadValueNames(-1)
		for _, n := range names {
			val, _, err := k.GetStringValue(n)
			if err != nil || (n == "" && val == "") {
				continue
			}
			if dup(n, val) {
				continue
			}
			out = append(out, map[string]any{"location": s.label, "name": n, "command": val})
		}
		k.Close()
	}

	type startupSpot struct{ dir, label string }
	startups := []startupSpot{
		{filepath.Join(os.Getenv("ProgramData"), `Microsoft\Windows\Start Menu\Programs\Startup`), "Startup (все)"},
	}
	// Папка «Автозагрузка» каждого профиля: ярлык там запускает программу так
	// же, как ключ в реестре, а от SYSTEM переменная APPDATA указывает на
	// профиль службы, а не сотрудника.
	for _, h := range hives {
		if h.Profile == "" {
			continue
		}
		startups = append(startups, startupSpot{
			dir:   filepath.Join(h.Profile, `AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`),
			label: "Startup (" + h.Name + ")",
		})
	}
	// Запасной путь для запуска не от SYSTEM — как и с HKCU, идёт последним.
	startups = append(startups, startupSpot{
		dir:   filepath.Join(os.Getenv("APPDATA"), `Microsoft\Windows\Start Menu\Programs\Startup`),
		label: "Startup (пользователь)",
	})

	for _, s := range startups {
		entries, err := os.ReadDir(s.dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || e.Name() == "desktop.ini" {
				continue
			}
			cmd := filepath.Join(s.dir, e.Name())
			if dup(e.Name(), cmd) {
				continue
			}
			out = append(out, map[string]any{
				"location": s.label, "name": e.Name(), "command": cmd,
			})
		}
	}
	return out
}
