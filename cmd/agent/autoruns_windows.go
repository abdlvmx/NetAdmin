//go:build windows

package main

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows/registry"
)

// collectAutoruns собирает точки автозапуска: ключи реестра Run/RunOnce
// (HKLM/HKCU + Wow6432Node) и ярлыки в папках автозагрузки. Не требует админа
// для HKCU и пользовательской Startup; HKLM-ветки читаются при наличии прав.
func collectAutoruns() []map[string]any {
	var out []map[string]any

	regSpots := []struct {
		root        registry.Key
		path, label string
	}{
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, `HKLM\Run`},
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, `HKLM\RunOnce`},
		{registry.LOCAL_MACHINE, `SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`, `HKLM\Run (Wow64)`},
		{registry.LOCAL_MACHINE, `SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce`, `HKLM\RunOnce (Wow64)`},
		{registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, `HKCU\Run`},
		{registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, `HKCU\RunOnce`},
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
			out = append(out, map[string]any{"location": s.label, "name": n, "command": val})
		}
		k.Close()
	}

	startups := []struct {
		dir, label string
	}{
		{filepath.Join(os.Getenv("ProgramData"), `Microsoft\Windows\Start Menu\Programs\Startup`), "Startup (все)"},
		{filepath.Join(os.Getenv("APPDATA"), `Microsoft\Windows\Start Menu\Programs\Startup`), "Startup (пользователь)"},
	}
	for _, s := range startups {
		entries, err := os.ReadDir(s.dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || e.Name() == "desktop.ini" {
				continue
			}
			out = append(out, map[string]any{
				"location": s.label, "name": e.Name(), "command": filepath.Join(s.dir, e.Name()),
			})
		}
	}
	return out
}
