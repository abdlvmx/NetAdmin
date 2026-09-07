//go:build windows

package main

import "golang.org/x/sys/windows/registry"

// collectSoftware читает установленное ПО из реестра Windows (Uninstall-ветки).
func collectSoftware() []map[string]any {
	type spot struct {
		root registry.Key
		path string
	}
	paths := []spot{
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`},
		{registry.LOCAL_MACHINE, `SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall`},
		// на случай запуска не от SYSTEM (ручной запуск, отладка)
		{registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`},
	}
	// ПО, установленное «только для меня», лежит в кусте пользователя, а не в
	// HKLM. Агент работает от SYSTEM, поэтому его собственный HKCU пуст —
	// пользовательские ветки ищем в профилях из HKEY_USERS.
	for _, h := range userHives() {
		paths = append(paths,
			spot{registry.USERS, h.SID + `\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`},
			spot{registry.USERS, h.SID + `\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall`},
		)
	}
	seen := map[string]bool{}
	var out []map[string]any
	for _, p := range paths {
		k, err := registry.OpenKey(p.root, p.path, registry.READ)
		if err != nil {
			continue
		}
		subs, _ := k.ReadSubKeyNames(-1)
		for _, s := range subs {
			sk, err := registry.OpenKey(p.root, p.path+`\`+s, registry.READ)
			if err != nil {
				continue
			}
			name, _, _ := sk.GetStringValue("DisplayName")
			ver, _, _ := sk.GetStringValue("DisplayVersion")
			date, _, _ := sk.GetStringValue("InstallDate")
			sysComp, _, _ := sk.GetIntegerValue("SystemComponent")
			sk.Close()
			if name == "" || sysComp == 1 || seen[name] {
				continue
			}
			seen[name] = true
			out = append(out, map[string]any{"name": name, "version": ver, "install_date": date})
		}
		k.Close()
	}
	return out
}
