//go:build windows

package main

import "golang.org/x/sys/windows/registry"

// collectSoftware читает установленное ПО из реестра Windows (Uninstall-ветки).
func collectSoftware() []map[string]any {
	paths := []struct {
		root registry.Key
		path string
	}{
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`},
		{registry.LOCAL_MACHINE, `SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall`},
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
