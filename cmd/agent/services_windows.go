//go:build windows

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
)

// collectServices читает список служб Windows (Win32_Service через CIM — доступно
// без прав администратора). Возвращает имя, отображаемое имя, тип запуска и путь.
func collectServices() []map[string]any {
	const ps = `Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ name=$_.Name; display=$_.DisplayName; start=$_.StartMode; path=$_.PathName } | ConvertTo-Json -Compress }`
	data, ok := runPS(ps)
	if !ok {
		return nil
	}
	var svcs []map[string]any
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var s struct {
			Name    string `json:"name"`
			Display string `json:"display"`
			Start   string `json:"start"`
			Path    string `json:"path"`
		}
		if json.Unmarshal([]byte(line), &s) != nil || s.Name == "" {
			continue
		}
		svcs = append(svcs, map[string]any{
			"name": s.Name, "display_name": s.Display, "start_type": s.Start, "path": s.Path,
		})
	}
	return svcs
}
