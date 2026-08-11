//go:build windows

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
)

// collectScheduledTasks читает задачи планировщика Windows (Get-ScheduledTask —
// доступно без прав администратора). Действия (Execute+Arguments) склеиваются в
// строку, чтобы ловить перенацеливание задачи на запуск вредоноса.
func collectScheduledTasks() []map[string]any {
	const ps = `Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object {
  $act = ($_.Actions | ForEach-Object { if ($_.Execute) { ($_.Execute + ' ' + $_.Arguments).Trim() } }) -join '; '
  [pscustomobject]@{ name=$_.TaskName; path=$_.TaskPath; action=$act; state=[string]$_.State } | ConvertTo-Json -Compress }`
	data, ok := runPS(ps)
	if !ok {
		return nil
	}
	var tasks []map[string]any
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var t struct {
			Name   string `json:"name"`
			Path   string `json:"path"`
			Action string `json:"action"`
			State  string `json:"state"`
		}
		if json.Unmarshal([]byte(line), &t) != nil || t.Name == "" {
			continue
		}
		tasks = append(tasks, map[string]any{
			"name": t.Name, "path": t.Path, "action": t.Action, "state": t.State,
		})
	}
	return tasks
}
