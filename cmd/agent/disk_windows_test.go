//go:build windows

package main

import "testing"

// TestCollectDisksReal — реальный сбор SMART на текущей Windows-машине.
// Проверяет, что PowerShell-сборщик возвращает хотя бы один диск с моделью.
func TestCollectDisksReal(t *testing.T) {
	disks := collectDisks()
	if len(disks) == 0 {
		t.Skip("дисков не обнаружено (нет Get-PhysicalDisk или прав) — пропуск")
	}
	withModel := 0
	for _, d := range disks {
		if m, _ := d["model"].(string); m != "" {
			withModel++
		}
		t.Logf("диск: %v %v %v ГБ health=%v wear=%v temp=%v",
			d["model"], d["media_type"], d["size_gb"], d["health"], d["wear_pct"], d["temperature"])
	}
	if withModel == 0 {
		t.Fatalf("ни у одного диска нет модели — вероятно, сломан парсинг вывода PowerShell")
	}
}
