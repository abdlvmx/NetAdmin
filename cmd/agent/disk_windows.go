//go:build windows

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
)

// collectDisks читает здоровье физических дисков (SMART). HealthStatus/MediaType/Size
// доступны через Get-PhysicalDisk без прав администратора; счётчики надёжности
// (температура, наработка, износ SSD, ошибки чтения) — через Get-StorageReliabilityCounter
// (могут требовать прав; при недоступности поля остаются нулевыми). Это мониторинг
// состояния оборудования, не средство защиты информации.
func collectDisks() []map[string]any {
	const ps = `Get-PhysicalDisk -ErrorAction SilentlyContinue | ForEach-Object {
  $d=$_; $r=$null
  try { $r = $d | Get-StorageReliabilityCounter -ErrorAction Stop } catch {}
  [pscustomobject]@{
    model="$($d.FriendlyName)";
    serial="$($d.SerialNumber)".Trim();
    size_gb=[int]($d.Size/1GB);
    media="$($d.MediaType)";
    health="$($d.HealthStatus)";
    temp=[int]$r.Temperature;
    poh=[int]$r.PowerOnHours;
    wear=[int]$r.Wear;
    read_err=[int]$r.ReadErrorsTotal
  } | ConvertTo-Json -Compress
}`
	data, ok := runPS(ps)
	if !ok {
		return nil
	}
	var disks []map[string]any
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var d struct {
			Model   string `json:"model"`
			Serial  string `json:"serial"`
			SizeGB  int    `json:"size_gb"`
			Media   string `json:"media"`
			Health  string `json:"health"`
			Temp    int    `json:"temp"`
			POH     int    `json:"poh"`
			Wear    int    `json:"wear"`
			ReadErr int    `json:"read_err"`
		}
		if json.Unmarshal([]byte(line), &d) != nil {
			continue
		}
		if d.Model == "" && d.Serial == "" {
			continue
		}
		disks = append(disks, map[string]any{
			"model":          d.Model,
			"serial":         d.Serial,
			"size_gb":        d.SizeGB,
			"media_type":     normalizeMedia(d.Media),
			"health":         d.Health,
			"temperature":    d.Temp,
			"power_on_hours": d.POH,
			"wear_pct":       d.Wear,
			"read_errors":    d.ReadErr,
			"predict_fail":   smartPredictsFail(d.Health),
		})
	}
	return disks
}

// smartPredictsFail — SMART предсказывает отказ только при явно неисправном
// состоянии. «Warning» означает деградацию, а не отказ.
//
// Раньше отказом считалось всё, кроме «Healthy». Из-за этого диск в состоянии
// Warning приезжал на сервер как предсказанный отказ: поднимался критический
// инцидент и уходило письмо, а ветка Warning в оценке на сервере становилась
// недостижимой. Регистр не учитываем — значение приходит строкой от PowerShell.
func smartPredictsFail(health string) bool {
	switch strings.ToLower(strings.TrimSpace(health)) {
	case "unhealthy", "failed", "fail":
		return true
	}
	return false
}

// normalizeMedia приводит MediaType от Get-PhysicalDisk к читаемому виду.
func normalizeMedia(m string) string {
	switch strings.ToLower(strings.TrimSpace(m)) {
	case "ssd", "4":
		return "SSD"
	case "hdd", "3":
		return "HDD"
	case "scm", "5":
		return "SCM"
	case "", "0", "unspecified":
		return ""
	default:
		return m
	}
}
