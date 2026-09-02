package handlers

import (
	"log"
	"net/http"
	"strconv"

	"netadmin/internal/auth"
	"netadmin/internal/tz"
)

// recordDeviceChange фиксирует изменение характеристики устройства (Asset Change Tracking).
func (a *App) recordDeviceChange(deviceID int64, field, oldV, newV string) {
	a.DB.Exec(`INSERT INTO device_changes (device_id, field, old_value, new_value)
		VALUES (?,?,?,?)`, deviceID, field, oldV, newV)
}

// trackHardwareChanges сравнивает новые характеристики с сохранёнными и пишет историю.
// Изменение фиксируется только если прежнее значение известно (не на первом сборе).
func (a *App) trackHardwareChanges(deviceID int64, cpuModel, osVer string, ramGB, diskGB int) {
	var curCPU, curOS string
	var curRAM, curDisk int
	if a.DB.QueryRow(`SELECT COALESCE(cpu_model,''), COALESCE(os_version,''),
		COALESCE(ram_total_gb,0), COALESCE(disk_total_gb,0) FROM devices WHERE id=?`,
		deviceID).Scan(&curCPU, &curOS, &curRAM, &curDisk) != nil {
		return
	}
	if cpuModel != "" && curCPU != "" && cpuModel != curCPU {
		a.recordDeviceChange(deviceID, "Процессор", curCPU, cpuModel)
	}
	if ramGB > 0 && curRAM > 0 && ramGB != curRAM {
		a.recordDeviceChange(deviceID, "Оперативная память",
			strconv.Itoa(curRAM)+" ГБ", strconv.Itoa(ramGB)+" ГБ")
	}
	if diskGB > 0 && curDisk > 0 && diskGB != curDisk {
		a.recordDeviceChange(deviceID, "Объём диска",
			strconv.Itoa(curDisk)+" ГБ", strconv.Itoa(diskGB)+" ГБ")
	}
	if osVer != "" && curOS != "" && osVer != curOS {
		a.recordDeviceChange(deviceID, "Операционная система", curOS, osVer)
	}
}

// DeviceChanges — GET /api/devices/{id}/changes : история изменений устройства.
func (a *App) DeviceChanges(w http.ResponseWriter, r *http.Request) {
	if auth.CurrentUser(a.DB, r) == nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	rows, err := a.DB.Query(`SELECT ts, COALESCE(field,''), COALESCE(old_value,''), COALESCE(new_value,'')
		FROM device_changes WHERE device_id=? ORDER BY ts DESC LIMIT 200`, id)
	type item struct {
		Ts    string `json:"ts"`
		Field string `json:"field"`
		Old   string `json:"old"`
		New   string `json:"new"`
	}
	items := []item{}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var it item
			var ts string
			if rows.Scan(&ts, &it.Field, &it.Old, &it.New) == nil {
				it.Ts = tz.DateTime(ts)
				items = append(items, it)
			}
		}
		if err := rows.Err(); err != nil {
			log.Printf("DeviceChanges: %v", err)
		}
	}
	writeJSON(w, map[string]any{"changes": items})
}
