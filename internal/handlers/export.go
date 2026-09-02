package handlers

import (
	"encoding/csv"
	"net/http"
	"strconv"

	"netadmin/internal/auth"
)

// writeCSV отдаёт CSV с UTF-8 BOM и разделителем ';' (корректно в русском Excel).
func writeCSV(w http.ResponseWriter, filename string, header []string, rows [][]string) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+filename+"\"")
	_, _ = w.Write([]byte{0xEF, 0xBB, 0xBF}) // BOM
	cw := csv.NewWriter(w)
	cw.Comma = ';'
	_ = cw.Write(header)
	for _, r := range rows {
		safe := make([]string, len(r))
		for i, v := range r {
			safe[i] = csvSafe(v)
		}
		_ = cw.Write(safe)
	}
	cw.Flush()
}

// csvSafe гасит инъекцию формул в табличных процессорах. Excel и LibreOffice
// трактуют значение ячейки как формулу, если оно начинается с =, +, -, @ или
// управляющего символа (Tab/CR). Имена хостов и ПО приходят от агента, а имя
// компьютера на управляемой машине можно задать вида `=cmd|'/c calc'!A1` — и
// оно выполнится на машине того, кто откроет экспорт. Ведущий апостроф
// заставляет процессор считать ячейку текстом; на само значение он не влияет.
func csvSafe(v string) string {
	if v == "" {
		return v
	}
	switch v[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + v
	}
	return v
}

func statusRU(s string) string {
	switch s {
	case "online":
		return "онлайн"
	case "offline":
		return "оффлайн"
	default:
		return "неизвестно"
	}
}

// ExportDevices — GET /devices/export.
func (a *App) ExportDevices(w http.ResponseWriter, r *http.Request) {
	if auth.CurrentUser(a.DB, r) == nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	var rows [][]string
	for _, d := range a.listDevices() {
		owner := d.EmployeeName
		if owner == "" {
			owner = d.OwnerName
		}
		rows = append(rows, []string{
			d.Hostname, d.IP, d.MAC, d.OSType, d.DeviceType, d.Manufacturer, d.Model,
			d.SerialNumber, d.Location, owner, statusRU(d.Status), d.LastSeen,
		})
	}
	writeCSV(w, "devices.csv",
		[]string{"Хост", "IP", "MAC", "ОС", "Тип", "Производитель", "Модель",
			"Серийный №", "Расположение", "Владелец", "Статус", "Последний онлайн"},
		rows)
}

// ExportEmployees — GET /employees/export.
func (a *App) ExportEmployees(w http.ResponseWriter, r *http.Request) {
	if auth.CurrentUser(a.DB, r) == nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	var rows [][]string
	for _, e := range a.listEmployeesFull() {
		active := "отключён"
		if e.IsActive == 1 {
			active = "активен"
		}
		rows = append(rows, []string{
			e.FullName, e.Position, e.Email, e.Phone, e.DepartmentName,
			strconv.Itoa(e.DevicesCount), active,
		})
	}
	writeCSV(w, "employees.csv",
		[]string{"ФИО", "Должность", "Email", "Телефон", "Отдел", "Устройств", "Статус"},
		rows)
}
