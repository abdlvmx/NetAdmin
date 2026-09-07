package handlers

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"netadmin/internal/auth"
)

// powerLabels — человекочитаемые подписи действий питания.
var powerLabels = map[string]string{
	"reboot":   "Перезагрузка",
	"shutdown": "Выключение",
	"logoff":   "Выход из сессии",
	"wol":      "Включение (Wake-on-LAN)",
}

// DevicePower — POST /devices/{id}/power : удалённое питание устройства (CanWrite).
// reboot/shutdown/logoff ставятся в очередь агенту; wol шлётся сразу magic-пакетом.
func (a *App) DevicePower(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if !user.CanWrite() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	action := strings.TrimSpace(r.FormValue("action"))
	label, ok := powerLabels[action]
	if !ok {
		writeJSON(w, map[string]any{"ok": false, "error": "неизвестное действие"})
		return
	}

	var hostname, mac, token string
	var hasToken bool
	if a.DB.QueryRow(`SELECT COALESCE(hostname,''), COALESCE(mac_address,''), COALESCE(agent_token,'')
		FROM devices WHERE id=?`, id).Scan(&hostname, &mac, &token) != nil {
		writeJSON(w, map[string]any{"ok": false, "error": "устройство не найдено"})
		return
	}
	hasToken = token != ""

	if action == "wol" {
		if mac == "" {
			writeJSON(w, map[string]any{"ok": false, "error": "у устройства не задан MAC-адрес"})
			return
		}
		if err := sendWOL(mac); err != nil {
			writeJSON(w, map[string]any{"ok": false, "error": "ошибка отправки: " + err.Error()})
			return
		}
		auth.LogAction(a.DB, user.ID, "device_wol", hostname, mac)
		writeJSON(w, map[string]any{"ok": true, "message": "Magic-пакет отправлен на " + mac})
		return
	}

	// reboot/shutdown/logoff — задача агенту
	if !hasToken {
		writeJSON(w, map[string]any{"ok": false, "error": "на устройстве не установлен агент — действие невозможно"})
		return
	}
	if _, err := a.enqueueTask(id, action, "", label, user.ID); err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": "не удалось поставить задачу"})
		return
	}
	auth.LogAction(a.DB, user.ID, "device_power", hostname, action)
	writeJSON(w, map[string]any{"ok": true, "message": label + ": задача поставлена, агент выполнит в течение минуты"})
}

// DeviceSelfCheck — POST /devices/{id}/selfcheck : попросить агента прогнать
// самодиагностику и прислать отчёт (CanWrite).
//
// Отвечает на самый частый вопрос про машину, которая числится онлайн, а данных
// от неё нет: тот же agent.exe -check, который иначе пришлось бы запускать
// руками на месте. Отчёт приходит во вкладку «Действия».
//
// Работает, пока агент забирает задачи. Машине, которая до сервера не
// достучалась вовсе, это не поможет — она и задачу не заберёт; такую видно по
// времени последнего heartbeat.
func (a *App) DeviceSelfCheck(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if !user.CanWrite() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)

	var hostname, token string
	if a.DB.QueryRow(`SELECT COALESCE(hostname,''), COALESCE(agent_token,'')
		FROM devices WHERE id=?`, id).Scan(&hostname, &token) != nil {
		writeJSON(w, map[string]any{"ok": false, "error": "устройство не найдено"})
		return
	}
	if token == "" {
		writeJSON(w, map[string]any{"ok": false,
			"error": "на устройстве не установлен агент — диагностировать нечего"})
		return
	}
	if _, err := a.enqueueTask(id, "check", "", "Самодиагностика агента", user.ID); err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": "не удалось поставить задачу"})
		return
	}
	auth.LogAction(a.DB, user.ID, "device_selfcheck", hostname, "")
	writeJSON(w, map[string]any{"ok": true,
		"message": "Самодиагностика запрошена: отчёт появится во вкладке «Действия» в течение минуты"})
}

var macClean = regexp.MustCompile(`[^0-9a-fA-F]`)

// buildMagicPacket собирает Wake-on-LAN magic-пакет: 6×0xFF + 16×MAC (102 байта).
func buildMagicPacket(mac string) ([]byte, error) {
	hexStr := macClean.ReplaceAllString(mac, "")
	if len(hexStr) != 12 {
		return nil, fmt.Errorf("некорректный MAC")
	}
	hw, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, err
	}
	packet := make([]byte, 0, 102)
	for i := 0; i < 6; i++ {
		packet = append(packet, 0xFF)
	}
	for i := 0; i < 16; i++ {
		packet = append(packet, hw...)
	}
	return packet, nil
}

// sendWOL шлёт magic-пакет Wake-on-LAN на широковещательный адрес (UDP 9).
func sendWOL(mac string) error {
	packet, err := buildMagicPacket(mac)
	if err != nil {
		return err
	}
	conn, err := net.Dial("udp", "255.255.255.255:9")
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write(packet)
	return err
}

// DeviceRDP — GET /devices/{id}/rdp : выдаёт .rdp-файл для подключения к рабочему столу.
func (a *App) DeviceRDP(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if !user.CanWrite() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var hostname, ip string
	if a.DB.QueryRow("SELECT COALESCE(hostname,''), COALESCE(ip_address,'') FROM devices WHERE id=?", id).
		Scan(&hostname, &ip) != nil {
		http.NotFound(w, r)
		return
	}
	target := ip
	if target == "" {
		target = hostname
	}
	if target == "" {
		http.Error(w, "у устройства нет IP/имени", http.StatusBadRequest)
		return
	}
	auth.LogAction(a.DB, user.ID, "device_rdp", hostname, target)

	fname := hostname
	if fname == "" {
		fname = target
	}
	// hostname и ip попадают сюда из карточки устройства, а имя приходит от
	// агента при регистрации. Перевод строки внутри значения позволил бы
	// дописать в файл произвольные настройки RDP (например, alternate shell)
	// и выполнить код на машине администратора, открывшего файл.
	rdp := "full address:s:" + rdpValue(target) + "\r\n" +
		"prompt for credentials:i:1\r\n" +
		"administrative session:i:0\r\n" +
		"screen mode id:i:2\r\n"
	w.Header().Set("Content-Type", "application/x-rdp")
	w.Header().Set("Content-Disposition", `attachment; filename="`+sanitizeFilename(fname)+`.rdp"`)
	_, _ = w.Write([]byte(rdp))
}

// rdpValue готовит значение для .rdp-файла: управляющие символы и переводы
// строк вырезаются, иначе значение «разрывает» файл и дописывает свои строки.
func rdpValue(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

// sanitizeFilename убирает из имени файла небезопасные символы.
func sanitizeFilename(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1 // управляющие символы в заголовке Content-Disposition
		}
		if strings.ContainsRune(`\/:*?"<>|`, r) {
			return '_'
		}
		return r
	}, s)
	if s == "" {
		return "device"
	}
	return s
}
