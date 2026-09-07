// Package demo — правдоподобное наполнение базы вымышленными данными.
//
// Используется дважды: инструментом разработчика cmd/seed и режимом
// `netadmin -demo`, который поднимает сервер на временной базе, чтобы продукт
// можно было посмотреть до развёртывания. Логика общая намеренно: когда она
// жила только в cmd/seed, демо-режима не было вовсе, а появись он копией —
// две картинки разошлись бы при первом же изменении схемы.
package demo

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"math/rand"
	"strings"
	"time"

	"netadmin/internal/auth"
)

// Учётные данные демо-администратора. Пароль заведомо известен, поэтому
// наполнение допустимо только на пустой или временной базе.
const (
	AdminUser     = "admin"
	AdminPassword = "Parol12345"
)

// Host — одно тестовое устройство. Список общий для наполнения базы и для
// Keepalive, чтобы «живой» статус в демо совпадал с задуманным.
type Host struct {
	Hostname, IP, MAC, OS, Status, Type, Location string
	Employee                                      int
	Agent                                         bool
	Critical                                      bool
}

// Hosts — вымышленный парк небольшой организации.
var Hosts = []Host{
	{"BUH-01", "192.168.1.11", "AA:BB:CC:00:00:01", "Windows", "online", "Рабочая станция", "каб. 201", 1, true, false},
	{"BUH-02", "192.168.1.12", "AA:BB:CC:00:00:02", "Windows", "online", "Рабочая станция", "каб. 201", 2, true, false},
	{"KADR-01", "192.168.1.21", "AA:BB:CC:00:00:03", "Windows", "offline", "Рабочая станция", "каб. 105", 3, true, false},
	{"PROIZV-01", "192.168.1.31", "AA:BB:CC:00:00:04", "Windows", "online", "Рабочая станция", "цех 1", 4, true, false},
	{"SRV-1C", "192.168.1.5", "AA:BB:CC:00:00:05", "Windows", "online", "Сервер", "серверная", 0, true, true},
	{"SRV-FILE", "192.168.1.6", "AA:BB:CC:00:00:06", "Windows", "online", "Сервер", "серверная", 0, true, true},
	{"SW-CORE", "192.168.1.2", "AA:BB:CC:00:00:07", "", "online", "Коммутатор", "серверная", 0, false, true},
	{"PRINTER-BUH", "192.168.1.50", "AA:BB:CC:00:00:08", "", "online", "Принтер", "каб. 201", 0, false, false},
	{"NVR-01", "192.168.1.60", "AA:BB:CC:00:00:09", "", "offline", "Видеорегистратор", "проходная", 0, false, false},
}

// IsEmpty сообщает, что база ещё не использовалась: наполнять чужую базу
// администратором с заведомо известным паролем нельзя.
func IsEmpty(d *sql.DB) (bool, error) {
	var users int
	if err := d.QueryRow("SELECT COUNT(*) FROM users").Scan(&users); err != nil {
		return false, err
	}
	return users == 0, nil
}

// seeder копит первую ошибку и пропускает остальные запросы: молчаливая
// ошибка вставки хуже остановки — опечатка в имени колонки просто оставляет
// раздел пустым, и это выглядит как недоделанная функция, а не как баг.
type seeder struct {
	d   *sql.DB
	err error
}

func (s *seeder) exec(query string, args ...any) sql.Result {
	if s.err != nil {
		return nil
	}
	res, err := s.d.Exec(query, args...)
	if err != nil {
		s.err = fmt.Errorf("%w\nзапрос: %s", err, strings.TrimSpace(query))
		return nil
	}
	return res
}

func (s *seeder) id(res sql.Result) int64 {
	if res == nil {
		return 0
	}
	id, _ := res.LastInsertId()
	return id
}

// Seed наполняет пустую базу вымышленными данными: пользователи, сотрудники,
// парк устройств с историей метрик, проверки сервисов, заявки, лицензии,
// диски, топология и события.
func Seed(d *sql.DB) error {
	s := &seeder{d: d}

	hash, err := auth.HashPassword(AdminPassword)
	if err != nil {
		return err
	}
	s.exec(`INSERT OR IGNORE INTO users (username, full_name, email, role, password_hash)
		VALUES ('admin','Иванов Иван Иванович','admin@firma.local','admin',?)`, hash)
	s.exec(`INSERT OR IGNORE INTO users (username, full_name, role, password_hash)
		VALUES ('operator','Петров Пётр','user',?)`, hash)
	s.exec(`INSERT OR IGNORE INTO users (username, full_name, role, password_hash)
		VALUES ('viewer','Сидорова Анна','viewer',?)`, hash)

	for _, dep := range []string{"Бухгалтерия", "Отдел кадров", "Производство", "ИТ-отдел"} {
		s.exec(`INSERT OR IGNORE INTO departments (name) VALUES (?)`, dep)
	}
	for _, e := range []struct {
		name, pos string
		dep       int
	}{
		{"Смирнова Ольга Петровна", "Главный бухгалтер", 1},
		{"Кузнецов Андрей Сергеевич", "Бухгалтер", 1},
		{"Попова Мария Ивановна", "Инспектор по кадрам", 2},
		{"Васильев Дмитрий Олегович", "Мастер участка", 3},
		{"Новиков Сергей Павлович", "Системный администратор", 4},
	} {
		s.exec(`INSERT OR IGNORE INTO employees (full_name, position, department_id, email, phone)
			VALUES (?,?,?,?,?)`, e.name, e.pos, e.dep, "user@firma.local", "+7 900 000-00-00")
	}

	for i, h := range Hosts {
		tok := ""
		if h.Agent {
			tok = fmt.Sprintf("TESTTOKEN%02d", i)
		}
		var emp any
		if h.Employee > 0 {
			emp = h.Employee
		}
		res := s.exec(`INSERT OR IGNORE INTO devices
			(hostname, ip_address, mac_address, os_type, status, device_type, location,
			 employee_id, agent_token, critical, last_seen, cpu_usage, ram_usage, disk_usage,
			 cpu_model, ram_total_gb, disk_total_gb, os_version, agent_version, manufacturer)
			VALUES (?,?,?,?,?,?,?,?,?,?, datetime('now'), ?,?,?, ?,?,?,?,?,?)`,
			h.Hostname, h.IP, h.MAC, h.OS, h.Status, h.Type, h.Location, emp, tok, boolInt(h.Critical),
			float64(10+rand.Intn(80)), float64(30+rand.Intn(60)), float64(20+rand.Intn(70)),
			"Intel Core i5-10400", 8, 256, "Windows 10 Pro", "1.1.0", "Hewlett-Packard")
		id := s.id(res)
		if id == 0 {
			continue
		}
		for j := 0; j < 60; j++ {
			s.exec(`INSERT INTO metrics_history (device_id, cpu_usage, ram_usage, disk_usage, ts)
				VALUES (?,?,?,?, datetime('now', ?))`,
				id, float64(10+rand.Intn(80)), float64(30+rand.Intn(60)), float64(20+rand.Intn(70)),
				fmt.Sprintf("-%d minutes", j*20))
		}
		for _, sw := range []string{"7-Zip 24.08", "Google Chrome 130", "1С:Предприятие 8.3", "Adobe Acrobat Reader"} {
			s.exec(`INSERT INTO software (device_id, name, version) VALUES (?,?, '1.0')`, id, sw)
		}
	}

	for _, c := range []struct {
		name, typ, target, status string
		lat                       int
	}{
		{"Сервер 1С", "tcp", "192.168.1.5:1541", "up", 12},
		{"Файловый сервер", "tcp", "192.168.1.6:445", "up", 4},
		{"Контроллер печати", "tcp", "192.168.1.50:9100", "down", 0},
		{"DNS провайдера", "dns", "ya.ru", "up", 28},
	} {
		res := s.exec(`INSERT INTO service_checks (name, type, target, interval_sec, enabled,
			last_status, last_latency_ms, last_check)
			VALUES (?,?,?,120,1,?,?, datetime('now'))`, c.name, c.typ, c.target, c.status, c.lat)
		id := s.id(res)
		for j := 0; j < 300 && id != 0; j++ {
			up := 1
			if c.status == "down" && j < 40 {
				up = 0
			}
			s.exec(`INSERT INTO service_check_history (check_id, up, latency_ms, ts)
				VALUES (?,?,?, datetime('now', ?))`, id, up, c.lat, fmt.Sprintf("-%d minutes", j*15))
		}
	}

	for _, f := range []struct{ pat, cat, note string }{
		{"utorrent", "Торренты", "Торрент-клиент"},
		{"steam", "Игры", "Игровая платформа"},
		{"xmrig", "Майнеры", "Криптомайнер"},
	} {
		s.exec(`INSERT INTO forbidden_software (pattern, category, note) VALUES (?,?,?)`, f.pat, f.cat, f.note)
	}
	s.exec(`INSERT INTO software (device_id, name, version) SELECT id, 'uTorrent', '3.6' FROM devices WHERE hostname='KADR-01'`)
	s.exec(`INSERT INTO software (device_id, name, version) SELECT id, 'Steam', '1.0' FROM devices WHERE hostname='PROIZV-01'`)

	for _, l := range []struct {
		name, vendor string
		seats        int
		cost         float64
	}{
		{"1С:Предприятие", "1С", 10, 180000},
		{"Google Chrome", "Google", 5, 0},
		{"Adobe Acrobat", "Adobe", 2, 45000},
	} {
		s.exec(`INSERT INTO software_licenses (name, vendor, seats_purchased, cost)
			VALUES (?,?,?,?)`, l.name, l.vendor, l.seats, l.cost)
	}

	for _, dk := range []struct {
		host, model, serial, health string
		wear, temp, predict         int
	}{
		{"BUH-01", "Samsung SSD 870 EVO", "S1A2B3C", "ok", 12, 38, 0},
		{"SRV-1C", "Seagate ST2000DM008", "Z9X8Y7", "warning", 71, 52, 0},
		{"SRV-FILE", "WD Blue SN570 1TB", "WD44RT", "critical", 94, 61, 1},
	} {
		s.exec(`INSERT INTO disks (device_id, model, serial, size_gb, media_type,
			health, temperature, power_on_hours, wear_pct, read_errors, predict_fail, updated_at)
			SELECT id, ?, ?, 512, 'SSD', ?, ?, 12000, ?, 0, ?, datetime('now')
			FROM devices WHERE hostname=?`,
			dk.model, dk.serial, dk.health, dk.temp, dk.wear, dk.predict, dk.host)
	}

	for _, tk := range []struct{ code, title, cat, status, who string }{
		{"K7M2QP", "Не печатает принтер в 201 кабинете", "Оборудование", "new", "Смирнова Ольга Петровна"},
		{"R4TX8N", "Не открывается 1С, ошибка базы", "ПО", "in_progress", "Кузнецов Андрей Сергеевич"},
		{"B9YH3W", "Забыл пароль от учётной записи", "Доступ", "resolved", "Попова Мария Ивановна"},
		{"L2QF6K", "Медленно работает компьютер", "Оборудование", "closed", "Васильев Дмитрий Олегович"},
	} {
		s.exec(`INSERT INTO tickets (code, title, description, category, status, priority,
			reporter_name, reporter_email, location)
			VALUES (?,?,?,?,?, 'normal', ?, 'user@firma.local', 'каб. 201')`,
			tk.code, tk.title, "Подробное описание проблемы от сотрудника.", tk.cat, tk.status, tk.who)
	}

	// связи топологии: что к какому порту коммутатора подключено
	for _, l := range []struct{ parent, child, port string }{
		{"SW-CORE", "SRV-1C", "Gi0/1"},
		{"SW-CORE", "SRV-FILE", "Gi0/2"},
		{"SW-CORE", "PRINTER-BUH", "Gi0/8"},
		{"SW-CORE", "BUH-01", "Gi0/11"},
		{"SW-CORE", "BUH-02", "Gi0/12"},
		{"SRV-1C", "PROIZV-01", ""},
	} {
		s.exec(`INSERT INTO topology_links (parent_device_id, child_device_id, port)
			SELECT p.id, c.id, ? FROM devices p, devices c
			WHERE p.hostname=? AND c.hostname=?`, l.port, l.parent, l.child)
	}

	for _, e := range []struct{ host, sev, cat, msg string }{
		{"SRV-1C", "critical", "uptime", "Связь с критичным устройством SRV-1C (192.168.1.5) потеряна!"},
		{"KADR-01", "warning", "software", "Установлено новое ПО: uTorrent"},
		{"192.168.1.99", "warning", "replay", "Отклонён запрос агента: неверная подпись"},
	} {
		s.exec(`INSERT INTO events (hostname, source, event_id, severity, category, message)
			VALUES (?, 'correlation', 0, ?, ?, ?)`, e.host, e.sev, e.cat, e.msg)
	}

	s.exec(`INSERT INTO audit_log (user_id, action, target, detail) VALUES (1,'login','session','192.168.1.100')`)
	s.exec(`INSERT INTO audit_log (user_id, action, target, detail) VALUES (1,'command_run','flushdns','9 устройств')`)

	return s.err
}

// Keepalive возвращает тестовым устройствам их задуманный статус и обновляет
// last_seen, пока не отменён контекст. Без этого демо-база «умирает» через пару
// минут: сервер помечает offline всех, от кого не было heartbeat дольше
// таймаута, а критичные устройства вдобавок пингуются — вымышленные адреса
// не отвечают.
func Keepalive(ctx context.Context, d *sql.DB, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		for _, h := range Hosts {
			if _, err := d.Exec(`UPDATE devices
				SET status=?, last_seen=datetime('now'), down_streak=0, down_since=NULL
				WHERE hostname=?`, h.Status, h.Hostname); err != nil {
				log.Printf("демо-режим, обновление %s: %v", h.Hostname, err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
