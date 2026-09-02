// Команда seed — наполнение тестовой базы для ручного просмотра интерфейса.
//
// Инструмент разработчика: заполняет пустую базу правдоподобными данными,
// чтобы страницы можно было смотреть не на пустых таблицах. В поставку
// не входит и на рабочей базе не запускается.
package main

import (
	"fmt"
	"log"
	"math/rand"
	"os"

	"netadmin/internal/auth"
	"netadmin/internal/config"
	"netadmin/internal/db"
)

func main() {
	d, err := db.Open(config.DBPath())
	if err != nil {
		log.Fatal(err)
	}
	defer d.Close()
	if err := db.InitSchema(d); err != nil {
		log.Fatal(err)
	}

	// Защита от запуска на рабочей базе: инструмент заводит администратора
	// с заведомо известным паролем.
	if os.Getenv("NETADMIN_SEED_CONFIRM") != "1" {
		log.Fatal("это инструмент разработчика: задайте NETADMIN_SEED_CONFIRM=1 и отдельный NETADMIN_DATA_DIR")
	}
	var users int
	d.QueryRow("SELECT COUNT(*) FROM users").Scan(&users)
	if users > 0 {
		log.Fatal("база не пуста — наполнять её тестовыми данными нельзя")
	}

	hash, _ := auth.HashPassword("Parol12345")
	d.Exec(`INSERT OR IGNORE INTO users (username, full_name, email, role, password_hash)
		VALUES ('admin','Иванов Иван Иванович','admin@firma.local','admin',?)`, hash)
	d.Exec(`INSERT OR IGNORE INTO users (username, full_name, role, password_hash)
		VALUES ('operator','Петров Пётр','user',?)`, hash)
	d.Exec(`INSERT OR IGNORE INTO users (username, full_name, role, password_hash)
		VALUES ('viewer','Сидорова Анна','viewer',?)`, hash)

	for _, dep := range []string{"Бухгалтерия", "Отдел кадров", "Производство", "ИТ-отдел"} {
		d.Exec(`INSERT OR IGNORE INTO departments (name) VALUES (?)`, dep)
	}
	emps := []struct {
		name, pos string
		dep       int
	}{
		{"Смирнова Ольга Петровна", "Главный бухгалтер", 1},
		{"Кузнецов Андрей Сергеевич", "Бухгалтер", 1},
		{"Попова Мария Ивановна", "Инспектор по кадрам", 2},
		{"Васильев Дмитрий Олегович", "Мастер участка", 3},
		{"Новиков Сергей Павлович", "Системный администратор", 4},
	}
	for _, e := range emps {
		d.Exec(`INSERT OR IGNORE INTO employees (full_name, position, department_id, email, phone)
			VALUES (?,?,?,?,?)`, e.name, e.pos, e.dep, "user@firma.local", "+7 900 000-00-00")
	}

	hosts := []struct {
		host, ip, mac, os, status, typ, loc string
		emp                                 int
		agent                               bool
		crit                                bool
	}{
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
	for i, h := range hosts {
		tok := ""
		if h.agent {
			tok = fmt.Sprintf("TESTTOKEN%02d", i)
		}
		var emp any
		if h.emp > 0 {
			emp = h.emp
		}
		res, err := d.Exec(`INSERT OR IGNORE INTO devices
			(hostname, ip_address, mac_address, os_type, status, device_type, location,
			 employee_id, agent_token, critical, last_seen, cpu_usage, ram_usage, disk_usage,
			 cpu_model, ram_total_gb, disk_total_gb, os_version, agent_version, manufacturer)
			VALUES (?,?,?,?,?,?,?,?,?,?, datetime('now'), ?,?,?, ?,?,?,?,?,?)`,
			h.host, h.ip, h.mac, h.os, h.status, h.typ, h.loc, emp, tok, boolInt(h.crit),
			float64(10+rand.Intn(80)), float64(30+rand.Intn(60)), float64(20+rand.Intn(70)),
			"Intel Core i5-10400", 8, 256, "Windows 10 Pro", "1.1.0", "Hewlett-Packard")
		if err != nil {
			continue
		}
		id, _ := res.LastInsertId()
		for j := 0; j < 60; j++ {
			d.Exec(`INSERT INTO metrics_history (device_id, cpu_usage, ram_usage, disk_usage, ts)
				VALUES (?,?,?,?, datetime('now', ?))`,
				id, float64(10+rand.Intn(80)), float64(30+rand.Intn(60)), float64(20+rand.Intn(70)),
				fmt.Sprintf("-%d minutes", j*20))
		}
		for _, sw := range []string{"7-Zip 24.08", "Google Chrome 130", "1С:Предприятие 8.3", "Adobe Acrobat Reader"} {
			d.Exec(`INSERT INTO software (device_id, name, version) VALUES (?,?, '1.0')`, id, sw)
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
		res, err := d.Exec(`INSERT INTO service_checks (name, type, target, interval_sec, enabled,
			last_status, last_latency_ms, last_check)
			VALUES (?,?,?,120,1,?,?, datetime('now'))`, c.name, c.typ, c.target, c.status, c.lat)
		if err != nil {
			log.Fatalf("service_checks: %v", err)
		}
		id, _ := res.LastInsertId()
		for j := 0; j < 300; j++ {
			up := 1
			if c.status == "down" && j < 40 {
				up = 0
			}
			if _, err := d.Exec(`INSERT INTO service_check_history (check_id, up, latency_ms, ts)
				VALUES (?,?,?, datetime('now', ?))`, id, up, c.lat, fmt.Sprintf("-%d minutes", j*15)); err != nil {
				log.Fatalf("history: %v", err)
			}
		}
	}

	for _, f := range []struct{ pat, cat, note string }{
		{"utorrent", "Торренты", "Торрент-клиент"},
		{"steam", "Игры", "Игровая платформа"},
		{"xmrig", "Майнеры", "Криптомайнер"},
	} {
		if _, err := d.Exec(`INSERT INTO forbidden_software (pattern, category, note) VALUES (?,?,?)`,
			f.pat, f.cat, f.note); err != nil {
			log.Fatalf("forbidden: %v", err)
		}
	}
	d.Exec(`INSERT INTO software (device_id, name, version) SELECT id, 'uTorrent', '3.6' FROM devices WHERE hostname='KADR-01'`)
	d.Exec(`INSERT INTO software (device_id, name, version) SELECT id, 'Steam', '1.0' FROM devices WHERE hostname='PROIZV-01'`)

	for _, l := range []struct {
		name, vendor string
		seats        int
		cost         float64
	}{
		{"1С:Предприятие", "1С", 10, 180000},
		{"Google Chrome", "Google", 5, 0},
		{"Adobe Acrobat", "Adobe", 2, 45000},
	} {
		if _, err := d.Exec(`INSERT INTO software_licenses (name, vendor, seats_purchased, cost)
			VALUES (?,?,?,?)`, l.name, l.vendor, l.seats, l.cost); err != nil {
			log.Fatalf("licenses: %v", err)
		}
	}

	for _, dk := range []struct {
		host, model, serial, health string
		wear, temp, predict         int
	}{
		{"BUH-01", "Samsung SSD 870 EVO", "S1A2B3C", "ok", 12, 38, 0},
		{"SRV-1C", "Seagate ST2000DM008", "Z9X8Y7", "warning", 71, 52, 0},
		{"SRV-FILE", "WD Blue SN570 1TB", "WD44RT", "critical", 94, 61, 1},
	} {
		if _, err := d.Exec(`INSERT INTO disks (device_id, model, serial, size_gb, media_type,
			health, temperature, power_on_hours, wear_pct, read_errors, predict_fail, updated_at)
			SELECT id, ?, ?, 512, 'SSD', ?, ?, 12000, ?, 0, ?, datetime('now')
			FROM devices WHERE hostname=?`,
			dk.model, dk.serial, dk.health, dk.temp, dk.wear, dk.predict, dk.host); err != nil {
			log.Fatalf("disks: %v", err)
		}
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
		if _, err := d.Exec(`INSERT INTO topology_links (parent_device_id, child_device_id, port)
			SELECT p.id, c.id, ? FROM devices p, devices c
			WHERE p.hostname=? AND c.hostname=?`, l.port, l.parent, l.child); err != nil {
			log.Fatalf("topology: %v", err)
		}
	}

	for _, e := range []struct{ host, sev, cat, msg string }{
		{"SRV-1C", "critical", "uptime", "Связь с критичным устройством SRV-1C (192.168.1.5) потеряна!"},
		{"KADR-01", "warning", "software", "Установлено новое ПО: uTorrent"},
		{"192.168.1.99", "warning", "replay", "Отклонён запрос агента: неверная подпись"},
	} {
		d.Exec(`INSERT INTO events (hostname, source, event_id, severity, category, message)
			VALUES (?, 'correlation', 0, ?, ?, ?)`, e.host, e.sev, e.cat, e.msg)
	}

	d.Exec(`INSERT INTO audit_log (user_id, action, target, detail) VALUES (1,'login','session','192.168.1.100')`)
	d.Exec(`INSERT INTO audit_log (user_id, action, target, detail) VALUES (1,'command_run','flushdns','9 устройств')`)
	d.Exec(`INSERT INTO forbidden_software (pattern, reason) VALUES ('utorrent','Торрент-клиент')`)
	d.Exec(`INSERT INTO software_licenses (name, vendor, total_seats, expires_at) VALUES ('1С:Предприятие 8.3','1С',10,date('now','+60 days'))`)

	fmt.Println("готово: admin / Parol12345")
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
