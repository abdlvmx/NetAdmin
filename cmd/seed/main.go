// Команда seed — наполнение тестовой базы для ручного просмотра интерфейса.
//
// Инструмент разработчика: заполняет пустую базу правдоподобными данными,
// чтобы страницы можно было смотреть не на пустых таблицах. В поставку
// не входит и на рабочей базе не запускается.
package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"strings"
	"time"

	"netadmin/internal/auth"
	"netadmin/internal/config"
	"netadmin/internal/db"
)

// demoHost — одно тестовое устройство. Список общий для наполнения базы и для
// режима -keepalive, чтобы «живой» статус в демо совпадал с задуманным.
type demoHost struct {
	host, ip, mac, os, status, typ, loc string
	emp                                 int
	agent                               bool
	crit                                bool
}

var demoHosts = []demoHost{
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

func main() {
	keepalive := flag.Bool("keepalive", false,
		"не наполнять базу, а держать тестовые устройства «онлайн» до Ctrl+C (для снятия скриншотов)")
	every := flag.Duration("every", 10*time.Second, "период обновления в режиме -keepalive")
	flag.Parse()

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

	if *keepalive {
		runKeepalive(d, *every)
		return
	}

	var users int
	d.QueryRow("SELECT COUNT(*) FROM users").Scan(&users)
	if users > 0 {
		log.Fatal("база не пуста — наполнять её тестовыми данными нельзя")
	}

	hash, _ := auth.HashPassword("Parol12345")
	mustExec(d, `INSERT OR IGNORE INTO users (username, full_name, email, role, password_hash)
		VALUES ('admin','Иванов Иван Иванович','admin@firma.local','admin',?)`, hash)
	mustExec(d, `INSERT OR IGNORE INTO users (username, full_name, role, password_hash)
		VALUES ('operator','Петров Пётр','user',?)`, hash)
	mustExec(d, `INSERT OR IGNORE INTO users (username, full_name, role, password_hash)
		VALUES ('viewer','Сидорова Анна','viewer',?)`, hash)

	for _, dep := range []string{"Бухгалтерия", "Отдел кадров", "Производство", "ИТ-отдел"} {
		mustExec(d, `INSERT OR IGNORE INTO departments (name) VALUES (?)`, dep)
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
		mustExec(d, `INSERT OR IGNORE INTO employees (full_name, position, department_id, email, phone)
			VALUES (?,?,?,?,?)`, e.name, e.pos, e.dep, "user@firma.local", "+7 900 000-00-00")
	}

	hosts := demoHosts
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
			mustExec(d, `INSERT INTO metrics_history (device_id, cpu_usage, ram_usage, disk_usage, ts)
				VALUES (?,?,?,?, datetime('now', ?))`,
				id, float64(10+rand.Intn(80)), float64(30+rand.Intn(60)), float64(20+rand.Intn(70)),
				fmt.Sprintf("-%d minutes", j*20))
		}
		for _, sw := range []string{"7-Zip 24.08", "Google Chrome 130", "1С:Предприятие 8.3", "Adobe Acrobat Reader"} {
			mustExec(d, `INSERT INTO software (device_id, name, version) VALUES (?,?, '1.0')`, id, sw)
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
	mustExec(d, `INSERT INTO software (device_id, name, version) SELECT id, 'uTorrent', '3.6' FROM devices WHERE hostname='KADR-01'`)
	mustExec(d, `INSERT INTO software (device_id, name, version) SELECT id, 'Steam', '1.0' FROM devices WHERE hostname='PROIZV-01'`)

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

	for _, tk := range []struct{ code, title, cat, status, who string }{
		{"K7M2QP", "Не печатает принтер в 201 кабинете", "Оборудование", "new", "Смирнова Ольга Петровна"},
		{"R4TX8N", "Не открывается 1С, ошибка базы", "ПО", "in_progress", "Кузнецов Андрей Сергеевич"},
		{"B9YH3W", "Забыл пароль от учётной записи", "Доступ", "resolved", "Попова Мария Ивановна"},
		{"L2QF6K", "Медленно работает компьютер", "Оборудование", "closed", "Васильев Дмитрий Олегович"},
	} {
		if _, err := d.Exec(`INSERT INTO tickets (code, title, description, category, status, priority,
			reporter_name, reporter_email, location)
			VALUES (?,?,?,?,?, 'normal', ?, 'user@firma.local', 'каб. 201')`,
			tk.code, tk.title, "Подробное описание проблемы от сотрудника.", tk.cat, tk.status, tk.who); err != nil {
			log.Fatalf("tickets: %v", err)
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
		mustExec(d, `INSERT INTO events (hostname, source, event_id, severity, category, message)
			VALUES (?, 'correlation', 0, ?, ?, ?)`, e.host, e.sev, e.cat, e.msg)
	}

	mustExec(d, `INSERT INTO audit_log (user_id, action, target, detail) VALUES (1,'login','session','192.168.1.100')`)
	mustExec(d, `INSERT INTO audit_log (user_id, action, target, detail) VALUES (1,'command_run','flushdns','9 устройств')`)

	fmt.Println("готово: admin / Parol12345")
}

// runKeepalive возвращает тестовым устройствам их задуманный статус и обновляет
// last_seen, пока работает. Без этого демо-база «умирает» через пару минут:
// сервер помечает offline всех, от кого не было heartbeat дольше таймаута, а
// критичные устройства вдобавок пингуются — фиктивные адреса не отвечают.
// Нужно, чтобы снять скриншоты на живой картинке, а не на полностью красной.
func runKeepalive(d *sql.DB, every time.Duration) {
	var devices int
	d.QueryRow("SELECT COUNT(*) FROM devices").Scan(&devices)
	if devices == 0 {
		log.Fatal("база пуста — сначала наполните её без -keepalive")
	}
	fmt.Printf("держу тестовые устройства онлайн, обновление раз в %s; Ctrl+C для выхода\n", every)
	for {
		for _, h := range demoHosts {
			if _, err := d.Exec(`UPDATE devices
				SET status=?, last_seen=datetime('now'), down_streak=0, down_since=NULL
				WHERE hostname=?`, h.status, h.host); err != nil {
				log.Printf("keepalive %s: %v", h.host, err)
			}
		}
		time.Sleep(every)
	}
}

// mustExec падает на любой ошибке вставки. В инструменте разработчика молчаливая
// ошибка хуже падения: опечатка в имени колонки просто оставляет раздел
// приложения пустым, и это выглядит как недоделанная функция, а не как баг seed.
func mustExec(d *sql.DB, query string, args ...any) {
	if _, err := d.Exec(query, args...); err != nil {
		log.Fatalf("seed: %v\nзапрос: %s", err, strings.TrimSpace(query))
	}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
