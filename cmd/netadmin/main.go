// Команда netadmin — HTTP-сервер NetAdmin (Go-порт).
package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"netadmin/internal/auth"
	"netadmin/internal/backup"
	"netadmin/internal/config"
	"netadmin/internal/db"
	"netadmin/internal/handlers"
	"netadmin/internal/ingest"
	"netadmin/internal/netaccess"
)

func main() {
	database, err := db.Open(config.DBPath())
	if err != nil {
		log.Fatalf("db open: %v", err)
	}
	defer database.Close()

	if err := db.InitSchema(database); err != nil {
		log.Fatalf("db schema: %v", err)
	}

	// материализуем config.json и токен агента при первом запуске
	config.Load()

	// фоновая задача: авто-offline устройств с агентом по таймауту heartbeat
	go func() {
		markStaleOffline(database)
		auth.PurgeExpiredSessions(database)
		t := time.NewTicker(60 * time.Second)
		defer t.Stop()
		for range t.C {
			markStaleOffline(database)
			auth.PurgeExpiredSessions(database)
		}
	}()

	// разрешённые подсети: по умолчанию только локальные и частные сети
	allow, err := netaccess.Parse(os.Getenv("NETADMIN_ALLOW"))
	if err != nil {
		log.Fatalf("NETADMIN_ALLOW: %v", err)
	}

	app := &handlers.App{
		DB:     database,
		Ingest: ingest.New(database, config.MetricsRetentionDays, config.EventsRetentionDays, config.AuditRetentionDays),
		Allow:  allow,
	}

	// резервные копии базы по расписанию
	go runBackups(database)

	// мониторинг доступности критичных устройств (uptime-алерты)
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for range t.C {
			app.CheckCritical()
		}
	}()

	// планировщик автосканирования сети (deep — раз в N часов; fast-ping — каждые 15 мин)
	go func() {
		var lastDeep, lastFast = time.Now(), time.Now()
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for range t.C {
			app.DiscoverPassive() // пассивное обнаружение из ARP-кэша (всегда)
			app.RunDueChecks()    // проверки сервисов по интервалу (всегда)
			app.RunDueSNMP()      // опрос SNMP-устройств по интервалу (всегда)
			h := config.Load().ScanIntervalHours
			if h <= 0 {
				continue
			}
			if time.Since(lastDeep) >= time.Duration(h)*time.Hour {
				app.PerformScan()
				lastDeep = time.Now()
			}
			if time.Since(lastFast) >= 15*time.Minute {
				app.FastPing()
				lastFast = time.Now()
			}
		}
	}()

	// адрес прослушивания: по умолчанию 0.0.0.0 (доступ агентам по сети),
	// переопределяется NETADMIN_ADDR (например, 127.0.0.1:8765 или :9000).
	listenAddr := getenv("NETADMIN_ADDR", "0.0.0.0:8765")
	_, port, e := net.SplitHostPort(listenAddr)
	if e != nil {
		port = "8765"
	}

	if os.Getenv("NETADMIN_NO_BROWSER") == "" {
		go openBrowser("http://127.0.0.1:" + port)
	}

	log.Printf("NetAdmin слушает %s (UI: http://127.0.0.1:%s)", listenAddr, port)
	log.Printf("Доступ разрешён с адресов: %s", allow)
	if allow.Unrestricted() {
		log.Print("ВНИМАНИЕ: NETADMIN_ALLOW=any — ограничение по подсетям снято, " +
			"сервер обслуживает любые адреса. Канал не шифруется, используйте только в доверенной сети.")
	}
	logReachableAddrs(port)

	srv := &http.Server{
		Addr:    listenAddr,
		Handler: app.Routes(),
		// ReadHeaderTimeout — основная защита от медленных соединений: без него
		// клиент, тянущий заголовки по байту, занимает воркер бесконечно.
		ReadHeaderTimeout: 15 * time.Second,
		// Чтение и запись тела заданы щедро осознанно: через те же соединения
		// идут дистрибутивы ПО (до 1 ГБ), и короткий таймаут рвал бы установку.
		ReadTimeout:    30 * time.Minute,
		WriteTimeout:   30 * time.Minute,
		IdleTimeout:    2 * time.Minute,
		MaxHeaderBytes: 1 << 20,
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("listen: %v", err)
		}
	}()

	// Корректная остановка. Без неё рвались текущие запросы, а метрики из
	// буфера ingest пропадали: они пишутся пачками и обычный перезапуск
	// сервера терял всё, что не успело уйти в базу.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	log.Print("остановка: дожидаюсь текущих запросов и дописываю метрики...")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("остановка сервера: %v", err)
	}
	app.Ingest.Close()
	log.Print("остановлено")
}

// runBackups снимает копии базы по расписанию из настроек.
//
// Отсчёт ведётся от времени самой свежей копии в каталоге, а не от запуска
// сервера: иначе перезапуск сдвигал бы расписание, и при частых перезапусках
// копия не снималась бы никогда.
func runBackups(d *sql.DB) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		cfg := config.Load()
		if cfg.BackupIntervalHours > 0 {
			dir, err := backup.Dir(config.DataDir(), cfg.BackupDir)
			if err != nil {
				log.Printf("резервное копирование: %v", err)
			} else {
				due := true
				if list := backup.List(dir); len(list) > 0 {
					due = time.Since(list[0].Created) >= time.Duration(cfg.BackupIntervalHours)*time.Hour
				}
				if due {
					if path, err := backup.Create(d, dir, cfg.BackupKeep); err != nil {
						log.Printf("резервное копирование: %v", err)
					} else {
						log.Printf("резервная копия базы: %s", path)
					}
				}
			}
		}
		<-t.C
	}
}

// logReachableAddrs печатает адреса, по которым сервер доступен агентам,
// и предупреждает, если среди них есть публичный: продукт не предназначен
// для работы за пределами локальной сети.
func logReachableAddrs(port string) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return
	}
	var lan, public []string
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok || n.IP.IsLoopback() || n.IP.To4() == nil {
			continue // в подсказке для агентов показываем только IPv4
		}
		ip := n.IP.String()
		switch {
		case n.IP.IsLinkLocalUnicast():
			// 169.254.x — адрес самоназначения при неработающем DHCP,
			// подсказывать его для агентов бессмысленно
		case n.IP.IsPrivate():
			lan = append(lan, ip)
		default:
			public = append(public, ip)
		}
	}
	for _, ip := range lan {
		log.Printf("Адрес для агентов: NETADMIN_SERVER_URL=http://%s:%s", ip, port)
	}
	for _, ip := range public {
		log.Printf("ВНИМАНИЕ: на интерфейсе публичный адрес %s — закройте порт %s "+
			"брандмауэром (см. deploy/firewall_server.bat)", ip, port)
	}
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// markStaleOffline помечает offline устройства С АГЕНТОМ (есть история метрик),
// от которых не было heartbeat дольше таймаута. Устройства без агента
// (только из сканирования) не трогает.
func markStaleOffline(d *sql.DB) {
	_, _ = d.Exec(`
		UPDATE devices SET status='offline'
		WHERE status='online'
		  AND last_seen < datetime('now', ?)
		  AND EXISTS (SELECT 1 FROM metrics_history m WHERE m.device_id = devices.id)`,
		fmt.Sprintf("-%d minutes", config.HeartbeatTimeoutMin))
}

// openBrowser пытается открыть URL в браузере по умолчанию.
func openBrowser(url string) {
	time.Sleep(700 * time.Millisecond)
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}
