// Команда netadmin — HTTP-сервер NetAdmin (Go-порт).
package main

import (
	"database/sql"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"time"

	"netadmin/internal/config"
	"netadmin/internal/db"
	"netadmin/internal/handlers"
	"netadmin/internal/ingest"
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
		t := time.NewTicker(60 * time.Second)
		defer t.Stop()
		for range t.C {
			markStaleOffline(database)
		}
	}()

	app := &handlers.App{
		DB:     database,
		Ingest: ingest.New(database, config.MetricsRetentionDays, config.EventsRetentionDays, config.AuditRetentionDays),
	}

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
	log.Fatal(http.ListenAndServe(listenAddr, app.Routes()))
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
