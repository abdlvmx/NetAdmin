// Команда seed — наполнение тестовой базы для ручного просмотра интерфейса.
//
// Инструмент разработчика: заполняет пустую базу правдоподобными данными,
// чтобы страницы можно было смотреть не на пустых таблицах. В поставку
// не входит и на рабочей базе не запускается. Сами данные живут в
// internal/demo — тот же набор показывает `netadmin -demo`.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"netadmin/internal/config"
	"netadmin/internal/db"
	"netadmin/internal/demo"
)

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
		var devices int
		d.QueryRow("SELECT COUNT(*) FROM devices").Scan(&devices)
		if devices == 0 {
			log.Fatal("база пуста — сначала наполните её без -keepalive")
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		fmt.Printf("держу тестовые устройства онлайн, обновление раз в %s; Ctrl+C для выхода\n", *every)
		demo.Keepalive(ctx, d, *every)
		return
	}

	empty, err := demo.IsEmpty(d)
	if err != nil {
		log.Fatal(err)
	}
	if !empty {
		log.Fatal("база не пуста — наполнять её тестовыми данными нельзя")
	}
	if err := demo.Seed(d); err != nil {
		log.Fatalf("seed: %v", err)
	}
	fmt.Printf("готово: %s / %s\n", demo.AdminUser, demo.AdminPassword)
}
