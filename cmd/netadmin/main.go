// Команда netadmin — HTTP-сервер NetAdmin (Go-порт).
package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
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

	"netadmin/internal/agentbin"
	"netadmin/internal/auth"
	"netadmin/internal/backup"
	"netadmin/internal/config"
	"netadmin/internal/db"
	"netadmin/internal/demo"
	"netadmin/internal/handlers"
	"netadmin/internal/ingest"
	"netadmin/internal/netaccess"
	"netadmin/internal/netiface"
	"netadmin/internal/notify"
	"netadmin/internal/version"
	"netadmin/internal/web"
	"netadmin/internal/winsvc"
)

func main() {
	demoMode := flag.Bool("demo", false,
		"витрина: временная база с вымышленными данными, сеть не сканируется")
	install := flag.Bool("install", false,
		"установить службу Windows и запустить её (права запросит Windows)")
	uninstall := flag.Bool("uninstall", false,
		"остановить и удалить службу Windows (данные сохраняются)")
	status := flag.Bool("status", false, "показать состояние службы Windows")
	restart := flag.Bool("restart", false,
		"перезапустить службу Windows (применить изменения настроек или восстановление)")
	firewall := flag.Bool("firewall", false,
		"при установке открыть порт 8765 в брандмауэре без вопросов")
	noFirewall := flag.Bool("no-firewall", false,
		"при установке не трогать брандмауэр")
	showVersion := flag.Bool("version", false,
		"показать версию сборки и выйти")
	resetPw := flag.Bool("reset-password", false,
		"задать новый пароль администратору, потерявшему доступ (спросит, кому)")
	resetUser := flag.String("user", "",
		"для -reset-password: чей пароль менять, если администраторов несколько")
	flag.Parse()

	switch {
	case *showVersion:
		// Прав не требует и ничего не открывает: на вопрос «какая у вас версия»
		// нужно уметь ответить, не запуская сервер.
		fmt.Println("NetAdmin " + version.Full())
		return
	case *resetPw:
		runServiceCommand(resetPasswordArgs(*resetUser),
			func() error { return resetPassword(*resetUser) })
		return
	case *resetUser != "":
		// Сам по себе -user ничего не значит, а молча запустить вместо смены
		// пароля обычный сервер — худший из возможных ответов: человек решит,
		// что пароль сменён.
		fmt.Println("ОШИБКА: -user задаётся вместе с -reset-password. " +
			"Пароль меняет netadmin.exe -reset-password -user=" + *resetUser)
		holdWindow()
		os.Exit(1)
	case *restart:
		// Перезапуск тоже требует прав: раньше он единственный их не запрашивал
		// и падал с сырым «Access is denied» ровно там, куда интерфейс сам же
		// и посылает — на страницу настроек с кнопкой «Перезапустить сервер».
		runServiceCommand([]string{"-restart"}, restartServer)
		return
	case *install, *uninstall:
		if *firewall && *noFirewall {
			fmt.Println("ОШИБКА: заданы сразу -firewall и -no-firewall — непонятно, " +
				"открывать порт или нет. Оставьте один флаг.")
			holdWindow()
			os.Exit(1)
		}
		if *uninstall {
			runServiceCommand([]string{"-uninstall"}, uninstallServer)
			return
		}
		fw := firewallFromFlags(*firewall, *noFirewall)
		runServiceCommand(append([]string{"-install"}, firewallArgs(fw)...),
			func() error { return installServer(fw) })
		return
	case *status:
		if err := printServerStatus(); err != nil {
			fmt.Println("ОШИБКА:", err)
			holdWindow()
			os.Exit(1)
		}
		return
	}

	// Запуск диспетчером служб: останавливаемся по команде системы, а не по
	// Ctrl+C, и пишем в файл — консоли у службы нет и вывод иначе пропадает.
	if winsvc.IsService() {
		startServiceLog()
		// Ошибка уходит в журнал: консоли у службы нет, и это единственный след
		// причины. Диспетчеру о неудаче сообщает сам winsvc.Run.
		if err := winsvc.Run(serviceName, func(stop <-chan struct{}) error {
			return serve(*demoMode, stop)
		}); err != nil {
			log.Printf("служба остановлена с ошибкой: %v", err)
			os.Exit(1)
		}
		return
	}

	// Запуск двойным щелчком без аргументов: спрашиваем, чего человек хочет.
	// Через консоль с флагами вопросов не задаём — там намерение уже выражено.
	if askOnStart(flag.NFlag(), ownsConsole(), dataExists()) {
		switch askFirstRun() {
		case choiceQuit:
			return
		case choiceDemo:
			*demoMode = true
		case choiceInstall:
			runServiceCommand([]string{"-install"}, func() error { return installServer(firewallAsk) })
			return
		case choiceSetup:
			// обычный запуск, ничего менять не надо
		}
	}

	// Консольный запуск: останавливаемся по Ctrl+C.
	stop := make(chan struct{})
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		close(stop)
	}()
	// Отказ на запуске показывается человеку и держит окно открытым: при
	// двойном щелчке сообщение иначе исчезает раньше, чем его прочитают.
	if err := serve(*demoMode, stop); err != nil {
		fmt.Println("ОШИБКА:", err)
		holdWindow()
		os.Exit(1)
	}
}

// askOnStart — показывать ли выбор при запуске.
//
// Только на пустом месте: у кого база уже заведена, тот продукт настроил, и
// спрашивать его при каждом запуске «чего вы хотите» — навязчиво. Флаги тоже
// снимают вопрос: намерение в них уже выражено. И общее окно консоли значит,
// что человек пришёл из терминала и сам знает, что запускает.
func askOnStart(flags int, ownsConsole, dataExists bool) bool {
	return flags == 0 && ownsConsole && !dataExists
}

// dataExists — база уже создана в каталоге данных.
func dataExists() bool {
	_, err := os.Stat(config.DBPath())
	return err == nil
}

// runServiceCommand выполняет установку или удаление службы, запросив права
// через UAC, если их нет.
//
// Раньше без прав команда просто отказывалась с подсказкой «откройте консоль от
// имени администратора» — для человека, скачавшего один файл, лишний шаг:
// Windows умеет спросить сама.
func runServiceCommand(elevateArgs []string, do func() error) {
	if runtime.GOOS == "windows" && !winsvc.Elevated() {
		started, err := elevateSelf(elevateArgs...)
		if err != nil {
			fmt.Println("ОШИБКА:", err)
			holdWindow()
			os.Exit(1)
		}
		if started {
			return // работу продолжит запущенная с правами копия
		}
	}
	if err := do(); err != nil {
		fmt.Println("ОШИБКА:", err)
		holdWindow()
		os.Exit(1)
	}
	holdWindow()
}

// firewallFromFlags переводит флаги в решение о брандмауэре. Без флагов
// установщик спрашивает: он же запускается двойным щелчком.
func firewallFromFlags(yes, no bool) firewallChoice {
	switch {
	case no:
		return firewallNo
	case yes:
		return firewallYes
	}
	return firewallAsk
}

// firewallArgs — как передать решение о брандмауэре копии, запущенной с
// правами.
//
// Аргументы выводятся из самого решения, а не собираются заново из флагов.
// Раньше две ветки читали флаги по-разному: при -firewall и -no-firewall
// сразу неповышенная копия выбирала «не трогать», а повышенная — «открыть»,
// то есть одна команда означала разное по разные стороны UAC. Само сочетание
// теперь отклоняется, но выводить аргументы из решения всё равно правильнее:
// разойтись им больше негде.
func firewallArgs(fw firewallChoice) []string {
	switch fw {
	case firewallYes:
		return []string{"-firewall"}
	case firewallNo:
		return []string{"-no-firewall"}
	}
	return nil
}

// serve поднимает сервер со всеми фоновыми задачами и работает, пока не
// закроется stop. Вынесено из main, чтобы одно и то же тело обслуживало и
//
// Возвращает ошибку вместо того, чтобы гасить процесс: под службой log.Fatalf
// означает os.Exit прямо из горутины — диспетчер не получает ни отчёта, ни
// кода, в журнале остаётся «terminated unexpectedly», а настроенные действия
// восстановления загоняют службу в цикл перезапусков без единой строки о
// причине.
// консольный запуск, и службу Windows.
func serve(demoMode bool, stop <-chan struct{}) error {
	// Демо-режим готовится до открытия базы: каталог данных выбирается по
	// переменной окружения, и подменить его позже уже нельзя.
	if demoMode {
		dir, err := os.MkdirTemp("", "netadmin-demo-")
		if err != nil {
			return fmt.Errorf("демо-режим: не удалось создать временный каталог: %w", err)
		}
		// удаляется последним: defer database.Close() зарегистрирован ниже и
		// сработает раньше, иначе Windows не отдаст файл открытой базы
		defer os.RemoveAll(dir)
		os.Setenv("NETADMIN_DATA_DIR", dir)
		web.SetDemo(true)
	}

	// Подготовленное восстановление применяется здесь — до открытия базы:
	// подменить файл работающей базы нельзя (см. internal/backup).
	if saved, err := backup.ApplyPending(config.DBPath()); err != nil {
		log.Printf("восстановление из копии: %v", err)
	} else if saved != "" {
		log.Printf("база восстановлена из копии; прежняя сохранена как %s", saved)
	}

	database, err := db.Open(config.DBPath())
	if err != nil {
		return fmt.Errorf("не удалось открыть базу %s: %w.\n"+
			"Проверьте, что каталог доступен на запись и файл не занят другой копией сервера.",
			config.DBPath(), err)
	}
	defer database.Close()

	if err := db.InitSchema(database); err != nil {
		return fmt.Errorf("не удалось подготовить схему базы: %w", err)
	}

	// материализуем config.json и токен агента при первом запуске
	config.Load()

	if demoMode {
		if err := demo.Seed(database); err != nil {
			return fmt.Errorf("демо-режим, наполнение базы: %w", err)
		}
	}

	// Все фоновые задачи ниже смотрят на stop. Без этого они переживали serve:
	// та возвращается, defer закрывает базу — и тикеры продолжают ходить в
	// закрытую базу. Пока serve заканчивалась вместе с процессом, этого не было
	// видно, но она больше не заканчивается процессом.
	// фоновая задача: авто-offline устройств с агентом по таймауту heartbeat
	go func() {
		tick := func() {
			// В демо статусы держит demo.Keepalive: вымышленные машины
			// heartbeat не шлют, и через две минуты весь парк стал бы offline.
			if !demoMode {
				markStaleOffline(database)
			}
			auth.PurgeExpiredSessions(database)
			handlers.PurgeEnrollCodes(database)
		}
		tick()
		t := time.NewTicker(60 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				tick()
			}
		}
	}()

	// Разрешённые подсети: переменная окружения, затем настройка из config.json,
	// затем умолчание (локальные и частные сети). Служба окружение консоли не
	// наследует, поэтому одной переменной было мало.
	cfg := config.Load()
	allowSet := cfg.AllowSubnetsSetting()
	allow, err := netaccess.Parse(allowSet.Value)
	if err != nil {
		// Перезапуском это не лечится: значение в файле не изменится само,
		// а действия восстановления иначе поднимали бы службу раз в минуту.
		return winsvc.Permanent(fmt.Errorf("разрешённые подсети (источник: %s): %w.\n"+
			"Сервер не запускается, пока значение неверно: исправьте allow_subnets в "+
			"config.json или уберите переменную NETADMIN_ALLOW.", allowSet.Source, err))
	}

	app := &handlers.App{
		DB:     database,
		Ingest: ingest.New(database, config.MetricsRetentionDays, config.EventsRetentionDays, config.AuditRetentionDays),
		Allow:  allow,
		Demo:   demoMode,
		// Перезапуск доступен только установленной службе: из консоли сервер
		// перезапускает человек, и интерфейс так и напишет.
		Restart: serverRestarter(),
		// Установка агента на эту же машину — сервер уже имеет и файл агента,
		// и права, если запущен службой.
		InstallAgent: localAgentInstaller(),
		// Запущен ли сервер службой — первый вопрос чек-листа первых шагов:
		// сервер из консоли закрывается вместе с окном.
		IsService: winsvc.IsService(),
	}

	// Фоновая работа. В демо она вся отключена, а вместо неё вымышленный парк
	// держится «живым»: тот, кто просто смотрит продукт, не должен получить от
	// него сканирование своей сети, пинги, опрос SNMP и запросы наружу —
	// а копии временной базы во временном каталоге и подавно бессмысленны.
	if demoMode {
		demoCtx, demoStop := context.WithCancel(context.Background())
		defer demoStop()
		go demo.Keepalive(demoCtx, database, 30*time.Second)
	} else {
		// мониторинг доступности критичных устройств (uptime-алерты)
		go func() {
			t := time.NewTicker(time.Minute)
			defer t.Stop()
			for {
				select {
				case <-stop:
					return
				case <-t.C:
					app.CheckCritical()
				}
			}
		}()

		// планировщик автосканирования сети (deep — раз в N часов; fast-ping — каждые 15 мин)
		go func() {
			var lastDeep, lastFast = time.Now(), time.Now()
			t := time.NewTicker(time.Minute)
			defer t.Stop()
			for {
				select {
				case <-stop:
					return
				case <-t.C:
				}
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
	}

	// адрес прослушивания: по умолчанию 0.0.0.0 (доступ агентам по сети),
	// переопределяется NETADMIN_ADDR (например, 127.0.0.1:8765 или :9000).
	// Демо слушает только петлю: агентам туда подключаться незачем, а запрос
	// брандмауэра на чужой машине — плохая первая минута знакомства.
	defaultAddr := "0.0.0.0:8765"
	if demoMode {
		defaultAddr = "127.0.0.1:8765"
	}
	listenAddr := defaultAddr
	// В демо каталог данных временный, поэтому config.json там всегда пустой:
	// сюда может прийти только явно заданная переменная окружения. Раньше она
	// молча отбрасывалась, и сервер слушал не тот порт, который просили.
	if addrSet := cfg.ListenAddrSetting(); addrSet.Value != "" {
		listenAddr = addrSet.Value
	}
	_, port, e := net.SplitHostPort(listenAddr)
	if e != nil {
		port = "8765"
	}

	// Браузер открываем только при запуске из консоли: у службы нет рабочего
	// стола, и rundll32 от имени SYSTEM ничего не показал бы никому.
	if os.Getenv("NETADMIN_NO_BROWSER") == "" && !winsvc.IsService() {
		go openBrowser("http://127.0.0.1:" + port)
	}

	// Служба пишет в файл журнала, человек за консолью — читает приветствие.
	// Прежде и ему доставались строки с отметками времени: работающий сервер
	// выглядел как отладочный вывод, и даже то, что окно закрывать нельзя,
	// приходилось угадывать.
	if winsvc.IsService() {
		log.Printf("NetAdmin слушает %s (UI: http://127.0.0.1:%s)", listenAddr, port)
		log.Printf("Доступ разрешён с адресов: %s (источник: %s)", allow, allowSet.Source)
		if allow.Unrestricted() {
			log.Print("ВНИМАНИЕ: ограничение по подсетям снято, сервер обслуживает " +
				"любые адреса. Канал не шифруется, используйте только в доверенной сети.")
		}
		logReachableAddrs(port)
	} else if demoMode {
		printDemoBanner(port)
	} else {
		printServerBanner(port, allow, allowSet.Source)
	}

	warnStaleAgent()

	// Резервные копии запускаются после приветствия: первая снимается сразу,
	// и её строка иначе падала бы человеку прямо посреди приветствия.
	if !demoMode {
		go runBackups(database, stop)
	}

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
	// Ошибка прослушивания приходит из горутины. Раньше она гасила процесс
	// целиком: log.Fatalf — это os.Exit, при котором не закрывается база и
	// теряется всё, что ingest не успел записать. Теперь она возвращается
	// наверх обычным путём, через остановку.
	failed := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			failed <- fmt.Errorf("не удалось занять адрес %s: %w.\n"+
				"Порт занят другой программой или другой копией NetAdmin. Освободите его "+
				"или задайте другой адрес: listen_addr в config.json.", listenAddr, err)
		}
	}()

	// Корректная остановка. Без неё рвались текущие запросы, а метрики из
	// буфера ingest пропадали: они пишутся пачками и обычный перезапуск
	// сервера терял всё, что не успело уйти в базу.
	var failure error
	select {
	case <-stop:
	case failure = <-failed:
		log.Printf("аварийная остановка: %v", failure)
	}

	log.Print("остановка: дожидаюсь текущих запросов и дописываю метрики...")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("остановка сервера: %v", err)
	}
	app.Ingest.Close()
	log.Print("остановлено")
	return failure
}

// warnStaleAgent говорит, что встроенный агент собран не из той ревизии, что
// сервер, — то есть машины получат старую сборку.
//
// Порядок сборки («агент первым, сервер вторым» — он встраивает то, что лежит
// в internal/agentbin/bin на момент своей сборки) не проверялся ничем, а промах
// молчаливый и отложенный: сервер трое суток раздавал агента трёхдневной
// давности, и обнаружилось это только когда тот отказался ставиться поверх
// собственной службы.
func warnStaleAgent() {
	if !agentbin.Available() || agentbin.Compare() != agentbin.MatchStale {
		return
	}
	agent, _ := agentbin.Info()
	server, _ := agentbin.Self()
	when := agent.Time.Local().Format("02.01.2006")

	if winsvc.IsService() {
		log.Printf("ВНИМАНИЕ: внутри сервера сборка агента из ревизии %s (%s), сам сервер — "+
			"из %s. Собрано не в том порядке: пересоберите сначала агента, затем сервер.",
			agent.Short(), when, server.Short())
		return
	}
	fmt.Println()
	fmt.Printf("  ВНИМАНИЕ: внутри сервера сборка агента из ревизии %s (%s),\n", agent.Short(), when)
	fmt.Printf("  а сам сервер — из %s. Собрано не в том порядке.\n", server.Short())
	fmt.Println("  Пересоберите:")
	fmt.Println("      go build -o internal/agentbin/bin/agent.exe ./cmd/agent")
	fmt.Println("      go build -o netadmin.exe ./cmd/netadmin")
}

// runBackups снимает копии базы по расписанию из настроек.
//
// Отсчёт ведётся от времени самой свежей копии в каталоге, а не от запуска
// сервера: иначе перезапуск сдвигал бы расписание, и при частых перезапусках
// копия не снималась бы никогда.
func runBackups(d *sql.DB, stop <-chan struct{}) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	// Копирование не удаётся — состояние, а не событие: круг идёт каждые
	// десять минут, и письмо на каждом означало бы шесть писем в час об одном
	// и том же. Сообщаем о переходе в отказ и о возврате, как это сделано для
	// сервисов и SNMP.
	failing := false
	for {
		// Проверка в начале круга, а не только в конце: первая копия снимается
		// сразу при входе, и без неё она успевала уйти в уже закрытую базу —
		// строкой «sql: database is closed» в журнале на прощание.
		select {
		case <-stop:
			return
		default:
		}
		cfg := config.Load()
		if cfg.BackupIntervalHours > 0 {
			dir, err := backup.Dir(config.DataDir(), cfg.BackupDir)
			if err != nil {
				backupFailed(&failing, err)
			} else {
				due := true
				if list := backup.List(dir); len(list) > 0 {
					due = time.Since(list[0].Created) >= time.Duration(cfg.BackupIntervalHours)*time.Hour
				}
				if due {
					if path, err := backup.Create(d, dir, cfg.BackupKeep); err != nil {
						backupFailed(&failing, err)
					} else {
						if failing {
							notify.Message("Резервное копирование восстановилось: копия снята в " + path)
							failing = false
						}
						log.Printf("резервная копия базы: %s", path)
					}
				}
			}
		}
		select {
		case <-stop:
			return
		case <-t.C:
		}
	}
}

// backupFailed сообщает о несостоявшейся копии — один раз на отказ.
//
// Раньше единственным следом была строка в журнале службы. Журнал никто не
// читает, а копии — единственная страховка от потери всего учёта разом: диск
// кончился месяц назад, узнали в день, когда копия понадобилась.
func backupFailed(failing *bool, err error) {
	log.Printf("резервное копирование: %v", err)
	if *failing {
		return
	}
	*failing = true
	notify.Message("Резервная копия базы не снялась: " + err.Error() +
		"\n\nВесь учёт хранится в одном файле, и копии — единственная защита от " +
		"его потери. Проверьте каталог копий и место на диске: " +
		"Настройки → Резервные копии базы.")
}

// splitAddrs возвращает адреса для агентов и публичные адреса, которых на
// машине быть не должно.
//
// Частные адреса берутся из netiface — с тем же порядком, что и в выборе на
// странице «Настройки»: первым идёт самый правдоподобный. Раньше здесь был
// свой обход интерфейсов без всякого порядка, и приветствие советовало агентам
// первый попавшийся адрес — на машине с Docker это оказывался 172.18.0.1,
// по которому не подключится никто.
func splitAddrs() (lan, public []string) {
	for _, a := range netiface.LocalIPv4s() {
		lan = append(lan, a.IP)
	}

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return lan, nil
	}
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok || n.IP.IsLoopback() || n.IP.To4() == nil {
			continue
		}
		if !n.IP.IsPrivate() && !n.IP.IsLinkLocalUnicast() {
			public = append(public, n.IP.String())
		}
	}
	return lan, public
}

// logReachableAddrs печатает адреса, по которым сервер доступен агентам,
// и предупреждает, если среди них есть публичный: продукт не предназначен
// для работы за пределами локальной сети.
func logReachableAddrs(port string) {
	lan, public := splitAddrs()
	for _, ip := range lan {
		log.Printf("Адрес для агентов: NETADMIN_SERVER_URL=http://%s:%s", ip, port)
	}
	for _, ip := range public {
		log.Printf("ВНИМАНИЕ: на интерфейсе публичный адрес %s — закройте порт %s "+
			"брандмауэром (см. deploy/firewall_server.bat)", ip, port)
	}
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
