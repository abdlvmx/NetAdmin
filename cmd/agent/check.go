package main

import (
	"fmt"
	"net"
	"net/url"
	"os/user"
	"strings"
	"time"
)

// runCheck — самодиагностика агента (`agent.exe -check`).
//
// Отвечает на вопрос «почему не работает» прямо на проблемной машине. Раньше
// для этого нужен был доступ к серверу и его базе: агент печатал ошибку и
// закрывал окно, а установленный службой не печатал ничего вовсе. При этом
// причины были однотипны и проверяемы на месте: не задан адрес или токен,
// сервер недоступен, токен разошёлся с серверным, не хватает прав.
//
// Возвращает код выхода: 0 — всё в порядке, 1 — есть неисправности.
func runCheck() int {
	fmt.Printf("NetAdmin agent %s — проверка\n\n", agentVersion)
	problems := 0
	fail := func(format string, a ...any) {
		problems++
		fmt.Printf("  [ПРОБЛЕМА] "+format+"\n", a...)
	}

	// --- настройки ---
	//
	// Источник указывается первой строкой: настройки берутся из файла рядом с
	// агентом либо из переменных окружения, и при неверном адресе прежде всего
	// нужно знать, какое из двух мест править.
	fmt.Println("Настройки")

	// Настройки лежат в закрытом каталоге установки (см. internal/instdir), и
	// из обычной консоли их не прочитать. Молча счесть их незаданными нельзя:
	// проверка сказала бы «агент не настроен» про исправно работающего агента
	// и отправила бы его переустанавливать.
	if settingsDenied {
		fmt.Printf("  файл настроек     %s — не читается\n", configPath())
		fail("нет доступа к настройкам агента из этой консоли.\n" +
			"             Каталог установки открыт только SYSTEM и администраторам.\n" +
			"             Запустите проверку от имени администратора — этого достаточно.")
		fmt.Println()
		fmt.Printf("Итог: найдено проблем — %d. См. пометки [ПРОБЛЕМА] выше.\n", problems)
		return 1
	}
	fmt.Printf("  источник          %s\n", settingsSource)
	switch {
	case rawServerURL == "":
		fmt.Printf("  адрес сервера     %s (не задан, значение по умолчанию)\n", serverURL)
		fail("адрес сервера не задан — агент будет искать сервер на этой же машине.\n" +
			"             Поставьте агента заново: agent.exe -install -server=… -token=…")
	case rawServerURL != serverURL:
		fmt.Printf("  адрес сервера     %s\n", serverURL)
		fmt.Printf("                    (задан как %q — достроен до полного вида)\n", rawServerURL)
	default:
		fmt.Printf("  адрес сервера     %s\n", serverURL)
	}

	switch {
	case strings.Contains(rawServerURL, "YOUR_URL_HERE"), strings.Contains(token, "YOUR_TOKEN_HERE"):
		fail("в настройках остались заглушки из шаблона install_agent.bat.\n" +
			"             Поставьте агента заново командой со страницы «Настройки».")
	case token == "":
		fmt.Println("  enrollment-токен  не задан (нормально, если устройство уже зарегистрировано)")
	default:
		fmt.Printf("  enrollment-токен  задан (%d символов)\n", len(token))
	}
	if settingsSource == sourceConfig {
		fmt.Printf("  файл настроек     %s\n", configPath())
	}
	fmt.Printf("  файл состояния    %s\n", statePath())

	// --- регистрация ---
	fmt.Println("\nРегистрация")
	st := loadState()
	deviceToken, deviceID = unprotectString(st.DeviceToken), st.DeviceID

	// Токен устройства зашифрован DPAPI под той учётной записью, что его
	// получила, — а получает его служба, работающая от SYSTEM. Запущенная
	// администратором проверка расшифровать его не может, и раньше это
	// выглядело как «устройство не зарегистрировано» плюс ложная жалоба на
	// несовпадение токенов. Идентификатор устройства в файле не шифруется,
	// поэтому отличить одно от другого можно.
	lockedToService := st.DeviceToken != "" && deviceToken == ""

	switch {
	case lockedToService:
		fmt.Printf("  устройство        #%d, зарегистрировано\n", st.DeviceID)
		fmt.Println("  персональный токен зашифрован под учётной записью службы (SYSTEM)")
		fmt.Println("                    и из этой консоли не читается — это нормально")
	case deviceID > 0 && deviceToken != "":
		fmt.Printf("  устройство        #%d, персональный токен получен\n", deviceID)
	case token != "":
		fmt.Println("  устройство        ещё не зарегистрировано — будет при первом обращении")
	default:
		fmt.Println("  устройство        не зарегистрировано")
		fail("нет ни персонального, ни enrollment-токена — подключиться нечем.\n" +
			"             Поставьте агента заново командой со страницы «Настройки».")
	}

	// --- связь ---
	fmt.Println("\nСвязь")
	host := serverURL
	if u, err := url.Parse(serverURL); err == nil && u.Host != "" {
		host = u.Host
	}
	t0 := time.Now()
	conn, err := net.DialTimeout("tcp", host, 5*time.Second)
	if err != nil {
		fmt.Printf("  TCP %-20s недоступен\n", host)
		fail("сервер не отвечает на %s: %v\n"+
			"             Проверьте, что сервер запущен, и что порт открыт в брандмауэре\n"+
			"             (deploy/firewall_server.bat), включая подсеть этой машины.", host, err)
	} else {
		conn.Close()
		fmt.Printf("  TCP %-20s ok (%d мс)\n", host, time.Since(t0).Milliseconds())

		// Подписанный запрос: именно он выявляет расхождение токенов, которое
		// со стороны выглядит как «агент работает, но данных нет».
		//
		// Если токен устройства принадлежит службе, подписать запрос отсюда
		// нечем: проверка получила бы 403 и обвинила бы в несовпадении токенов
		// исправно работающего агента.
		switch {
		case lockedToService:
			fmt.Println("  подпись запроса   не проверялась: подписать может только служба")
			fmt.Println("                    Работу агента видно на сервере — по времени")
			fmt.Println("                    последнего heartbeat в карточке устройства.")
		default:
			code, body, err := post("/api/agent-heartbeat", collectMetrics())
			switch {
			case err != nil:
				fail("запрос к серверу не прошёл: %v", err)
			case code == 200:
				fmt.Println("  подпись запроса   ok — сервер принял данные")
			case code == 403:
				fail("сервер отверг подпись (HTTP 403: %s).\n"+
					"             Токен агента не совпадает с серверным — так бывает после\n"+
					"             смены токена или пересоздания config.json. Поставьте агента\n"+
					"             заново командой со страницы «Настройки».", strings.TrimSpace(string(body)))
			case code == 409:
				fail("устройство уже зарегистрировано под другим токеном (HTTP 409).\n" +
					"             Откройте карточку устройства на сервере и нажмите «Сбросить токен»,\n" +
					"             затем запустите агента снова.")
			case code == 401:
				fail("сервер не принял токен (HTTP 401). Проверьте enrollment-токен в Настройках.")
			default:
				fail("сервер ответил HTTP %d: %s", code, strings.TrimSpace(string(body)))
			}
		}
	}

	// --- права ---
	fmt.Println("\nПрава")
	if u, err := user.Current(); err == nil {
		fmt.Printf("  учётная запись    %s\n", u.Username)
		if !isSystemAccount(u.Username) {
			fmt.Println("                    (для полного инвентаря агент ставится задачей от SYSTEM)")
		}
	}

	// --- что соберётся ---
	problems += checkInventory()

	fmt.Println()
	if problems == 0 {
		fmt.Println("Итог: неисправностей не найдено.")
		return 0
	}
	fmt.Printf("Итог: найдено проблем — %d. См. пометки [ПРОБЛЕМА] выше.\n", problems)
	return 1
}

// isSystemAccount — работает ли агент от системной учётной записи, под которой
// он видит реестр и службы целиком.
func isSystemAccount(name string) bool {
	n := strings.ToUpper(name)
	return strings.Contains(n, "SYSTEM")
}
