package main

import (
	"fmt"
	"net"
	"net/url"
	"os"
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
	fmt.Println("Настройки")
	raw := os.Getenv("NETADMIN_SERVER_URL")
	switch {
	case raw == "":
		fmt.Printf("  адрес сервера     %s (NETADMIN_SERVER_URL не задан, значение по умолчанию)\n", serverURL)
		fail("адрес сервера не задан — агент будет искать сервер на этой же машине.\n" +
			"             Задайте NETADMIN_SERVER_URL или переустановите агента установщиком из Настроек.")
	case raw != serverURL:
		fmt.Printf("  адрес сервера     %s\n", serverURL)
		fmt.Printf("                    (в переменной %q — достроен до полного вида)\n", raw)
	default:
		fmt.Printf("  адрес сервера     %s\n", serverURL)
	}

	switch {
	case strings.Contains(raw, "YOUR_URL_HERE"), strings.Contains(token, "YOUR_TOKEN_HERE"):
		fail("в переменных остались заглушки из шаблона install_agent.bat.\n" +
			"             Скачайте готовый установщик: Настройки → Установка агента.")
	case token == "":
		fmt.Println("  enrollment-токен  не задан")
	default:
		fmt.Printf("  enrollment-токен  задан (%d символов)\n", len(token))
	}
	fmt.Printf("  файл состояния    %s\n", statePath())

	// --- регистрация ---
	fmt.Println("\nРегистрация")
	st := loadState()
	deviceToken, deviceID = unprotectString(st.DeviceToken), st.DeviceID
	switch {
	case deviceID > 0 && deviceToken != "":
		fmt.Printf("  устройство        #%d, персональный токен получен\n", deviceID)
	case token != "":
		fmt.Println("  устройство        ещё не зарегистрировано — будет при первом обращении")
	default:
		fmt.Println("  устройство        не зарегистрировано")
		fail("нет ни персонального, ни enrollment-токена — подключиться нечем.\n" +
			"             Скачайте установщик в Настройках и запустите от администратора.")
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
		code, body, err := post("/api/agent-heartbeat", collectMetrics())
		switch {
		case err != nil:
			fail("запрос к серверу не прошёл: %v", err)
		case code == 200:
			fmt.Println("  подпись запроса   ok — сервер принял данные")
		case code == 403:
			fail("сервер отверг подпись (HTTP 403: %s).\n"+
				"             Токен агента не совпадает с серверным — так бывает после\n"+
				"             смены токена или пересоздания config.json. Скачайте установщик\n"+
				"             заново: Настройки → Установка агента.", strings.TrimSpace(string(body)))
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
