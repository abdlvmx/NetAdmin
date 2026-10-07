package main

import (
	"fmt"
	"os"
	"strings"

	"netadmin/internal/instdir"
	"netadmin/internal/wincon"
	"netadmin/internal/winsvc"
)

// Установка агента диалогом.
//
// Запущенный двойным щелчком без настроек агент печатал две строки и завершался
// с ошибкой «не задан NETADMIN_AGENT_TOKEN». Окно консоли принадлежало только
// ему, поэтому закрывалось вместе с процессом — со стороны выглядело так, будто
// не происходит ничего вовсе. Ни причины, ни того, что делать дальше.
//
// Теперь он спрашивает адрес сервера и код регистрации, а потом ставит себя
// службой, запросив права через UAC.

// askSetup спрашивает то, чего ещё не знает, и просит подтверждения.
//
// knownServer и knownCode приходят из файла, который сервер отдал уже
// настроенным (см. internal/agentcfg). Ради этого файл и делался: спрашивать
// адрес и сорокатрёхзначный код у человека, который просто запустил положенную
// на сетевую папку программу, значит вернуть ему ровно ту работу, от которой
// его избавляли. Пустые значения означают «спросить», как было раньше.
//
// Отделено от самой установки намеренно: диалог можно проверить тестами, не
// заводя службу на машине, где эти тесты идут.
func askSetup(knownServer, knownCode string) (server, code string, ok bool) {
	srv, c := knownServer, knownCode
	baked := srv != "" && c != ""

	if !baked {
		fmt.Println("  Недостающее показывает страница сервера:")
		fmt.Println("  Настройки → Установка агента.")
		fmt.Println()

		// Спрашиваем только то, чего не знаем: половина значений могла прийти
		// из файла, и переспрашивать её незачем.
		if srv == "" {
			if srv, ok = askUntil("  Адрес сервера (например 192.168.1.10:8765): "); !ok {
				return "", "", false
			}
		}
		if c == "" {
			if c, ok = askUntil("  Код регистрации: "); !ok {
				return "", "", false
			}
		}
	}

	full := normalizeServerURL(srv)
	fmt.Println()
	fmt.Printf("  Сервер: %s\n", full)
	if baked {
		fmt.Println("  Адрес и код регистрации вписаны в этот файл сервером.")
	}
	fmt.Println("  Агент будет установлен службой и запустится при загрузке.")
	fmt.Println()
	if !wincon.AskYesNo("  Продолжить?") {
		fmt.Println("\n  Отменено.")
		return "", "", false
	}
	return full, c, true
}

// askUntil повторяет вопрос, пока не получит непустой ответ. Три попытки —
// чтобы диалог не превращался в ловушку при закрытом вводе.
func askUntil(prompt string) (string, bool) {
	for i := 0; i < 3; i++ {
		v, ok := wincon.AskLine(prompt)
		if !ok {
			return "", false
		}
		if strings.TrimSpace(v) != "" {
			return v, true
		}
		fmt.Println("  Значение обязательно.")
	}
	return "", false
}

// confirmReconfigure предупреждает, если машина уже настроена, и спрашивает,
// точно ли перенастраивать. Ставить агента поверх работающего вслепую — способ
// потерять связь с сервером, на котором устройство уже числится.
func confirmReconfigure() bool {
	cfg, st, err := readInstallIdentity(instdir.Path())
	if err != nil {
		fmt.Println("  ОШИБКА:", err)
		return false
	}
	switch {
	case st.DeviceID > 0:
		fmt.Printf("  Этот компьютер уже зарегистрирован на сервере (устройство #%d).\n", st.DeviceID)
		fmt.Printf("  Сервер: %s\n\n", cfg.ServerURL)
		if !wincon.AskYesNo("  Изменить настройки агента?") {
			fmt.Println("\n  Ничего не меняю. Проверить связь: agent.exe -check")
			return false
		}
		fmt.Println()
	case settingsSource != sourceDefault:
		fmt.Printf("  Настройки уже есть (%s), сервер: %s\n", settingsSource, serverURL)
		fmt.Println("  Но устройство ещё не зарегистрировано — возможно, код не подошёл.")
		fmt.Println()
	}
	return true
}

// applySetup ставит агента с собранными значениями, запросив права у Windows.
func applySetup(server, code string) bool {
	transfer, keep, ok := confirmRegistrationChange(instdir.Path(), server)
	if !ok {
		return false
	}
	if !winsvc.Elevated() {
		fmt.Println("\n  Запрашиваю права администратора...")
		// Значения передаются запущенной копии: спрашивать их второй раз,
		// уже в другом окне, незачем.
		args := []string{"-install", "-server=" + server, "-token=" + code}
		if transfer {
			args = append(args, "-transfer")
		}
		if keep {
			args = append(args, "-keep-registration")
		}
		started, err := wincon.Elevate(args...)
		if err != nil {
			fmt.Println("\n  ОШИБКА:", err)
			return false
		}
		if started {
			return true // работу продолжит запущенная с правами копия
		}
	}
	if err := installAgent(server, code, transfer, keep); err != nil {
		fmt.Println("\n  ОШИБКА:", err)
		return false
	}
	return true
}

// runInteractiveSetup вызывается из main при запуске двойным щелчком.
func runInteractiveSetup() {
	// Настройки установленного агента доступны администраторам и SYSTEM.
	// Получаем права до диалога: запуск скачанного файла должен увидеть
	// прежнюю регистрацию в постоянном каталоге, а не только рядом с собой.
	if !winsvc.Elevated() {
		fmt.Println("\n  Запрашиваю права администратора для установки...")
		started, err := wincon.Elevate("-setup")
		if err != nil {
			fmt.Println("\n  ОШИБКА:", err)
			wincon.Hold()
			return
		}
		if started {
			return
		}
	}
	fmt.Println()
	fmt.Println("  ──────────────────────────────────────────────────────────")
	fmt.Println("  NetAdmin — установка агента")
	fmt.Println("  ──────────────────────────────────────────────────────────")
	fmt.Println()

	if confirmReconfigure() {
		// Вшитые в файл значения предлагаем как есть. Настройки из файла рядом
		// или из окружения не предлагаем: там агент уже настроен, и раз человек
		// запустил установку, он пришёл что-то изменить.
		var srv, code string
		if settingsSource == sourceBaked {
			srv, code = rawServerURL, token
		}
		if server, code, ok := askSetup(srv, code); ok {
			applySetup(server, code)
		}
	}
	wincon.Hold()
	os.Exit(0)
}

// confirmRegistrationChange distinguishes an address change from a transfer.
// Neither DNS nor the enrollment code proves these are the same database.
func confirmRegistrationChange(dir, server string) (transfer, keep, ok bool) {
	cfg, st, err := readInstallIdentity(dir)
	if err != nil {
		fmt.Println("\n  ОШИБКА:", err)
		return false, false, false
	}
	if st.DeviceID == 0 && st.DeviceToken == "" {
		return false, false, true
	}
	target, err := installServerURL(server)
	if err != nil {
		fmt.Println("\n  ОШИБКА:", err)
		return false, false, false
	}
	previous, err := installServerURL(cfg.ServerURL)
	if err == nil && previous == target {
		return false, false, true
	}
	fmt.Printf("\n  Прежний сервер: %s\n  Новый адрес:    %s\n", cfg.ServerURL, target)
	fmt.Println("  1 — тот же сервер, изменился только адрес: сохранить регистрацию.")
	fmt.Println("  2 — другой сервер: сохранить копию прежней регистрации и получить новую.")
	choice, accepted := wincon.AskLine("  Выберите 1 или 2; Enter — отмена: ")
	if accepted {
		switch strings.TrimSpace(choice) {
		case "1":
			return false, true, true
		case "2":
			return true, false, true
		}
	}
	fmt.Println("\n  Отменено. Прежняя регистрация сохранена.")
	return false, false, false
}
