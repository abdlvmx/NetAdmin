package main

import (
	"fmt"
	"strings"

	"netadmin/internal/config"
	"netadmin/internal/demo"
	"netadmin/internal/netaccess"
	"netadmin/internal/tz"
	"netadmin/internal/version"
	"netadmin/internal/wincon"
)

// Запуск двойным щелчком.
//
// Демонстрационный режим — лучшее, что можно показать человеку, который скачал
// один файл и хочет посмотреть, — до сих пор запускался только флагом из
// командной строки. То есть был спрятан ровно от тех, для кого делался: обычный
// пользователь консоль не открывает. Поэтому запуск без аргументов из
// собственного окна спрашивает, чего человек хочет.
//
// Заодно исчезает и запрос брандмауэра: демо слушает только петлю, и Windows
// про доступ к сети не спрашивает вовсе.

type firstRunChoice int

const (
	choiceSetup   firstRunChoice = iota // обычный запуск, настройка для организации
	choiceDemo                          // витрина на вымышленных данных
	choiceInstall                       // установка службой
	choiceQuit
)

// askFirstRun показывает выбор и возвращает решение. Пустой ввод — демо: тот,
// кто просто жмёт Enter, хочет посмотреть, а не настраивать.
func askFirstRun() firstRunChoice {
	fmt.Println()
	fmt.Println("  NetAdmin — учёт и мониторинг сети")
	fmt.Println()
	fmt.Println("  1  Посмотреть на примере — вымышленные данные, вашу сеть не трогаем")
	fmt.Println("  2  Настроить для своей организации")
	fmt.Println("  3  Установить службой, чтобы работал постоянно")
	fmt.Println("  0  Выход")
	fmt.Println()
	fmt.Print("  Ваш выбор [1]: ")

	line, ok := wincon.AskLine("")
	if !ok {
		fmt.Println()
		return choiceDemo // читать не у кого — показываем демо, оно безопасно
	}
	switch strings.TrimSpace(line) {
	case "", "1":
		return choiceDemo
	case "2":
		return choiceSetup
	case "3":
		return choiceInstall
	case "0":
		return choiceQuit
	}
	fmt.Println("  Непонятный выбор — показываю пример.")
	return choiceDemo
}

// bannerWidth — ширина отчёркивания в приветствии.
const bannerWidth = 66

func bannerRule() { fmt.Println("  " + strings.Repeat("─", bannerWidth)) }

// printDemoBanner — что видит человек, выбравший «посмотреть».
func printDemoBanner(port string) {
	fmt.Println()
	bannerRule()
	fmt.Println("  NetAdmin — демонстрационный режим")
	bannerRule()
	fmt.Println()
	fmt.Printf("  Версия:    %s\n", version.Full())
	fmt.Printf("  Откройте:  http://127.0.0.1:%s\n", port)
	fmt.Printf("  Вход:      %s  /  %s\n", demo.AdminUser, demo.AdminPassword)
	fmt.Println()
	fmt.Println("  Все устройства, сотрудники и заявки вымышлены. Ваша сеть не")
	fmt.Println("  сканируется, письма не отправляются, база временная и удалится.")
	fmt.Println()
	fmt.Println("  Понравилось? Установите для своей организации:")
	fmt.Println("      netadmin.exe -install")
	fmt.Println()
	fmt.Println("  Остановить — Ctrl+C. Пока смотрите, окно не закрывайте.")
	fmt.Println()
}

// printServerBanner — что видит человек, запустивший сервер по-настоящему,
// но из консоли, а не службой.
//
// Раньше здесь печатались строки журнала с отметками времени: работающий
// сервер выглядел как отладочный вывод, и было неочевидно даже то, что окно
// закрывать нельзя.
func printServerBanner(port string, allow netaccess.List, allowSource string) {
	fmt.Println()
	bannerRule()
	fmt.Println("  NetAdmin работает")
	bannerRule()
	fmt.Println()
	fmt.Printf("  Версия:    %s\n", version.Full())
	fmt.Printf("  Время:     %s\n", tz.Label())
	fmt.Printf("  Откройте:  http://127.0.0.1:%s\n", port)

	lan, public := splitAddrs()
	for i, ip := range lan {
		label := "  Агентам:  "
		if i > 0 {
			label = "            "
		}
		fmt.Printf("%shttp://%s:%s\n", label, ip, port)
	}
	fmt.Println()
	// Полный перечень подсетей по умолчанию — восемь диапазонов с масками:
	// человеку, который просто смотрит продукт, эта строка ничего не сообщает,
	// кроме того, что тут всё сложно.
	if allowSource == config.SourceDefault {
		fmt.Println("  Доступ разрешён из: локальные и частные сети")
	} else {
		fmt.Printf("  Доступ разрешён из: %s (%s)\n", allow, allowSource)
	}
	if allow.Unrestricted() {
		fmt.Println()
		fmt.Println("  ВНИМАНИЕ: ограничение по подсетям снято, сервер обслуживает любые")
		fmt.Println("  адреса. Канал не шифруется — так можно только в доверенной сети.")
	}
	for _, ip := range public {
		fmt.Println()
		fmt.Printf("  ВНИМАНИЕ: на интерфейсе публичный адрес %s. Закройте порт %s\n", ip, port)
		fmt.Println("  брандмауэром — продукт не предназначен для работы из интернета.")
	}
	fmt.Println()
	fmt.Println("  Не закрывайте это окно: сервер работает, пока оно открыто.")
	fmt.Println("  Остановить — Ctrl+C.")
	fmt.Println()
	fmt.Println("  Чтобы работал постоянно и запускался сам:")
	fmt.Println("      netadmin.exe -install")
	fmt.Println()
}
