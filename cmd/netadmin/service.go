package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"netadmin/internal/agentbin"
	"netadmin/internal/winsvc"
)

// Имя и описание службы. Имя видно в services.msc и в `sc query`, поэтому
// меняться между версиями не должно: иначе обновление заведёт вторую службу
// вместо замены первой.
const (
	serviceName        = "NetAdmin"
	serviceDisplayName = "NetAdmin — учёт и мониторинг сети"
	serviceDescription = "Сервер NetAdmin: веб-интерфейс, приём данных от агентов, " +
		"мониторинг сервисов и портал заявок."
	// logMaxBytes — при каком размере журнал службы уезжает в .old.
	// У службы нет консоли, журнал — единственный способ понять, что случилось,
	// но и расти без предела он не должен.
	logMaxBytes = 5 << 20
)

// installDir — постоянный каталог службы. Данные должны лежать в предсказуемом
// месте, а не там, откуда человек запустил файл: скачанный в «Загрузки» .exe
// заводил базу прямо в «Загрузках», а положенный в Program Files не мог
// записать её вовсе.
func installDir() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "NetAdmin")
}

func serviceExePath() string { return filepath.Join(installDir(), "netadmin.exe") }

// installServer копирует сервер в постоянный каталог и регистрирует службу.
func installServer(firewall firewallChoice) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("установка службой доступна только в Windows")
	}

	src, err := os.Executable()
	if err != nil {
		return fmt.Errorf("путь к текущему файлу: %w", err)
	}
	dir := installDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("каталог %s: %w", dir, err)
	}
	dst := serviceExePath()

	if !samePath(src, dst) {
		// Служба могла работать из целевого файла — подменить его на ходу
		// Windows не даст, поэтому сначала останавливаем.
		if err := winsvc.Stop(serviceName); err != nil {
			return err
		}
		if err := copyFile(src, dst); err != nil {
			return fmt.Errorf("копирование в %s: %w", dst, err)
		}
	}

	if err := winsvc.Install(winsvc.Config{
		Name:        serviceName,
		DisplayName: serviceDisplayName,
		Description: serviceDescription,
		Exe:         dst,
	}); err != nil {
		return err
	}

	if err := writeShortcut(); err != nil {
		log.Printf("ярлык на рабочем столе не создан: %v", err) // не повод считать установку неудачной
	}

	fmt.Println("Служба NetAdmin установлена и запущена.")
	fmt.Printf("  Программа и данные: %s\n", dir)
	fmt.Printf("  Журнал службы:      %s\n", logPath())
	fmt.Println("  Веб-интерфейс:      http://127.0.0.1:8765")
	if agentbin.Available() {
		fmt.Println("  Агент для рабочих станций уже внутри — загружать его не нужно.")
	}
	fmt.Println()

	applyFirewall(firewall)

	fmt.Println()
	fmt.Println("Состояние: netadmin.exe -status     Удалить: netadmin.exe -uninstall")
	return nil
}

// firewallChoice — что делать с правилом брандмауэра при установке.
type firewallChoice int

const (
	firewallAsk firewallChoice = iota // спросить (запуск двойным щелчком)
	firewallYes                       // открыть без вопросов (-firewall)
	firewallNo                        // не трогать (-no-firewall)
)

// applyFirewall открывает порт панели, спросив разрешения.
//
// Молча менять правила брандмауэра установщик не должен: это настройка
// безопасности машины, и решать её человеку. Поэтому по умолчанию — вопрос,
// а для раскатки скриптом есть флаги -firewall и -no-firewall.
//
// Параметры правила повторяют deploy/firewall_server.bat: канал не шифруется,
// и открывать порт шире локального сегмента нельзя.
func applyFirewall(choice firewallChoice) {
	const port = "8765"

	open := choice == firewallYes
	switch choice {
	case firewallNo:
		fmt.Println("Порт 8765 в брандмауэре не открыт — агенты с других машин не подключатся.")
		fmt.Println("Открыть позже: netadmin.exe -install -firewall")
		return
	case firewallAsk:
		fmt.Println("Чтобы агенты с других компьютеров достучались до сервера, нужно открыть")
		fmt.Println("порт 8765 в брандмауэре Windows — только для частной сети и только для")
		fmt.Println("вашей локальной подсети.")
		open = askYesNo("Открыть порт 8765 сейчас?")
	}

	if !open {
		fmt.Println("Порт не открыт. Открыть позже: netadmin.exe -install -firewall")
		return
	}
	if err := openFirewallPort(port); err != nil {
		fmt.Printf("Не удалось создать правило брандмауэра: %v\n", err)
		fmt.Println("Откройте порт вручную скриптом deploy/firewall_server.bat")
		return
	}
	fmt.Println("Правило «NetAdmin (LAN)» создано: TCP 8765, частная сеть, локальная подсеть.")
	if !privateProfileActive() {
		fmt.Println()
		fmt.Println("ВНИМАНИЕ: ни одно подключение не отнесено к «Частной сети», поэтому правило")
		fmt.Println("не действует. Параметры → Сеть и Интернет → свойства подключения → Частная сеть.")
	}
}

// uninstallServer удаляет службу, оставляя базу и настройки на месте: снос
// накопленных данных вместе со службой — не то, чего ждут от -uninstall.
func uninstallServer() error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("служба Windows на этой системе не используется")
	}
	if err := winsvc.Uninstall(serviceName); err != nil {
		return err
	}
	_ = os.Remove(shortcutPath())

	fmt.Println("Служба NetAdmin остановлена и удалена.")
	fmt.Printf("Данные остались в %s — удалите каталог вручную, если они больше не нужны.\n", installDir())
	return nil
}

func printServerStatus() error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("служба Windows на этой системе не используется")
	}
	state, err := winsvc.State(serviceName)
	if err != nil {
		return err
	}
	fmt.Printf("Служба %s: %s\n", serviceName, state)
	if state == winsvc.StateNotInstalled {
		fmt.Println("Установить: netadmin.exe -install (от имени администратора)")
		return nil
	}
	fmt.Printf("  Каталог: %s\n", installDir())
	fmt.Printf("  Журнал:  %s\n", logPath())
	fmt.Println("  Интерфейс: http://127.0.0.1:8765")
	return nil
}

func logPath() string { return filepath.Join(installDir(), "netadmin.log") }

// startServiceLog переводит журнал в файл. У службы нет консоли: без этого
// причина неудачного старта не видна нигде, и остаётся только гадать.
func startServiceLog() {
	path := logPath()
	if st, err := os.Stat(path); err == nil && st.Size() > logMaxBytes {
		_ = os.Remove(path + ".old")
		_ = os.Rename(path, path+".old")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return // писать некуда — работаем без журнала, но не падаем
	}
	log.SetOutput(f)
}

// shortcutPath — ярлык на общем рабочем столе. Формат .url выбран вместо .lnk
// намеренно: .lnk пришлось бы собирать через COM, а .url — обычный текстовый
// файл, который Windows открывает браузером по умолчанию.
func shortcutPath() string {
	pub := os.Getenv("PUBLIC")
	if pub == "" {
		pub = `C:\Users\Public`
	}
	return filepath.Join(pub, "Desktop", "NetAdmin.url")
}

func writeShortcut() error {
	body := "[InternetShortcut]\r\nURL=http://127.0.0.1:8765/\r\n"
	return os.WriteFile(shortcutPath(), []byte(body), 0o644)
}

func samePath(a, b string) bool {
	aa, err1 := filepath.Abs(a)
	bb, err2 := filepath.Abs(b)
	if err1 != nil || err2 != nil {
		return false
	}
	// пути Windows регистронезависимы
	return strings.EqualFold(filepath.Clean(aa), filepath.Clean(bb))
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// restartServer останавливает и снова запускает службу. Отдельная команда
// нужна потому, что перезапустить себя изнутри служба не может: процесс,
// вызвавший Stop, будет остановлен вместе с ней.
func restartServer() error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("служба Windows на этой системе не используется")
	}
	// Пауза даёт вызвавшей стороне (странице настроек) дописать ответ до того,
	// как сервер уйдёт на перезапуск.
	time.Sleep(2 * time.Second)
	if err := winsvc.Restart(serviceName); err != nil {
		return err
	}
	fmt.Println("Служба NetAdmin перезапущена.")
	return nil
}

// serverRestarter возвращает функцию перезапуска для интерфейса — или nil,
// если сервер запущен не службой и перезапускать его должен человек.
func serverRestarter() func() error {
	if !winsvc.IsService() {
		return nil
	}
	return func() error {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		// Запускаем отдельный процесс: он переживёт остановку службы и сам же
		// поднимет её обратно.
		cmd := exec.Command(exe, "-restart")
		if err := cmd.Start(); err != nil {
			return err
		}
		go func() { _ = cmd.Wait() }() // не оставляем зомби, результат неважен
		return nil
	}
}

// localAgentInstaller ставит встроенного агента на эту же машину.
//
// Самый частый первый шаг — начать наблюдать за машиной, где стоит сервер.
// Раньше для этого приходилось скачивать агента, открывать консоль от
// администратора и вставлять команду — при том, что сервер и права, и файл
// агента уже имеет.
func localAgentInstaller() func(serverURL, token string) (string, error) {
	// nil означает «возможности нет», и кнопка на странице не появляется.
	// Мёртвая кнопка, которая всегда отвечает отказом, хуже её отсутствия:
	// сервер без прав (запуск из консоли обычным пользователем) поставить
	// службу агента всё равно не сможет.
	if runtime.GOOS != "windows" || !winsvc.Elevated() || !agentbin.Available() {
		return nil
	}
	return func(serverURL, token string) (string, error) {
		data, _, ok := agentbin.Bytes()
		if !ok {
			return "", fmt.Errorf("этот сервер собран без встроенного агента")
		}

		tmp := filepath.Join(os.TempDir(), "netadmin-agent-setup.exe")
		if err := os.WriteFile(tmp, data, 0o700); err != nil {
			return "", fmt.Errorf("запись файла агента: %w", err)
		}
		defer os.Remove(tmp)

		out, err := exec.Command(tmp, "-install", "-server="+serverURL, "-token="+token).CombinedOutput()
		text := strings.TrimSpace(string(out))
		if err != nil {
			if text == "" {
				return "", err
			}
			return "", fmt.Errorf("%s", text)
		}
		return text, nil
	}
}
