package main

import (
	"crypto/sha256"
	"encoding/hex"
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
	"netadmin/internal/instdir"
	"netadmin/internal/version"
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
//
// Каталог общий с агентом, поэтому и путь, и права на него живут в одном месте.
func installDir() string { return instdir.Path() }

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
	// Каталог заводится с явным списком доступа. Унаследованные права
	// C:\ProgramData позволяют обычному пользователю положить сюда файл, а
	// созданное отдают ему в полное распоряжение — этого хватает, чтобы
	// подменить файл службы, работающей от LocalSystem.
	dir := installDir()
	tightened, err := instdir.Secure(dir)
	if err != nil {
		return err
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
	fmt.Printf("  Версия:             %s\n", version.Full())
	fmt.Printf("  Программа и данные: %s\n", dir)
	if tightened {
		fmt.Println("  Доступ к каталогу ограничен SYSTEM и администраторами (был открыт).")
	}
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
	// Версия печатается и у неустановленной службы: это версия файла, который
	// сейчас запустили, и вопрос «что у меня за сборка» от установки не зависит.
	fmt.Printf("  Версия:  %s\n", version.Full())
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
	// Первой строкой — какая это сборка. Журнал службы — единственный след
	// происходившего, и разбирать его, не зная версии, значит гадать, к какому
	// коду относятся сообщения. Заодно строка отмечает границу перезапуска.
	log.Printf("NetAdmin %s запускается", version.Full())
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
	return os.WriteFile(shortcutPath(), []byte(shortcutBody(serviceExePath())), 0o644)
}

// shortcutBody — содержимое ярлыка.
//
// Значок задан явно: без IconFile Windows рисует .url значком браузера по
// умолчанию, и NetAdmin лежит на рабочем столе неотличимо от случайной
// закладки. Берём его из установленного .exe — значок там уже есть
// (см. cmd/icongen), класть рядом отдельный .ico не нужно.
func shortcutBody(exe string) string {
	return "[InternetShortcut]\r\n" +
		"URL=http://127.0.0.1:8765/\r\n" +
		"IconFile=" + exe + "\r\n" +
		"IconIndex=0\r\n"
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
		data, sum, ok := agentbin.Bytes()
		if !ok {
			return "", fmt.Errorf("этот сервер собран без встроенного агента")
		}

		// Каталог установки закрыт для всех, кроме SYSTEM и администраторов —
		// туда же через секунду встанет и сам агент.
		dir := installDir()
		if _, err := instdir.Secure(dir); err != nil {
			return "", err
		}
		exe, cleanup, err := stageAgent(dir, data, sum)
		if err != nil {
			return "", err
		}
		defer cleanup()

		out, err := exec.Command(exe, "-install", "-server="+serverURL, "-token="+token).CombinedOutput()
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

// stageAgent кладёт сборку агента в каталог, куда не может писать обычный
// пользователь, и сверяет записанное перед запуском. Возвращает путь и уборку.
//
// Раньше файл писался в os.TempDir() под постоянным именем. У службы это
// C:\Windows\Temp — каталог, доступный на запись всем: занятый заранее файл
// остаётся во владении того, кто его создал, и подменить содержимое между
// записью и запуском ему ничто не мешало. Запускается же файл от LocalSystem.
func stageAgent(dir string, data []byte, sum string) (string, func(), error) {
	work, err := os.MkdirTemp(dir, "agent-setup-")
	if err != nil {
		return "", nil, fmt.Errorf("каталог для установки агента: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(work) }

	exe := filepath.Join(work, "agent.exe")
	// O_EXCL: имя каждый раз новое, и файла с ним быть не должно. Если он всё
	// же есть — это не наш файл, и открывать его на запись нельзя.
	f, err := os.OpenFile(exe, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
	if err != nil {
		cleanup()
		return "", nil, fmt.Errorf("файл агента: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		cleanup()
		return "", nil, fmt.Errorf("запись файла агента: %w", err)
	}
	if err := f.Close(); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("запись файла агента: %w", err)
	}

	// Сумма уже посчитана в agentbin и прежде просто отбрасывалась. Между
	// записью и запуском файл меняет не только злоумышленник: антивирус вправе
	// вырезать или подменить его, и без проверки это выглядело бы как
	// необъяснимый отказ установки.
	if err := verifyFileSum(exe, sum); err != nil {
		cleanup()
		return "", nil, err
	}
	return exe, cleanup, nil
}

// verifyFileSum сверяет SHA-256 файла с ожидаемой.
func verifyFileSum(path, want string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("проверка файла агента: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("проверка файла агента: %w", err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return fmt.Errorf("файл агента не совпал с контрольной суммой: получено %s, ожидалось %s.\n"+
			"Файл изменился между записью и запуском — проверьте антивирус и повторите.", got, want)
	}
	return nil
}
