package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"netadmin/internal/agentbin"
	"netadmin/internal/installtxn"
	"netadmin/internal/instdir"
	"netadmin/internal/tz"
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
	prior, err := winsvc.State(serviceName)
	if err != nil {
		return err
	}
	dataSetting, err := winsvc.Environment(serviceName, "NETADMIN_DATA_DIR")
	if err != nil {
		return err
	}
	dataDir, err := serverDataDir(dir, dataSetting)
	if err != nil {
		return err
	}
	// A running upgraded service reports the environment it actually received
	// from SCM. Refuse a changed registry path until that change is applied:
	// guessing would snapshot the wrong database before candidate migration.
	if prior == winsvc.StateRunning {
		var live serverRuntime
		if b, readErr := os.ReadFile(filepath.Join(dir, "server_runtime.json")); readErr == nil && json.Unmarshal(b, &live) == nil {
			pid, pidErr := winsvc.ProcessID(serviceName)
			if pidErr == nil && live.ProcessID == pid && live.DataDir != "" && !samePath(live.DataDir, dataDir) {
				return fmt.Errorf("каталог данных работающей службы %s отличается от машинной настройки %s; сначала примените смену каталога и перезапустите службу, затем обновляйте", live.DataDir, dataDir)
			}
		}
	}
	if _, err := os.Stat(filepath.Join(dataDir, "netadmin.db.restore")); err == nil {
		return fmt.Errorf("ожидается восстановление базы: сначала перезапустите установленный сервер или отмените восстановление в настройках, затем обновляйте")
	} else if !os.IsNotExist(err) {
		return err
	}
	if _, err := installedServerHealthURL(dataDir); err != nil {
		return err
	}
	service := winsvc.Config{
		Name:        serviceName,
		DisplayName: serviceDisplayName,
		Description: serviceDescription,
		Exe:         dst,
	}
	guard, err := json.Marshal(struct {
		DataDir string `json:"data_dir"`
	}{dataDir})
	if err != nil {
		return err
	}
	files := []installtxn.File{
		{Path: filepath.Join(dir, serverInstallGuardName), Data: guard, Mode: 0o600},
		{Path: filepath.Join(dir, "server_runtime.json"), Snapshot: true},
	}
	if !samePath(src, dst) {
		files = append(files, installtxn.File{Path: dst, Source: src, Mode: 0o755})
	}
	// Startup can migrate the database and create settings even when binding
	// the HTTP port later fails. Preserve the stopped SQLite files together.
	for _, name := range []string{"netadmin.db", "netadmin.db-wal", "netadmin.db-shm", "config.json"} {
		files = append(files, installtxn.File{Path: filepath.Join(dataDir, name), Snapshot: true})
	}
	fmt.Println("Подготавливаю установку; прежняя версия будет возвращена при ошибке запуска.")
	var readyURL string
	var restoreConfig func() error
	captured := false
	startAttempted := false
	if err := installtxn.Apply(files, installtxn.Hooks{
		Stop: func() error {
			if !captured {
				var err error
				prior, err = winsvc.State(serviceName)
				if err != nil {
					return err
				}
				restoreConfig, err = winsvc.CaptureConfig(serviceName)
				if err != nil {
					return err
				}
				captured = true
			}
			return winsvc.Stop(serviceName)
		},
		Start: func() error {
			startAttempted = true
			return winsvc.Install(service)
		},
		Verify: func() error {
			var err error
			readyURL, err = waitInstalledServerHealth(dir, dataDir)
			return err
		},
		Recover: func() error {
			if !captured {
				return nil
			}
			if prior == winsvc.StateNotInstalled {
				if startAttempted {
					return winsvc.Uninstall(serviceName)
				}
				return nil
			}
			if restoreConfig != nil {
				if err := restoreConfig(); err != nil {
					return err
				}
			}
			if prior == winsvc.StateRunning {
				return winsvc.Start(serviceName)
			}
			return nil
		},
	}); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(dir, serverInstallGuardName)); err != nil {
		log.Printf("уборка отметки завершённой установки: %v", err)
	}

	panelURL := strings.TrimSuffix(readyURL, "healthz")
	if err := writeShortcut(panelURL); err != nil {
		log.Printf("ярлык на рабочем столе не создан: %v", err) // не повод считать установку неудачной
	}

	fmt.Println("Служба NetAdmin установлена; веб-интерфейс и база подтвердили готовность.")
	fmt.Printf("  Версия:             %s\n", version.Full())
	fmt.Printf("  Программа:          %s\n", dir)
	fmt.Printf("  База и настройки:   %s\n", dataDir)
	if tightened {
		fmt.Println("  Доступ к каталогу ограничен SYSTEM и администраторами (был открыт).")
	}
	fmt.Printf("  Журнал службы:      %s\n", logPath())
	fmt.Printf("  Веб-интерфейс:      %s\n", panelURL)
	if agentbin.Available() {
		fmt.Println("  Агент для рабочих станций уже внутри — загружать его не нужно.")
	}
	fmt.Println()

	address, _ := url.Parse(panelURL) // verified URL contains a validated port
	applyFirewall(firewall, address.Port())

	fmt.Println()
	fmt.Println("Состояние: netadmin.exe -status     Удалить: netadmin.exe -uninstall")
	if ownsConsole() && os.Getenv("NETADMIN_NO_BROWSER") == "" {
		openBrowser(panelURL)
	}
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
func applyFirewall(choice firewallChoice, port string) {
	open := choice == firewallYes
	switch choice {
	case firewallNo:
		fmt.Printf("Порт %s в брандмауэре не открыт — агенты с других машин не подключатся.\n", port)
		fmt.Println("Открыть позже: netadmin.exe -install -firewall")
		return
	case firewallAsk:
		fmt.Println("Чтобы агенты с других компьютеров достучались до сервера, нужно открыть")
		fmt.Printf("порт %s в брандмауэре Windows — только для частной сети и только для\n", port)
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
	fmt.Printf("Правило «NetAdmin (LAN)» создано: TCP %s, частная сеть, локальная подсеть.\n", port)
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
	fmt.Printf("  Время:   %s\n", tz.Label())
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

func writeShortcut(url string) error {
	return os.WriteFile(shortcutPath(), []byte(shortcutBodyForURL(serviceExePath(), url)), 0o644)
}

// shortcutBody — содержимое ярлыка.
//
// Значок задан явно: без IconFile Windows рисует .url значком браузера по
// умолчанию, и NetAdmin лежит на рабочем столе неотличимо от случайной
// закладки. Берём его из установленного .exe — значок там уже есть
// (см. cmd/icongen), класть рядом отдельный .ico не нужно.
func shortcutBody(exe string) string {
	return shortcutBodyForURL(exe, "http://127.0.0.1:8765/")
}

func shortcutBodyForURL(exe, url string) string {
	return "[InternetShortcut]\r\n" +
		"URL=" + url + "\r\n" +
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
