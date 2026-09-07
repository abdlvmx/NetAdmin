//go:build windows

package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"netadmin/internal/instdir"
	"netadmin/internal/winsvc"
)

// Установка агента без .bat-файла.
//
// Раньше на каждую машину нужно было принести два файла (agent.exe и
// install_agent.bat) и запустить второй от администратора. Теперь всё делает
// сам агент: копирует себя в постоянный каталог, записывает настройки и
// регистрируется службой. Служба, а не задача планировщика, — чтобы упавший
// агент поднимался сам, а не лежал до перезагрузки.
const (
	agentServiceName    = "NetAdminAgent"
	agentServiceDisplay = "NetAdmin Agent"
	agentServiceDesc    = "Агент NetAdmin: метрики и инвентарь ПО, служб, автозагрузки и задач."
)

// agentInstallDir — каталог установки, общий с сервером: агент обслуживает в
// том числе машину сервера, и два каталога значили бы два места, где искать
// настройки и состояние.
func agentInstallDir() string { return instdir.Path() }

func agentExePath() string { return filepath.Join(agentInstallDir(), "agent.exe") }

// installAgent ставит агента службой. Пустые server/token берутся из настроек,
// уже лежащих в каталоге установки: так переустановка поверх (обновление
// версии) не требует заново указывать адрес и токен.
func installAgent(server, tok string) error {
	if !winsvc.Elevated() {
		return fmt.Errorf("нужны права администратора: откройте PowerShell «от имени администратора» и повторите")
	}

	// Явный список доступа вместо унаследованного от C:\ProgramData: там
	// обычный пользователь может создать файл и получить на него полные права,
	// а рядом лежат enrollment-токен и персональный токен устройства.
	dir := agentInstallDir()
	tightened, err := instdir.Secure(dir)
	if err != nil {
		return err
	}
	existing := loadAgentConfigFrom(dir)

	if server == "" {
		server = existing.ServerURL
	}
	if server == "" {
		return fmt.Errorf("не указан адрес сервера: agent.exe -install -server=http://192.168.1.10:8765 -token=…\n" +
			"адрес и токен показывает страница «Настройки» на сервере")
	}
	if tok == "" {
		tok = existing.EnrollToken
	}
	// Токен нужен только для первой регистрации: если устройство уже
	// зарегистрировано, у него есть персональный токен в agent_state.json,
	// и требовать enrollment-токен при обновлении версии незачем.
	if tok == "" {
		if _, err := os.Stat(filepath.Join(dir, "agent_state.json")); err != nil {
			return fmt.Errorf("не указан enrollment-токен: agent.exe -install -server=… -token=ТОКЕН\n" +
				"токен показывает страница «Настройки» на сервере")
		}
	}

	src, err := os.Executable()
	if err != nil {
		return fmt.Errorf("путь к текущему файлу: %w", err)
	}
	dst := agentExePath()

	// Файл работающей службы Windows подменить не даёт — сначала остановка.
	if err := winsvc.Stop(agentServiceName); err != nil {
		return err
	}
	if !samePath(src, dst) {
		if err := copyFile(src, dst); err != nil {
			return fmt.Errorf("копирование в %s: %w", dst, err)
		}
	}

	if err := saveAgentConfigTo(dir, agentConfig{ServerURL: server, EnrollToken: tok}); err != nil {
		return fmt.Errorf("запись настроек: %w", err)
	}

	// Установка поверх старого агента из install_agent.bat: задача планировщика
	// с тем же именем подняла бы вторую копию рядом со службой.
	removeLegacyTask()

	if err := winsvc.Install(winsvc.Config{
		Name:        agentServiceName,
		DisplayName: agentServiceDisplay,
		Description: agentServiceDesc,
		Exe:         dst,
	}); err != nil {
		return err
	}

	fmt.Println("Агент NetAdmin установлен и запущен.")
	fmt.Printf("  Сервер:    %s\n", normalizeServerURL(server))
	fmt.Printf("  Каталог:   %s\n", dir)
	if tightened {
		fmt.Println("  Доступ к каталогу ограничен SYSTEM и администраторами (был открыт).")
	}
	fmt.Println()
	fmt.Println("Если устройство не появится на сервере в течение минуты:")
	fmt.Printf("  \"%s\" -check\n", dst)
	return nil
}

// uninstallAgent снимает службу и убирает файлы агента.
//
// Каталог целиком не удаляется: на машине с сервером в нём же лежит база
// NetAdmin, и rmdir /S снёс бы её вместе с агентом.
func uninstallAgent() error {
	if !winsvc.Elevated() {
		return fmt.Errorf("нужны права администратора: откройте PowerShell «от имени администратора» и повторите")
	}
	if err := winsvc.Uninstall(agentServiceName); err != nil {
		return err
	}
	removeLegacyTask()

	dir := agentInstallDir()
	for _, name := range []string{"agent_config.json", "agent_state.json", "agent.exe"} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !os.IsNotExist(err) {
			// agent.exe может быть занят, если удаление запущено из него же —
			// это нормально, файл уберёт следующая установка
			fmt.Printf("  не удалось удалить %s: %v\n", name, err)
		}
	}
	fmt.Println("Агент NetAdmin удалён.")
	return nil
}

// removeLegacyTask убирает задачу планировщика от install_agent.bat.
func removeLegacyTask() {
	cmd := exec.Command("schtasks", "/delete", "/tn", agentServiceName, "/f")
	hideWindow(cmd)
	_ = cmd.Run() // задачи может не быть — это обычный случай
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

// logMaxBytes — при каком размере журнал службы уезжает в .old.
const logMaxBytes = 5 << 20

// agentLogPath — журнал агента, работающего службой.
func agentLogPath() string { return filepath.Join(agentInstallDir(), "agent.log") }

// startServiceLog переводит журнал в файл.
//
// У службы нет консоли: всё, что агент пишет, до сих пор уходило в никуда.
// Когда служба падала, в системном журнале оставалось только «terminated
// unexpectedly» — ни причины, ни строки от самого агента. Разобраться было
// нечем, и это ровно тот случай, ради которого журнал и нужен.
func startServiceLog() {
	path := agentLogPath()
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
