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
	"time"

	"netadmin/internal/agentstatus"
	"netadmin/internal/installtxn"
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
func installAgent(server, tok string, transfer, keepRegistration bool) error {
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
	src, err := os.Executable()
	if err != nil {
		return fmt.Errorf("путь к текущему файлу: %w", err)
	}
	dst := agentExePath()
	copySource := src
	if samePath(src, dst) {
		// Windows не позволяет заменить EXE самого установщика. При запуске
		// из постоянного каталога меняются только настройки и регистрация.
		copySource = ""
	}
	plan, err := planAgentInstall(dir, copySource, server, tok, transfer, keepRegistration, time.Now())
	if err != nil {
		return err
	}
	fmt.Println("1/4 Проверяю файл агента и доступность сервера...")
	if err := checkInstallBinary(src); err != nil {
		return err
	}
	if err := checkInstallServer(plan.Config.ServerURL); err != nil {
		return err
	}
	var previous string
	restoreConfig := func() error { return nil }
	metadataCaptured := false
	service := winsvc.Config{
		Name:        agentServiceName,
		DisplayName: agentServiceDisplay,
		Description: agentServiceDesc,
		Exe:         dst,
	}
	var startedAt time.Time
	startAttempted := false
	err = installtxn.Apply(plan.Files, installtxn.Hooks{
		Stop: func() error {
			if !startAttempted {
				if err := checkInstallUpdatePending(dir); err != nil {
					return err
				}
				if !metadataCaptured {
					previous, err = winsvc.State(agentServiceName)
					if err != nil {
						return err
					}
					restoreConfig, err = winsvc.CaptureConfig(agentServiceName)
					if err != nil {
						return err
					}
					metadataCaptured = true
				}
			}
			fmt.Println("2/4 Файлы подготовлены. Останавливаю службу для установки...")
			if err := winsvc.Stop(agentServiceName); err != nil {
				return err
			}
			if !startAttempted {
				// A request may have completed while Stop was waiting for the
				// old service's last iteration. The transaction lock also keeps
				// its helper from replacing files concurrently with this install.
				return checkInstallUpdatePending(dir)
			}
			return nil
		},
		Start: func() error {
			fmt.Println("3/4 Запускаю службу агента...")
			startedAt = time.Now()
			startAttempted = true
			return winsvc.Install(service)
		},
		Verify: func() error {
			fmt.Println("4/4 Ожидаю подтверждённую регистрацию и передачу данных на сервер...")
			if err := agentstatus.Wait(dir, plan.Config.ServerURL, agentVersion, startedAt, 60*time.Second); err != nil {
				return err
			}
			pid, err := winsvc.ProcessID(agentServiceName)
			if err != nil {
				return err
			}
			status, err := agentstatus.Read(dir)
			if err != nil {
				return err
			}
			if !status.Matches(plan.Config.ServerURL, agentVersion, startedAt) || status.ProcessID != pid {
				return fmt.Errorf("подключение подтвердил другой процесс агента; проверка установленной службы не пройдена")
			}
			_, identity, err := readInstallIdentity(dir)
			if err != nil {
				return err
			}
			if identity.DeviceID != status.DeviceID || identity.DeviceToken == "" {
				return fmt.Errorf("сервер получил данные, но персональная регистрация не сохранена в agent_state.json; проверьте доступ и свободное место в %s", dir)
			}
			return nil
		},
		Recover: func() error {
			if metadataCaptured && previous != winsvc.StateNotInstalled {
				if err := restoreConfig(); err != nil {
					return err
				}
			}
			if previous == winsvc.StateRunning {
				return winsvc.Start(agentServiceName)
			}
			if previous == winsvc.StateNotInstalled && startAttempted {
				return winsvc.Uninstall(agentServiceName)
			}
			return nil
		},
	})
	if err != nil {
		return fmt.Errorf("установка агента не подтверждена: %w\nЖурнал: %s\nПроверка: \"%s\" -check", err, agentLogPath(), dst)
	}
	// Задачу прежнего установщика снимаем после подтверждённой установки:
	// сбой подготовки не должен менять способ запуска действующего агента.
	removeLegacyTask()

	fmt.Println("Агент NetAdmin установлен: регистрация подтверждена, сервер получил данные.")
	fmt.Printf("  Сервер:    %s\n", plan.Config.ServerURL)
	fmt.Printf("  Каталог:   %s\n", dir)
	if tightened {
		fmt.Println("  Доступ к каталогу ограничен SYSTEM и администраторами (был открыт).")
	}
	if plan.ArchivePath != "" {
		fmt.Printf("  Прежняя регистрация: %s\n", plan.ArchivePath)
	}
	return nil
}

func checkInstallBinary(path string) error {
	version, err := probeBinaryTimeout(path, 5*time.Second)
	if err != nil {
		return fmt.Errorf("проверка файла агента до остановки службы: %w", err)
	}
	if version != agentVersion {
		return fmt.Errorf("файл агента сообщает другую версию; действующая служба пока не остановлена")
	}
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
	for _, name := range []string{"agent_config.json", "agent_state.json", "agent_status.json", "agent_update_result.json", "agent_update.json", "agent_update.json.rejected", "agent-update-helper.exe", "agent.exe.new", "agent.exe"} {
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
