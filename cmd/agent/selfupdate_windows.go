//go:build windows

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"netadmin/internal/agentstatus"
	"netadmin/internal/edition"
	"netadmin/internal/installtxn"
	"netadmin/internal/instdir"
	"netadmin/internal/winsvc"

	"golang.org/x/sys/windows"
)

const (
	updateRequestName = "agent_update.json"
	updateResultName  = "agent_update_result.json"
	updateHelperName  = "agent-update-helper.exe"
	updateHealthWait  = 90 * time.Second
	versionProbeWait  = 10 * time.Second
)

type agentUpdateRequest struct {
	ExecutionKey string `json:"execution_key,omitempty"`
	TaskID       int64  `json:"task_id"`
	DeviceID     int64  `json:"device_id"`
	SHA256       string `json:"sha256"`
	FromVersion  string `json:"from_version"`
	ToVersion    string `json:"to_version"`
	ServerURL    string `json:"server_url"`
}

type agentUpdateResult struct {
	ExecutionKey string `json:"execution_key,omitempty"`
	TaskID       int64  `json:"task_id"`
	DeviceID     int64  `json:"device_id"`
	ServerURL    string `json:"server_url"`
	Status       string `json:"status"`
	Output       string `json:"output"`
	ExitCode     int    `json:"exit_code"`
}

var pendingUpdate *agentUpdateRequest

func setUpdateExecutionKey(key string) {
	if pendingUpdate != nil {
		pendingUpdate.ExecutionKey = key
	}
}
func updateHandoffPending() bool {
	return fileExists(filepath.Join(exeDir(), updateRequestName)) || fileExists(filepath.Join(exeDir(), updateResultName))
}

// Старую сборку нельзя удалять при старте: успешный запуск ещё не подтверждает,
// что новая версия смогла связаться с сервером. Резервной копией теперь владеет
// транзакция обновления, которая удаляет её только после heartbeat.
func cleanupOldBinary() {}

// selfUpdate только готовит обновление. Замена работающей службы выполняется
// отдельным процессом, а результат задачи уходит после проверки новой версии.
func selfUpdate(payload string) (status, output string, code int) {
	return selfUpdateContext(context.Background(), payload)
}

func selfUpdateContext(ctx context.Context, payload string) (status, output string, code int) {
	if !winsvc.IsService() {
		return "failed", "самообновление требует службы Windows: установите агента командой agent.exe -install; работающий агент оставлен без изменений", 1
	}
	exe, err := os.Executable()
	if err != nil || !samePath(exe, agentExePath()) {
		return "failed", "самообновление доступно для агента в штатном каталоге установки; повторите agent.exe -install", 1
	}
	dir := agentInstallDir()
	if _, err := instdir.Secure(dir); err != nil {
		return "failed", "каталог обновления: " + err.Error(), 1
	}
	if pendingUpdate != nil || fileExists(filepath.Join(dir, updateRequestName)) || fileExists(filepath.Join(dir, updateResultName)) {
		return "failed", "предыдущее обновление ещё выполняется или ожидает отправки результата", 1
	}
	var p struct {
		ID     int64  `json:"id"`
		SHA256 string `json:"sha256"`
	}
	if json.Unmarshal([]byte(payload), &p) != nil || p.ID <= 0 {
		return "failed", "некорректные данные обновления", 1
	}
	if !validUpdateHash(p.SHA256) {
		return "failed", "некорректная контрольная сумма — обновление отклонено", 1
	}
	newPath := exe + ".new"
	_ = os.Remove(newPath)
	if err := downloadPackageContext(ctx, p.ID, newPath); err != nil {
		_ = os.Remove(newPath)
		return "failed", "скачивание: " + err.Error(), 1
	}
	if err := verifyUpdateFile(newPath, p.SHA256); err != nil {
		_ = os.Remove(newPath)
		return "failed", err.Error(), 1
	}
	if err := verifyUpdateEdition(newPath); err != nil {
		_ = os.Remove(newPath)
		return "failed", err.Error(), 1
	}
	ver, err := probeBinary(newPath)
	if err != nil {
		_ = os.Remove(newPath)
		return "failed", "новая сборка не запускается: " + err.Error(), 1
	}
	// Две сборки между релизами могут иметь один номер версии: пропускаем
	// обновление только при полном совпадении файлов.
	if currentHash, err := fileSHA256(exe); err == nil && strings.EqualFold(currentHash, p.SHA256) {
		_ = os.Remove(newPath)
		return "done", "уже установлена эта сборка " + ver + ", обновление не требуется", 0
	}
	_, id := agentIdentity()
	pendingUpdate = &agentUpdateRequest{DeviceID: id, SHA256: p.SHA256, FromVersion: agentVersion,
		ToVersion: ver, ServerURL: serverURL}
	return "done", "сборка проверена; ожидается перезапуск службы и подтверждение связи", 0
}

// true означает, что результатом теперь владеет helper, а не старый агент.
func launchPendingUpdate(taskID int64) (bool, error) {
	if pendingUpdate == nil {
		return false, nil
	}
	r := *pendingUpdate
	pendingUpdate = nil
	dir := agentInstallDir()
	if taskID <= 0 {
		_ = os.Remove(agentExePath() + ".new")
		return false, errors.New("не указан идентификатор задачи обновления")
	}
	r.TaskID = taskID
	requestPath, helperPath := filepath.Join(dir, updateRequestName), filepath.Join(dir, updateHelperName)
	b, err := json.Marshal(r)
	if err != nil {
		return false, err
	}
	// O_EXCL не даёт второй задаче затереть запрос уже работающего helper.
	f, err := os.OpenFile(requestPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return false, fmt.Errorf("запись запроса обновления: %w", err)
	}
	_, writeErr := f.Write(b)
	closeErr := f.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		_ = os.Remove(requestPath)
		return false, err
	}
	failed := true
	defer func() {
		if failed {
			_ = os.Remove(requestPath)
			_ = os.Remove(agentExePath() + ".new")
		}
	}()
	if err := os.Remove(helperPath); err != nil && !os.IsNotExist(err) {
		return false, fmt.Errorf("предыдущий процесс обновления: %w", err)
	}
	if err := copyFile(agentExePath(), helperPath); err != nil {
		return false, fmt.Errorf("подготовка процесса обновления: %w", err)
	}
	cmd := exec.Command(helperPath, "-apply-update", requestPath)
	hideWindow(cmd)
	cmd.SysProcAttr.CreationFlags |= windows.CREATE_NEW_PROCESS_GROUP
	if err := cmd.Start(); err != nil {
		return false, fmt.Errorf("запуск процесса обновления: %w", err)
	}
	_ = cmd.Process.Release()
	failed = false
	log.Printf("задача #%d: обновление передано отдельному процессу", taskID)
	return true, nil
}

// Внутренняя команда принимает только собственный запрос в закрытом каталоге.
func runUpdateHelperCommand(args []string) (bool, int) {
	if len(args) == 0 || args[0] != "-apply-update" {
		return false, 0
	}
	dir := agentInstallDir()
	exe, err := os.Executable()
	if len(args) != 2 || err != nil || !samePath(exe, filepath.Join(dir, updateHelperName)) ||
		!samePath(args[1], filepath.Join(dir, updateRequestName)) || !winsvc.Elevated() {
		log.Print("некорректный запуск процесса обновления")
		return true, 1
	}
	if _, err := instdir.Secure(dir); err != nil {
		log.Printf("каталог процесса обновления: %v", err)
		return true, 1
	}
	loadSettings()
	startServiceLog()
	return true, applyPendingUpdate(dir)
}

func applyPendingUpdate(dir string) int {
	requestPath := filepath.Join(dir, updateRequestName)
	b, err := os.ReadFile(requestPath)
	var r agentUpdateRequest
	if err != nil || json.Unmarshal(b, &r) != nil || r.TaskID <= 0 || r.DeviceID <= 0 || !validUpdateHash(r.SHA256) ||
		r.ToVersion == "" || r.ServerURL != serverURL {
		log.Printf("некорректный запрос обновления: %v", err)
		// Не оставляем заблокированными будущие обновления. Запрос сохраняется
		// для диагностики, а работающая прежняя служба остаётся без изменений.
		if err := os.Rename(requestPath, requestPath+".rejected"); err != nil {
			log.Printf("сохранение отклонённого запроса: %v", err)
		}
		return 1
	}
	defer os.Remove(requestPath)
	candidate := filepath.Join(dir, "agent.exe.new")
	defer os.Remove(candidate)
	if err := verifyUpdateFile(candidate, r.SHA256); err != nil {
		return finishUpdate(dir, r, err)
	}
	if err := verifyUpdateEdition(candidate); err != nil {
		return finishUpdate(dir, r, err)
	}
	ver, err := probeBinary(candidate)
	if err != nil || ver != r.ToVersion {
		return finishUpdate(dir, r, fmt.Errorf("повторная проверка сборки: версия %q, ошибка %v", ver, err))
	}
	err = applyAgentUpdate(dir, candidate, updateServiceOps{
		stop:  func() error { return winsvc.Stop(agentServiceName) },
		start: func() error { return winsvc.Start(agentServiceName) },
		verify: func(startedAt time.Time) error {
			if err := agentstatus.Wait(dir, r.ServerURL, r.ToVersion, startedAt, updateHealthWait); err != nil {
				return err
			}
			st, err := agentstatus.Read(dir)
			if err != nil {
				return err
			}
			pid, err := winsvc.ProcessID(agentServiceName)
			if err != nil || pid <= 0 || st.ProcessID != pid {
				return fmt.Errorf("heartbeat не подтверждён работающей службой: PID %d, heartbeat PID %d, ошибка %v", pid, st.ProcessID, err)
			}
			return nil
		},
	})
	return finishUpdate(dir, r, err)
}

type updateServiceOps struct {
	stop   func() error
	start  func() error
	verify func(time.Time) error
}

// Снимки состояния/настроек возвращают прежнего агента целиком, даже если
// новая версия успела изменить их перед отказом.
func applyAgentUpdate(dir, candidate string, ops updateServiceOps) error {
	var startedAt time.Time
	return installtxn.Apply([]installtxn.File{
		{Path: filepath.Join(dir, "agent.exe"), Source: candidate, Mode: 0o755},
		{Path: filepath.Join(dir, "agent_config.json"), Snapshot: true},
		{Path: filepath.Join(dir, "agent_state.json"), Snapshot: true},
		{Path: filepath.Join(dir, "agent_status.json"), Remove: true},
	}, installtxn.Hooks{
		Stop: ops.stop,
		Start: func() error {
			startedAt = time.Now()
			return ops.start()
		},
		Verify:  func() error { return ops.verify(startedAt) },
		Recover: ops.start,
	})
}

func finishUpdate(dir string, r agentUpdateRequest, updateErr error) int {
	result := agentUpdateResult{TaskID: r.TaskID, ExecutionKey: r.ExecutionKey, DeviceID: r.DeviceID, ServerURL: r.ServerURL, Status: "done",
		Output: "обновление " + r.FromVersion + " → " + r.ToVersion + ": служба запущена, связь с сервером подтверждена"}
	if updateErr != nil {
		result.Status, result.ExitCode = "failed", 1
		result.Output = "обновление не подтверждено: " + updateErr.Error()
	}
	log.Printf("задача #%d: %s", r.TaskID, result.Output)
	if err := saveUpdateResult(dir, result); err != nil {
		log.Printf("сохранение результата обновления: %v", err)
		return 1
	}
	// Пока существует запрос, служба оставляет отправку результата helper.
	// Повторяет и сам helper: следующая сборка может знать heartbeat-маркер,
	// но не уметь отправлять отложенные результаты этой версии протокола.
	deadline := time.Now().Add(time.Minute)
	for time.Now().Before(deadline) {
		if sendUpdateResult(dir) {
			break
		}
		time.Sleep(min(5*time.Second, time.Until(deadline)))
	}
	return result.ExitCode
}

func saveUpdateResult(dir string, r agentUpdateResult) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, updateResultName)
	if err := os.WriteFile(path+".tmp", b, 0o600); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}

// При кратком отказе сервера исход обновления остаётся на диске и отправится
// рабочим агентом после восстановления связи.
func flushUpdateResult() {
	if !fileExists(filepath.Join(exeDir(), updateRequestName)) {
		sendUpdateResult(exeDir())
		if winsvc.IsService() {
			// Запущенный helper удалить Windows ещё не даст. Следующий круг
			// уберёт его копию после выхода процесса, не оставляя второй EXE.
			_ = os.Remove(filepath.Join(exeDir(), updateHelperName))
		}
	}
}

func sendUpdateResult(dir string) bool {
	path := filepath.Join(dir, updateResultName)
	b, err := os.ReadFile(path)
	if err != nil {
		return os.IsNotExist(err)
	}
	var r agentUpdateResult
	if json.Unmarshal(b, &r) != nil || r.TaskID <= 0 || r.DeviceID <= 0 || r.ServerURL == "" || (r.Status != "done" && r.Status != "failed") {
		log.Print("некорректный сохранённый результат обновления")
		return false
	}
	var st agentState
	stateBytes, err := os.ReadFile(filepath.Join(dir, "agent_state.json"))
	if err != nil || json.Unmarshal(stateBytes, &st) != nil {
		return false
	}
	// Идентификаторы задач локальны для сервера: после переноса на другой
	// сервер старый результат не должен менять там задачу с таким же номером.
	if r.ServerURL != serverURL || r.DeviceID != st.DeviceID {
		return false
	}
	setAgentIdentity(unprotectString(st.DeviceToken), st.DeviceID)
	if deviceToken == "" || deviceID <= 0 {
		return false
	}
	status, body, err := post("/api/agent-tasks/result", map[string]any{
		"id": r.TaskID, "status": r.Status, "result": r.Output, "exit_code": r.ExitCode,
		"execution_key": r.ExecutionKey,
	})
	var ack struct {
		OK bool `json:"ok"`
	}
	if err == nil && status == http.StatusOK && json.Unmarshal(body, &ack) == nil && ack.OK {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			log.Printf("удаление отправленного результата обновления: %v", err)
			return false
		}
		return true
	} else {
		log.Printf("результат обновления сохранён для повторной отправки: HTTP %d, %v", status, err)
	}
	return false
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil || !os.IsNotExist(err)
}

func validUpdateHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func verifyUpdateFile(path, expected string) error {
	sum, err := fileSHA256(path)
	if err != nil {
		return fmt.Errorf("проверка контрольной суммы: %w", err)
	}
	if !strings.EqualFold(sum, expected) {
		return errors.New("контрольная сумма не совпала — сборка подменена или повреждена")
	}
	return nil
}

// Remote updates preserve the edition. Choosing another edition is a separate
// installation action, not an accidental consequence of matching version text.
func verifyUpdateEdition(path string) error {
	actual, err := edition.ReadBinary(path)
	if err != nil {
		return fmt.Errorf("редакция обновления не подтверждена: %w", err)
	}
	if actual != edition.ID {
		return fmt.Errorf("редакция обновления %q отличается от установленной %q; для смены редакции переустановите агента", actual, edition.ID)
	}
	return nil
}

func probeBinary(path string) (string, error) {
	return probeBinaryTimeout(path, versionProbeWait)
}

// Повреждённый EXE не может навсегда остановить цикл или заполнить память stdout.
func probeBinaryTimeout(path string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "-version")
	hideWindow(cmd)
	return runVersionProbe(ctx, cmd)
}

func runVersionProbe(ctx context.Context, cmd *exec.Cmd) (string, error) {
	var out versionOutput
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return "", errors.New("проверка -version превысила время ожидания")
		}
		return "", err
	}
	v := strings.TrimSpace(out.String())
	if v == "" || len(v) > 128 || strings.IndexFunc(v, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return "", errors.New("некорректный ответ на -version")
	}
	return v, nil
}

type versionOutput struct{ buf bytes.Buffer }

func (w *versionOutput) String() string { return w.buf.String() }

func (w *versionOutput) Write(p []byte) (int, error) {
	if w.buf.Len()+len(p) > 1024 {
		return 0, errors.New("слишком большой ответ на -version")
	}
	return w.buf.Write(p)
}
