// Package taskrun keeps one durable task and runs it independently of polling.
package taskrun

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const MaxOutput = 8000

type Task struct {
	ID      int64  `json:"id"`
	Kind    string `json:"kind"`
	Payload string `json:"payload"`
}

type Outcome struct {
	Status   string `json:"status"`
	Output   string `json:"result"`
	ExitCode int    `json:"exit_code"`
}

type Record struct {
	Task         Task    `json:"task"`
	ServerURL    string  `json:"server_url"`
	DeviceID     int64   `json:"device_id"`
	ExecutionKey string  `json:"execution_key"`
	Phase        string  `json:"phase"` // accepted, running, finished, handoff
	Outcome      Outcome `json:"outcome"`
}

type Runner func(context.Context, string, string) Outcome

// Engine is owned by the polling goroutine. The worker only writes its channel.
type Engine struct {
	Path        string
	Record      *Record
	run         Runner
	completed   chan Outcome
	cancel      context.CancelFunc
	releaseLock func()
}

func Open(path string, run Runner) (*Engine, error) {
	e := &Engine{Path: path, run: run}
	release, err := lockJournal(path + ".lock")
	if err != nil {
		return nil, fmt.Errorf("журнал уже занят другим агентом или недоступен: %w", err)
	}
	e.releaseLock = release
	success := false
	defer func() {
		if !success {
			release()
		}
	}()
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		success = true
		return e, nil
	}
	if err != nil {
		return nil, err
	}
	b, err := io.ReadAll(io.LimitReader(f, 128<<10+1))
	closeErr := f.Close()
	err = errors.Join(err, closeErr)
	if err != nil {
		return nil, err
	}
	var r Record
	if len(b) > 128<<10 || json.Unmarshal(b, &r) != nil || !validRecord(r) {
		return nil, errors.New("повреждён журнал удалённой задачи; выполнение остановлено")
	}
	e.Record = &r
	if r.Phase == "running" {
		e.Finish(Outcome{"failed", "Выполнение прервано перезапуском агента. Действие могло частично выполниться; автоматический повтор отключён.", 1})
		if err := e.Save(); err != nil {
			return nil, err
		}
	}
	success = true
	return e, nil
}

func (e *Engine) Close() {
	e.Cancel()
	if e.releaseLock != nil {
		e.releaseLock()
		e.releaseLock = nil
	}
}

func validRecord(r Record) bool {
	key, err := hex.DecodeString(r.ExecutionKey)
	return r.Task.ID > 0 && r.DeviceID > 0 && r.ServerURL != "" && r.ExecutionKey != "" &&
		err == nil && len(key) == 16 &&
		(r.Phase == "accepted" || r.Phase == "running" || r.Phase == "finished" || r.Phase == "handoff") &&
		len(r.Task.Payload) <= 64<<10 && (r.Phase != "finished" || r.Outcome.Status == "done" || r.Outcome.Status == "failed" || r.Outcome.Status == "cancelled")
}

func (e *Engine) Accept(r Record) error {
	if e.Record != nil {
		return errors.New("предыдущая задача ещё не подтверждена")
	}
	r.Phase = "accepted"
	if !validRecord(r) {
		return errors.New("некорректная задача")
	}
	e.Record = &r
	if err := e.Save(); err != nil {
		e.Record = nil
		return err
	}
	return nil
}

func (e *Engine) Save() error {
	if e.Record == nil {
		return nil
	}
	b, err := json.Marshal(e.Record)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(e.Path), ".na-task-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err = errors.Join(err, closeErr); err != nil {
		return err
	}
	return os.Rename(name, e.Path)
}

// Start persists the no-replay marker before allowing any side effect.
func (e *Engine) Start(ctx context.Context) error {
	if e.Record == nil || e.Record.Phase != "accepted" {
		return errors.New("задача не готова к запуску")
	}
	e.Record.Phase = "running"
	if err := e.Save(); err != nil {
		e.Record.Phase = "accepted"
		return err
	}
	ctx, e.cancel = context.WithCancel(ctx)
	e.completed = make(chan Outcome, 1)
	result := e.completed
	t := e.Record.Task
	go func() {
		var out Outcome
		func() {
			defer func() {
				if v := recover(); v != nil {
					out = Outcome{"failed", "Внутренняя ошибка исполнителя задачи.", 1}
				}
			}()
			out = e.run(ctx, t.Kind, t.Payload)
		}()
		result <- out
	}()
	return nil
}

func (e *Engine) Cancel() {
	if e.cancel != nil {
		e.cancel()
	}
}

func (e *Engine) Collect() bool {
	if e.completed == nil {
		return false
	}
	select {
	case out := <-e.completed:
		e.cancel()
		e.cancel = nil
		e.completed = nil
		e.Finish(out)
		return true
	default:
		return false
	}
}

func (e *Engine) Finish(out Outcome) {
	if e.Record == nil {
		return
	}
	if out.Status != "done" && out.Status != "failed" && out.Status != "cancelled" {
		out.Status = "failed"
		out.ExitCode = 1
	}
	out.Output = LimitOutput(out.Output)
	e.Record.Outcome = out
	e.Record.Phase = "finished"
}

func LimitOutput(s string) string {
	s = strings.ToValidUTF8(s, "�")
	if len(s) <= MaxOutput {
		return s
	}
	n := MaxOutput - len("\n[Вывод сокращён]")
	for n > 0 && (s[n]&0xc0) == 0x80 {
		n--
	}
	return s[:n] + "\n[Вывод сокращён]"
}

func (e *Engine) Clear() error {
	if e.Record == nil {
		return nil
	}
	if err := os.Remove(e.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	e.Record = nil
	return nil
}

// Detach preserves an old result across a transfer, without sending it to the
// new server (task IDs are local to each server).
func (e *Engine) Detach() error {
	if e.completed != nil {
		return errors.New("дождитесь остановки выполняемой задачи")
	}
	if e.Record == nil {
		return nil
	}
	dst := fmt.Sprintf("%s.previous-%d-%s", e.Path, e.Record.Task.ID, e.Record.ExecutionKey)
	if err := os.Rename(e.Path, dst); err != nil {
		return err
	}
	e.Record = nil
	return nil
}
