package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"

	"netadmin/internal/taskrun"
)

type taskReply struct {
	OK       bool   `json:"ok"`
	Status   string `json:"status"`
	Cancel   bool   `json:"cancel_requested"`
	Conflict bool   `json:"conflict"`
}

func taskRequest(path string, r *taskrun.Record) (taskReply, int, error) {
	code, b, err := post(path, map[string]any{"id": r.Task.ID, "execution_key": r.ExecutionKey})
	var reply taskReply
	if err == nil && code == http.StatusOK {
		err = json.Unmarshal(b, &reply)
	}
	return reply, code, err
}

func terminalTask(s string) bool { return s == "done" || s == "failed" || s == "cancelled" }

func pumpTasks(ctx context.Context, e *taskrun.Engine) {
	_, id := agentIdentity()
	if e.Record != nil && (e.Record.DeviceID != id || e.Record.ServerURL != serverURL) {
		if e.Record.Phase == "running" {
			e.Cancel()
			if !e.Collect() {
				return
			}
		}
		if err := e.Save(); err != nil {
			log.Print(err)
			return
		}
		if err := e.Detach(); err != nil {
			log.Printf("сохранение задачи прежней регистрации: %v", err)
			return
		}
		log.Print("задача прежней регистрации сохранена отдельно")
	}
	if e.Record == nil {
		host, _ := os.Hostname()
		code, b, err := post("/api/agent-tasks/poll", map[string]any{"hostname": host, "protocol": 2})
		if err != nil || code != http.StatusOK {
			return
		}
		var response struct {
			Tasks    []taskrun.Task `json:"tasks"`
			Protocol int            `json:"protocol"`
		}
		if json.Unmarshal(b, &response) != nil || len(response.Tasks) == 0 {
			return
		}
		if response.Protocol != 2 || len(response.Tasks) != 1 {
			log.Print("сервер не поддерживает подтверждение задач; обновите сервер перед агентом")
			return
		}
		r := taskrun.Record{Task: response.Tasks[0], ServerURL: serverURL, DeviceID: id, ExecutionKey: newNonce()}
		if err = e.Accept(r); err != nil {
			log.Printf("задача не запущена: не удалось сохранить журнал: %v", err)
			return
		}
	}
	r := e.Record
	if r.Phase == "accepted" {
		reply, code, err := taskRequest("/api/agent-tasks/start", r)
		if err != nil || code != http.StatusOK {
			return
		}
		switch {
		case reply.Cancel:
			e.Finish(taskrun.Outcome{Status: "cancelled", Output: "Отменено до запуска.", ExitCode: 125})
		case reply.Conflict || terminalTask(reply.Status):
			if err = e.Clear(); err != nil {
				log.Print(err)
			}
			return
		case reply.OK:
			if err = e.Start(ctx); err != nil {
				log.Printf("задача не запущена: %v", err)
			}
		default:
			return
		}
	}
	if r.Phase == "running" {
		if !e.Collect() {
			reply, code, err := taskRequest("/api/agent-tasks/state", r)
			if err == nil && code == http.StatusOK && reply.Cancel {
				e.Cancel()
			}
			return
		}
		if r.Task.Kind == "selfupdate" && r.Outcome.Status == "done" {
			// Persist handoff before the helper can stop this process.
			r.Phase = "handoff"
			if err := e.Save(); err != nil {
				r.Phase = "finished"
				log.Print(err)
				return
			}
			setUpdateExecutionKey(r.ExecutionKey)
			if launched, err := launchPendingUpdate(r.Task.ID); err != nil {
				e.Finish(taskrun.Outcome{Status: "failed", Output: "Запуск обновления: " + err.Error(), ExitCode: 1})
			} else if launched {
				return
			} else {
				r.Phase = "finished"
			}
		}
	}
	if r.Phase == "handoff" {
		reply, code, err := taskRequest("/api/agent-tasks/state", r)
		if err != nil || code != http.StatusOK {
			return
		}
		if terminalTask(reply.Status) {
			if err = e.Clear(); err != nil {
				log.Print(err)
			}
			return
		}
		if updateHandoffPending() {
			return
		}
		e.Finish(taskrun.Outcome{Status: "failed", Output: "Обновление прервано до подтверждения. Автоматический повтор отключён.", ExitCode: 1})
	}
	if r.Phase != "finished" {
		return
	}
	if err := e.Save(); err != nil {
		log.Printf("результат ожидает записи на диск: %v", err)
		return
	}
	code, b, err := post("/api/agent-tasks/result", map[string]any{"id": r.Task.ID, "execution_key": r.ExecutionKey,
		"status": r.Outcome.Status, "result": r.Outcome.Output, "exit_code": r.Outcome.ExitCode})
	var ack taskReply
	if err == nil && code == http.StatusOK && json.Unmarshal(b, &ack) == nil && ack.OK {
		log.Printf("задача #%d: %s (код %d)", r.Task.ID, r.Outcome.Status, r.Outcome.ExitCode)
		if err = e.Clear(); err != nil {
			log.Printf("подтверждённый результат: %v", err)
		}
	} else if err == nil && code == http.StatusConflict {
		state, status, stateErr := taskRequest("/api/agent-tasks/state", r)
		if stateErr == nil && status == http.StatusOK && !state.Conflict && terminalTask(state.Status) {
			// Keep evidence of an update-helper race instead of overwriting
			// the first confirmed terminal result on the server.
			if err = e.Detach(); err != nil {
				log.Print(err)
			}
		}
	}
}
