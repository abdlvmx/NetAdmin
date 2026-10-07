// Package agentstatus records the last signed heartbeat accepted by the server.
// It contains no credentials and is kept in the protected installation directory.
package agentstatus

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const Filename = "agent_status.json"

type Status struct {
	ServerURL   string    `json:"server_url"`
	DeviceID    int64     `json:"device_id"`
	Version     string    `json:"version"`
	HeartbeatAt time.Time `json:"heartbeat_at"`
	AttemptAt   time.Time `json:"attempt_at"`
	ProcessID   int       `json:"process_id"`
	LastError   string    `json:"last_error,omitempty"`
}

func Save(dir string, status Status) error {
	data, err := json.Marshal(status)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".na-status-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), filepath.Join(dir, Filename))
}

func Read(dir string) (Status, error) {
	var s Status
	b, err := os.ReadFile(filepath.Join(dir, Filename))
	if err == nil {
		err = json.Unmarshal(b, &s)
	}
	return s, err
}

func (s Status) Matches(server, version string, since time.Time) bool {
	return s.ServerURL == server && s.Version == version && s.DeviceID > 0 &&
		s.ProcessID > 0 && !s.HeartbeatAt.Before(since) && s.LastError == ""
}

func Wait(dir, server, version string, since time.Time, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last Status
	for {
		if s, err := Read(dir); err == nil {
			last = s
			if s.Matches(server, version, since) {
				return nil
			}
		}
		if !time.Now().Before(deadline) {
			if last.ServerURL == server && !last.AttemptAt.Before(since) && last.LastError != "" {
				return fmt.Errorf("сервер не подтвердил подключение агента: %s", last.LastError)
			}
			return fmt.Errorf("свежий heartbeat не получен за %s; проверьте журнал agent.log и выполните agent.exe -check", timeout)
		}
		delay := min(250*time.Millisecond, time.Until(deadline))
		time.Sleep(delay)
	}
}
