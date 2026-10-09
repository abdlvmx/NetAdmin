//go:build securityevents && windows

package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"netadmin/internal/eventlog"
	"netadmin/internal/securityevents"
)

var readEventLog = eventlog.Read

type eventsWorker struct {
	path   string
	queue  *securityevents.Queue
	state  securityevents.QueueState
	status securityevents.Status
}

func startEventWorker(ctx context.Context) {
	go func() {
		worker := &eventsWorker{path: filepath.Join(exeDir(), "agent_events.db"), status: securityevents.Status{State: "disabled"}}
		defer func() {
			if worker.queue != nil {
				worker.queue.Close()
			}
		}()
		for {
			worker.step(ctx)
			select {
			case <-ctx.Done():
				return
			case <-time.After(15 * time.Second):
			}
		}
	}()
}

func eventsPost(ctx context.Context, base, key string, id int64, path string, payload map[string]any) (int, []byte, error) {
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		return 0, nil, errors.New("для Events требуется HTTPS без логина в адресе")
	}
	payload["timestamp"], payload["nonce"] = time.Now().UTC().Unix(), newNonce()
	b, err := json.Marshal(payload)
	if err != nil {
		return 0, nil, err
	}
	if len(b) > securityevents.MaxBatchBytes {
		return 0, nil, errors.New("пакет Events превышает предел")
	}
	r, err := http.NewRequestWithContext(ctx, "POST", base+path, bytes.NewReader(b))
	if err != nil {
		return 0, nil, err
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set(hdrDevice, strconv.FormatInt(id, 10))
	r.Header.Set(hdrSig, sign(key, b))
	resp, err := httpClient.Do(r)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	if len(body) > 65536 {
		return resp.StatusCode, nil, errors.New("ответ Events превышает предел")
	}
	if resp.StatusCode == http.StatusOK && !hmac.Equal([]byte(resp.Header.Get(hdrSig)), []byte(sign(key, body))) {
		return resp.StatusCode, nil, errors.New("неверная подпись ответа Events")
	}
	return resp.StatusCode, body, nil
}

func validEventPolicy(p securityevents.Policy) bool {
	if !p.Enabled {
		return true
	}
	return (p.Profile == "system" || p.Profile == "security") && len(p.Generation) == 32 && strings.Trim(p.Generation, "0123456789abcdef") == ""
}

func (w *eventsWorker) problem(state string, err error) {
	w.status.State = state
	w.status.Error = eventErrorText(err.Error(), 512)
}

func eventErrorText(s string, limit int) string {
	s = strings.ToValidUTF8(s, "�")
	if len(s) <= limit {
		return s
	}
	for !utf8.ValidString(s[:limit]) {
		limit--
	}
	return s[:limit]
}

// Every collection pass requires a fresh signed policy response. A network
// outage pauses reading immediately; queued data waits for consent and ACK.
func (w *eventsWorker) step(ctx context.Context) {
	key, id := agentIdentity()
	base := serverURL
	if id <= 0 || key == "" || ctx.Err() != nil {
		return
	}
	if w.queue != nil {
		n, err := w.queue.Bytes()
		if err == nil {
			w.status.QueueBytes = n
		}
	}
	code, b, err := eventsPost(ctx, base, key, id, "/api/agent-events/poll", map[string]any{"capabilities": agentCapabilities(), "status": w.status})
	if err != nil {
		w.problem("paused", err)
		return
	}
	if code != 200 {
		w.problem("paused", fmt.Errorf("политика Events недоступна: HTTP %d", code))
		return
	}
	var reply securityevents.PollResponse
	if err = json.Unmarshal(b, &reply); err != nil || !validEventPolicy(reply.Policy) {
		w.problem("error", errors.New("сервер вернул некорректную политику Events"))
		return
	}
	policy := reply.Policy
	if !policy.Enabled {
		if w.queue == nil {
			if _, statErr := os.Stat(w.path); statErr == nil {
				w.queue, err = securityevents.OpenQueue(w.path)
				if err != nil {
					w.problem("error", err)
					return
				}
				w.state, err = w.queue.State()
				if err != nil {
					w.problem("error", err)
					w.queue.Close()
					w.queue = nil
					return
				}
			} else if !os.IsNotExist(statErr) {
				w.problem("error", statErr)
				return
			}
		}
		if w.queue != nil && w.state.Policy.Enabled {
			next := securityevents.QueueState{ServerURL: base, DeviceID: id, Policy: policy, Status: securityevents.Status{State: "disabled", Dropped: max(w.status.Dropped, w.state.Status.Dropped)}}
			state, resetErr := w.queue.Reset(ctx, next)
			if resetErr != nil {
				w.problem("error", resetErr)
				return
			}
			w.state = state
			w.status = w.state.Status
		}
		w.status.State = "disabled"
		w.status.Generation = ""
		w.status.Channels = nil
		return
	}
	if w.queue == nil {
		w.queue, err = securityevents.OpenQueue(w.path)
		if err != nil {
			w.problem("error", fmt.Errorf("очередь Events: %w", err))
			return
		}
		w.state, err = w.queue.State()
		if err != nil {
			w.problem("error", err)
			w.queue.Close()
			w.queue = nil
			return
		}
	}
	if w.state.ServerURL != base || w.state.DeviceID != id || w.state.Policy.Generation != policy.Generation || w.state.Policy.Profile != policy.Profile {
		next := securityevents.QueueState{ServerURL: base, DeviceID: id, Policy: policy, Status: securityevents.Status{Generation: policy.Generation, State: "collecting", Dropped: max(w.status.Dropped, w.state.Status.Dropped)}}
		state, resetErr := w.queue.Reset(ctx, next)
		if resetErr != nil {
			w.problem("error", resetErr)
			return
		}
		w.state = state
	}
	w.status = w.state.Status
	w.status.Generation = policy.Generation
	for i := 0; i < 4; i++ {
		batch, ok, getErr := w.queue.Oldest()
		if getErr != nil {
			w.problem("error", getErr)
			return
		}
		if !ok {
			break
		}
		if batch.Generation != policy.Generation {
			w.problem("error", errors.New("очередь принадлежит другой политике Events"))
			return
		}
		status, body, sendErr := eventsPost(ctx, base, key, id, "/api/agent-events/batch", map[string]any{"batch": batch})
		var ack struct {
			OK bool `json:"ok"`
		}
		if sendErr != nil {
			w.problem("paused", sendErr)
			return
		}
		if status != 200 || json.Unmarshal(body, &ack) != nil || !ack.OK {
			w.problem("paused", fmt.Errorf("пакет Events ожидает подтверждения: HTTP %d", status))
			return
		}
		if err = w.queue.Acknowledge(ctx, batch.ID); err != nil {
			w.problem("error", err)
			return
		}
	}
	events := []securityevents.Event{}
	gaps := []securityevents.Gap{}
	health := []securityevents.ChannelStatus{}
	channels := eventlog.Channels(policy.Profile)
	readLimit := min(100, securityevents.MaxBatchEvents/len(channels))
	currentKey, currentID := agentIdentity()
	if currentKey != key || currentID != id {
		w.problem("paused", errors.New("регистрация агента изменилась; сбор приостановлен"))
		return
	}
	next := w.state
	next.Cursors = map[string]securityevents.Cursor{}
	for channel, cursor := range w.state.Cursors {
		next.Cursors[channel] = cursor
	}
	w.status.State = "collecting"
	w.status.Error = ""
	readSucceeded := false
	for _, channel := range channels {
		cursor := w.state.Cursors[channel]
		readCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		result, readErr := readEventLog(readCtx, channel, eventlog.Cursor{Bookmark: cursor.Bookmark, StreamID: cursor.StreamID}, readLimit)
		cancel()
		if readErr != nil {
			message := eventErrorText(readErr.Error(), 256)
			health = append(health, securityevents.ChannelStatus{Channel: channel, State: "error", Error: message})
			w.status.State = "error"
			continue
		}
		readSucceeded = true
		next.Cursors[channel] = securityevents.Cursor{Bookmark: result.Cursor.Bookmark, StreamID: result.Cursor.StreamID}
		for _, e := range result.Events {
			events = append(events, securityevents.Event{StreamID: e.StreamID, Channel: e.Channel, Provider: e.Provider, EventID: e.EventID, RecordID: e.RecordID, Version: e.Version, TimeUTC: e.TimeUTC, Fields: e.Fields})
		}
		if result.Gap != nil {
			gaps = append(gaps, securityevents.Gap{Channel: result.Gap.Channel, Reason: result.Gap.Reason})
		}
		health = append(health, securityevents.ChannelStatus{Channel: channel, State: "ready"})
	}
	w.status.Channels = health
	if readSucceeded {
		w.status.LastCollected = time.Now().UTC()
	}
	next.Policy = policy
	next.Status = w.status
	packets, err := securityevents.SplitBatches(policy.Generation, events, gaps, w.status, newNonce)
	if err != nil {
		w.problem("error", err)
		return
	}
	state, err := w.queue.Commit(ctx, next, packets)
	if err != nil {
		w.problem("error", fmt.Errorf("сохранение событий и bookmarks: %w", err))
		return
	}
	w.state = state
	w.status = state.Status
}
