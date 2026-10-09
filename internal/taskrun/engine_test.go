package taskrun

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"
)

func testRecord() Record {
	return Record{Task: Task{ID: 10, Kind: "command", Payload: "ipconfig"}, ServerURL: "https://server:8765", DeviceID: 2, ExecutionKey: "0123456789abcdef0123456789abcdef"}
}

func TestWorkerDoesNotBlockPollingAndDoesNotReplayAfterRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "task.json")
	started := make(chan struct{})
	var calls atomic.Int32
	runner := func(ctx context.Context, _, _ string) Outcome {
		calls.Add(1)
		close(started)
		<-ctx.Done()
		return Outcome{"cancelled", "stopped", 125}
	}
	e, err := Open(path, runner)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.Accept(testRecord()); err != nil {
		t.Fatal(err)
	}
	if err = e.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer e.Cancel()
	defer e.Close()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("worker did not start")
	}
	if e.Collect() {
		t.Fatal("blocked worker completed")
	}
	if err = e.Accept(testRecord()); err == nil {
		t.Fatal("second task accepted before first result")
	}
	if other, err := Open(path, runner); err == nil {
		other.Close()
		t.Fatal("second agent acquired task journal")
	}
	e.Close() // simulate termination: leave the durable running marker intact
	// An independent process sees the running marker and reports interruption.
	recovered, err := Open(path, func(context.Context, string, string) Outcome { calls.Add(1); return Outcome{"done", "replayed", 0} })
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	if recovered.Record.Phase != "finished" || recovered.Record.Outcome.Status != "failed" {
		t.Fatalf("recovery: %+v", recovered.Record)
	}
	if calls.Load() != 1 {
		t.Fatal("side effect repeated after restart")
	}
	e.Cancel()
	deadline := time.Now().Add(time.Second)
	for !e.Collect() {
		if time.Now().After(deadline) {
			t.Fatal("cancellation did not finish")
		}
		time.Sleep(time.Millisecond)
	}
	if e.Record.Outcome.Status != "cancelled" {
		t.Fatal(e.Record.Outcome)
	}
}

func TestSavedResultSurvivesUntilExplicitAcknowledgement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "task.json")
	e, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Accept(testRecord()); err != nil {
		t.Fatal(err)
	}
	e.Finish(Outcome{"failed", "подробная ошибка", 17})
	if err := e.Save(); err != nil {
		t.Fatal(err)
	}
	e.Close()
	for i := 0; i < 3; i++ {
		e, err = Open(path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if e.Record.Outcome.ExitCode != 17 || e.Record.Outcome.Output != "подробная ошибка" {
			t.Fatal("result lost")
		}
		if i < 2 {
			e.Close()
		}
	}
	if err := e.Clear(); err != nil {
		t.Fatal(err)
	}
	e.Close()
	e, err = Open(path, nil)
	if err != nil || e.Record != nil {
		t.Fatalf("clear: %v %+v", err, e)
	}
	e.Close()
}

func TestDiskFailurePreventsExecution(t *testing.T) {
	var calls atomic.Int32
	e, err := Open(filepath.Join(t.TempDir(), "missing", "task.json"), func(context.Context, string, string) Outcome { calls.Add(1); return Outcome{} })
	if err == nil {
		e.Close()
		t.Fatal("missing directory accepted")
	}
	if calls.Load() != 0 || e != nil {
		t.Fatal("task executed without durable journal")
	}
}

func TestMalformedJournalIsNotReplayed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "task.json")
	if err := os.WriteFile(path, []byte(`{"phase":"running"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, nil); err == nil {
		t.Fatal("invalid journal accepted")
	}
}

func TestOutputLimitPreservesUTF8AndFlagsTruncation(t *testing.T) {
	s := LimitOutput(strings.Repeat("я", 9000))
	if len(s) > MaxOutput || !utf8.ValidString(s) || !strings.Contains(s, "сокращён") {
		t.Fatal("invalid limited output")
	}
}
