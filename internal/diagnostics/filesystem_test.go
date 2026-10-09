package diagnostics

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestBlockedFilesystemTimesOutWithoutAccumulatingWorkersAndRecovers(t *testing.T) {
	gate := &filesystemGate{active: make(chan struct{}, 1)}
	entered := make(chan struct{})
	release := make(chan struct{})
	var released sync.Once
	defer released.Do(func() { close(release) })
	var calls atomic.Int32
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	firstResult := make(chan error, 1)
	go func() {
		_, err := runFilesystem(ctx, gate, func() (int, error) {
			calls.Add(1)
			close(entered)
			<-release // models an uninterruptible UNC open/read/stat syscall
			return 42, nil
		})
		firstResult <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("worker did not start")
	}
	select {
	case err := <-firstResult:
		if !errors.Is(err, ErrFilesystemTimeout) {
			t.Fatalf("got %v, want timeout", err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked filesystem prevented request completion")
	}
	// The original caller is gone, but the uninterruptible operation still
	// holds the only slot. Every later request must fail quickly without
	// invoking or queueing another filesystem operation.
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := runFilesystem(context.Background(), gate, func() (int, error) { calls.Add(1); return 0, nil })
			if !errors.Is(err, ErrFilesystemBusy) {
				t.Errorf("later request got %v, want busy", err)
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 1 || len(gate.active) != 1 {
		t.Fatalf("workers accumulated: calls=%d active=%d", calls.Load(), len(gate.active))
	}
	released.Do(func() { close(release) })
	deadline := time.Now().Add(time.Second)
	for len(gate.active) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(gate.active) != 0 {
		t.Fatal("abandoned result blocked slot release")
	}
	value, err := runFilesystem(context.Background(), gate, func() (int, error) { calls.Add(1); return 99, nil })
	if err != nil || value != 99 || calls.Load() != 2 {
		t.Fatalf("recovery: value=%d err=%v calls=%d", value, err, calls.Load())
	}
}

func TestFilesystemCancelledContextDoesNotStartWork(t *testing.T) {
	gate := &filesystemGate{active: make(chan struct{}, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := runFilesystem(ctx, gate, func() (int, error) { t.Error("cancelled request started filesystem work"); return 1, nil })
	if !errors.Is(err, ErrFilesystemTimeout) || len(gate.active) != 0 {
		t.Fatalf("cancelled call: %v active=%d", err, len(gate.active))
	}
}

func TestFilesystemPanicReleasesWorker(t *testing.T) {
	gate := &filesystemGate{active: make(chan struct{}, 1)}
	_, err := runFilesystem(context.Background(), gate, func() (int, error) { panic("sensitive panic value") })
	if !errors.Is(err, ErrFilesystemUnavailable) || len(gate.active) != 0 {
		t.Fatalf("worker panic: %v active=%d", err, len(gate.active))
	}
	if _, err := runFilesystem(context.Background(), gate, func() (int, error) { return 1, nil }); err != nil {
		t.Fatalf("worker not reusable: %v", err)
	}
}

func TestReportMarksBusyFilesystemUnknownAndRecovers(t *testing.T) {
	in := testInput(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	var released sync.Once
	defer released.Do(func() { close(release) })
	done := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	go func() {
		_, err := Filesystem(ctx, func() (int, error) { close(entered); <-release; return 0, nil })
		done <- err
	}()
	<-entered
	if err := <-done; !errors.Is(err, ErrFilesystemTimeout) {
		t.Fatalf("fake-blocked worker: %v", err)
	}
	r := Collect(context.Background(), in)
	if r.Summary.Backup.Known || r.Summary.Backup.PendingRestoreKnown || checkLevel(t, r, "backups") != "unknown" || checkLevel(t, r, "restore") != "unknown" {
		t.Fatalf("invented filesystem success: %+v", r.Summary.Backup)
	}
	if !r.Summary.DatabaseAvailable {
		t.Fatal("busy filesystem prevented independent database check")
	}
	archiveFiles(t, r)
	released.Do(func() { close(release) })
	deadline := time.Now().Add(time.Second)
	for len(diagnosticFilesystem.active) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	r = Collect(context.Background(), in)
	if !r.Summary.Backup.Known || !r.Summary.Backup.PendingRestoreKnown || checkLevel(t, r, "backups") == "unknown" {
		t.Fatalf("filesystem did not recover: %+v", r.Summary.Backup)
	}
}
