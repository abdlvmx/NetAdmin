//go:build securityevents

package handlers

import (
	"context"
	"log"
	"netadmin/internal/config"
	"netadmin/internal/securityevents"
	"path/filepath"
	"sync"
	"time"
)

type eventsStore = *securityevents.Store

func (a *App) StartEvents(dir string) (func(), error) {
	path := filepath.Join(dir, "security-events.db")
	work, finish := context.WithTimeout(context.Background(), 2*time.Minute)
	saved, err := securityevents.ApplyRestore(work, path)
	finish()
	if err != nil {
		return nil, err
	}
	if saved != "" {
		log.Printf("Events восстановлен; прежняя база: %s; сбор выключен", saved)
	}
	store, err := securityevents.Open(path)
	if err != nil {
		return nil, err
	}
	a.Events = store
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if a.Demo {
			return
		}
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for {
			if ctx.Err() != nil {
				return
			}
			a.eventsBackupTick(ctx, dir)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { cancel(); <-done; store.Close() }) }, nil
}

func (a *App) eventsBackupTick(ctx context.Context, dataDir string) {
	cfg := config.Load()
	if cfg.BackupIntervalHours <= 0 {
		return
	}
	dir := eventsBackupDirectory(dataDir, cfg)
	list, err := securityevents.ListBackups(dir)
	if err != nil {
		log.Printf("копии Events: %v", err)
		return
	}
	if len(list) > 0 && time.Since(list[0].Created) < time.Duration(cfg.BackupIntervalHours)*time.Hour {
		return
	}
	work, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	info, err := a.Events.CreateBackup(work, dir, cfg.BackupKeep)
	if err != nil {
		if ctx.Err() == nil {
			log.Printf("резервная копия Events: %v", err)
		}
		return
	}
	log.Printf("резервная копия Events проверена: %s", info.Name)
}
