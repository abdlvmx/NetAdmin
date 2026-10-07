// Package installtxn replaces installation files only after staging them and
// restores the previous files and service when startup or verification fails.
package installtxn

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

type File struct {
	Path     string
	Source   string
	Data     []byte
	Mode     os.FileMode
	Remove   bool
	Snapshot bool // keep in place, but restore its original contents on failure
}

type Hooks struct {
	Stop    func() error
	Start   func() error
	Verify  func() error
	Recover func() error // restore the previous service state after file rollback
}

type stagedFile struct {
	File
	stage, backup string
	prepared      bool
	existed       bool
	changed       bool
}

// Apply stages replacements before stopping the service. Snapshots are taken
// after Stop so a running process cannot mutate the rollback copy. Failed
// rollback copies are retained for manual recovery, with their paths in errors.
func Apply(files []File, hooks Hooks) error {
	staged := make([]stagedFile, len(files))
	seen := make(map[string]bool)
	for i, f := range files {
		p, err := filepath.Abs(f.Path)
		if err != nil || f.Path == "" {
			return fmt.Errorf("неверный путь установки %q", f.Path)
		}
		key := filepath.Clean(p)
		if runtime.GOOS == "windows" {
			key = strings.ToLower(key)
		}
		if seen[key] {
			return fmt.Errorf("повторяющийся путь установки: %s", p)
		}
		seen[key] = true
		if (f.Remove && f.Snapshot) || ((f.Remove || f.Snapshot) && (f.Source != "" || f.Data != nil)) || (f.Source != "" && f.Data != nil) {
			return fmt.Errorf("несовместимые операции для %s", p)
		}
		f.Path = p
		staged[i].File = f
	}
	if len(staged) == 0 {
		return fmt.Errorf("не указаны файлы установки")
	}
	unlock, err := lock(filepath.Dir(staged[0].Path))
	if err != nil {
		return fmt.Errorf("другая установка уже выполняется или каталог недоступен: %w", err)
	}
	defer unlock()
	defer func() {
		for _, f := range staged {
			if f.stage != "" {
				_ = os.Remove(f.stage)
			}
		}
	}()
	for i := range staged {
		f := &staged[i]
		if f.Remove || f.Snapshot {
			continue
		}
		var err error
		f.stage, err = stage(*f)
		if err != nil {
			return fmt.Errorf("подготовка %s: %w", f.Path, err)
		}
	}
	if err := call(hooks.Stop); err != nil {
		return errors.Join(fmt.Errorf("остановка перед установкой: %w", err), wrap("восстановление службы", call(hooks.Recover)))
	}
	started := false
	rollback := func(cause error) error {
		if started {
			if err := call(hooks.Stop); err != nil {
				var backups []string
				for _, f := range staged {
					if f.backup != "" {
						backups = append(backups, f.Path+" ← "+f.backup)
					}
				}
				return errors.Join(cause, fmt.Errorf("откат остановлен: не удалось остановить новую службу: %w; резервные файлы сохранены: %s", err, strings.Join(backups, "; ")))
			}
		}
		var restoreErr error
		for i := len(staged) - 1; i >= 0; i-- {
			f := &staged[i]
			if !f.prepared {
				continue
			}
			if !f.changed && !f.Snapshot {
				continue
			}
			if err := os.Remove(f.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
				restoreErr = errors.Join(restoreErr, fmt.Errorf("удаление %s при откате: %w (копия: %s)", f.Path, err, f.backup))
				continue
			}
			if f.existed {
				if err := os.Rename(f.backup, f.Path); err != nil {
					restoreErr = errors.Join(restoreErr, fmt.Errorf("восстановление %s из %s: %w", f.Path, f.backup, err))
				}
			}
		}
		if restoreErr != nil {
			return errors.Join(cause, restoreErr)
		}
		return errors.Join(cause, wrap("восстановление службы после отката", call(hooks.Recover)))
	}
	for i := range staged {
		f := &staged[i]
		info, err := os.Lstat(f.Path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return rollback(fmt.Errorf("чтение %s: %w", f.Path, err))
		}
		f.existed = err == nil
		if f.existed {
			if !info.Mode().IsRegular() {
				return rollback(fmt.Errorf("%s не является обычным файлом", f.Path))
			}
			if f.Snapshot {
				f.backup, err = stage(stagedFile{File: File{Path: f.Path, Source: f.Path, Mode: info.Mode().Perm()}})
			} else {
				f.backup, err = reserve(filepath.Dir(f.Path))
				if err == nil {
					err = os.Rename(f.Path, f.backup)
				}
			}
			if err != nil {
				return rollback(fmt.Errorf("сохранение прежнего %s: %w", f.Path, err))
			}
		}
		f.prepared = true
		f.changed = !f.Snapshot
		if !f.Remove && !f.Snapshot {
			if err := os.Rename(f.stage, f.Path); err != nil {
				return rollback(fmt.Errorf("замена %s: %w", f.Path, err))
			}
			f.stage = ""
		}
	}
	started = true // Start may partially succeed before returning an error.
	if err := call(hooks.Start); err != nil {
		return rollback(fmt.Errorf("запуск новой установки: %w", err))
	}
	if err := call(hooks.Verify); err != nil {
		return rollback(fmt.Errorf("проверка новой установки: %w", err))
	}
	for _, f := range staged {
		if f.backup != "" {
			_ = os.Remove(f.backup)
		}
	}
	return nil
}

func call(f func() error) error {
	if f != nil {
		return f()
	}
	return nil
}

func wrap(action string, err error) error {
	if err != nil {
		return fmt.Errorf("%s: %w", action, err)
	}
	return nil
}

func reserve(dir string) (string, error) {
	f, err := os.CreateTemp(dir, ".na-rollback-*")
	if err != nil {
		return "", err
	}
	p := f.Name()
	if err := f.Close(); err != nil {
		_ = os.Remove(p)
		return "", err
	}
	return p, os.Remove(p)
}

func stage(f stagedFile) (path string, err error) {
	out, err := os.CreateTemp(filepath.Dir(f.Path), ".na-stage-*")
	if err != nil {
		return "", err
	}
	path = out.Name()
	defer func() {
		_ = out.Close()
		if err != nil {
			_ = os.Remove(path)
		}
	}()
	mode := f.Mode
	if mode == 0 {
		mode = 0o600
	}
	if err = out.Chmod(mode); err != nil {
		return path, err
	}
	if f.Source != "" {
		var in *os.File
		in, err = os.Open(f.Source)
		if err != nil {
			return path, err
		}
		_, err = io.Copy(out, in)
		closeErr := in.Close()
		if err == nil {
			err = closeErr
		}
	} else {
		_, err = out.Write(f.Data)
	}
	if err == nil {
		err = out.Sync()
	}
	if err == nil {
		err = out.Close()
	}
	return path, err
}
