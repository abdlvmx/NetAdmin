// Package backup — резервные копии базы.
//
// Копия снимается средствами самого SQLite (VACUUM INTO): он делает
// согласованный снимок на работающей базе, не останавливая сервер и не
// требуя блокировок. Простое копирование файла так не умеет — рядом лежит
// журнал WAL, и копия без него оказывается битой.
package backup

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// prefix/suffix задают имя копии; по ним же они находятся при ротации,
// поэтому посторонние файлы в каталоге не пострадают.
const (
	prefix = "netadmin-"
	suffix = ".db"
	// stamp — метка времени в имени: сортируется как строка по возрастанию.
	stamp = "2006-01-02-1504"
)

// Info — сведения о существующей копии.
type Info struct {
	Name    string
	Path    string
	Size    int64
	Created time.Time
}

// Dir возвращает каталог копий, создавая его при необходимости.
//
// Права 0700 задаются потому, что копия содержит токены агентов и хеши
// паролей. Windows режим файла не соблюдает — там каталог нужно закрыть
// средствами NTFS, о чём сказано в README.
func Dir(dataDir, configured string) (string, error) {
	d := strings.TrimSpace(configured)
	if d == "" {
		d = filepath.Join(dataDir, "backups")
	}
	if err := os.MkdirAll(d, 0o700); err != nil {
		return "", err
	}
	return d, nil
}

// Create снимает копию базы в каталог и удаляет самые старые, оставляя keep
// последних. Возвращает путь созданной копии.
func Create(db *sql.DB, dir string, keep int) (string, error) {
	if db == nil {
		return "", errors.New("база недоступна")
	}
	name := prefix + time.Now().Format(stamp) + suffix
	path := filepath.Join(dir, name)

	// VACUUM INTO отказывается писать в существующий файл — при копии чаще
	// раза в минуту добавляем к имени секунды, чтобы не потерять запуск.
	if _, err := os.Stat(path); err == nil {
		name = prefix + time.Now().Format(stamp+"-05") + suffix
		path = filepath.Join(dir, name)
	}

	if _, err := db.Exec("VACUUM INTO ?", path); err != nil {
		return "", fmt.Errorf("снятие копии: %w", err)
	}
	// копия содержит токены агентов — доступ только владельцу
	// (на Windows не действует, см. комментарий к Dir)
	_ = os.Chmod(path, 0o600)

	if err := prune(dir, keep); err != nil {
		return path, fmt.Errorf("копия создана, но ротация не удалась: %w", err)
	}
	return path, nil
}

// List возвращает копии в каталоге, новые первыми.
func List(dir string) []Info {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []Info
	for _, e := range entries {
		if e.IsDir() || !isBackup(e.Name()) {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, Info{
			Name: e.Name(), Path: filepath.Join(dir, e.Name()),
			Size: fi.Size(), Created: fi.ModTime(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name > out[j].Name })
	return out
}

// prune оставляет keep самых свежих копий. keep <= 0 отключает ротацию:
// иначе опечатка в настройках стёрла бы весь архив.
func prune(dir string, keep int) error {
	if keep <= 0 {
		return nil
	}
	all := List(dir)
	for _, b := range all[min(keep, len(all)):] {
		if err := os.Remove(b.Path); err != nil {
			return err
		}
	}
	return nil
}

func isBackup(name string) bool {
	return strings.HasPrefix(name, prefix) && strings.HasSuffix(name, suffix)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
