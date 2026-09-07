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
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite" // Verify открывает копию собственным соединением
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

// --- Восстановление ---
//
// Подменить файл работающей базы нельзя: он открыт, рядом лежит журнал WAL, а
// соединения в пуле продолжают писать. Поэтому восстановление разделено на два
// шага: выбранная копия проверяется и кладётся рядом с базой под именем
// netadmin.db.restore, а подмена происходит при следующем запуске, до открытия
// базы. Так восстановление либо проходит целиком, либо не начинается вовсе.

const (
	pendingSuffix  = ".restore"
	replacedSuffix = ".before-restore-"
)

// PendingPath — путь файла, ожидающего применения.
func PendingPath(dbPath string) string { return dbPath + pendingSuffix }

// Pending сообщает, подготовлено ли восстановление.
func Pending(dbPath string) bool {
	_, err := os.Stat(PendingPath(dbPath))
	return err == nil
}

// Verify проверяет, что файл — исправная база NetAdmin.
//
// Проверяются обе стороны: целостность (integrity_check) и то, что это вообще
// та база — у чужого файла sqlite или у обрезанной копии не окажется таблицы
// users. Без второй проверки восстановление «успешно» подменило бы рабочую
// базу пустышкой.
func Verify(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("файл копии недоступен: %w", err)
	}
	if st.Size() == 0 {
		return errors.New("файл копии пуст")
	}

	// Открываем только на чтение: проверка не должна ничего дописывать
	// в копию — иначе она перестала бы совпадать с тем, что снял VACUUM INTO.
	d, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?mode=ro&_pragma=busy_timeout(3000)")
	if err != nil {
		return fmt.Errorf("копия не открывается: %w", err)
	}
	defer d.Close()

	var res string
	if err := d.QueryRow("PRAGMA integrity_check").Scan(&res); err != nil {
		return fmt.Errorf("копия повреждена или не является базой SQLite: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(res), "ok") {
		return fmt.Errorf("копия повреждена: %s", res)
	}

	var users int
	if err := d.QueryRow("SELECT COUNT(*) FROM users").Scan(&users); err != nil {
		return fmt.Errorf("это не база NetAdmin: %w", err)
	}
	if users == 0 {
		return errors.New("в копии нет ни одной учётной записи — восстановление отрезало бы вход")
	}
	return nil
}

// StageRestore проверяет копию и готовит её к применению при следующем запуске.
func StageRestore(dbPath, backupPath string) error {
	if err := Verify(backupPath); err != nil {
		return err
	}
	tmp := PendingPath(dbPath) + ".tmp"
	if err := copyFile(backupPath, tmp); err != nil {
		return fmt.Errorf("подготовка восстановления: %w", err)
	}
	// Переименование поверх — атомарная часть: наполовину скопированный файл
	// не должен оказаться подготовленным к подмене.
	if err := os.Rename(tmp, PendingPath(dbPath)); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("подготовка восстановления: %w", err)
	}
	return nil
}

// CancelPending отменяет подготовленное восстановление.
func CancelPending(dbPath string) error {
	err := os.Remove(PendingPath(dbPath))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// ApplyPending подменяет базу подготовленной копией. Вызывается при запуске
// до открытия базы. Возвращает путь сохранённой прежней базы, если подмена
// состоялась.
//
// Прежняя база не удаляется, а откладывается в сторону: восстановление «не из
// той копии» — ошибка, которую замечают через минуту, и вернуться должно быть
// куда.
func ApplyPending(dbPath string) (string, error) {
	pending := PendingPath(dbPath)
	if _, err := os.Stat(pending); err != nil {
		return "", nil // подготовленного восстановления нет — обычный запуск
	}

	// Проверяем ещё раз: между подготовкой и запуском файл мог испортиться,
	// а подменять рабочую базу непроверенным нельзя.
	if err := Verify(pending); err != nil {
		_ = os.Remove(pending)
		return "", fmt.Errorf("подготовленная копия не прошла проверку, восстановление отменено: %w", err)
	}

	saved := dbPath + replacedSuffix + time.Now().Format(stamp) + suffix
	if _, err := os.Stat(dbPath); err == nil {
		if err := os.Rename(dbPath, saved); err != nil {
			return "", fmt.Errorf("прежнюю базу не отложить в сторону: %w", err)
		}
	} else {
		saved = ""
	}

	if err := os.Rename(pending, dbPath); err != nil {
		// возвращаем прежнюю базу на место — лучше остаться как было
		if saved != "" {
			_ = os.Rename(saved, dbPath)
		}
		return "", fmt.Errorf("подмена базы: %w", err)
	}

	// Журналы относятся к прежней базе: оставить их рядом с восстановленной —
	// верный способ получить «database disk image is malformed».
	_ = os.Remove(dbPath + "-wal")
	_ = os.Remove(dbPath + "-shm")
	return saved, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
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
