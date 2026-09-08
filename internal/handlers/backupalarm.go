package handlers

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"netadmin/internal/backup"
	"netadmin/internal/config"
)

// Тревога по резервным копиям.
//
// Весь учёт — инвентарь, заявки, журнал действий — лежит в одном файле, и
// копии объявлены единственной страховкой от его потери. Но до сих пор
// неудачное копирование по расписанию оставляло единственный след: строку в
// журнале службы, которого никто не читает. Диск кончился месяц назад,
// каталог переехал, права слетели — узнают об этом в день, когда копия
// понадобится, то есть ровно тогда, когда узнавать поздно.
//
// Поэтому расписание, которое не срабатывает, теперь такая же проблема, как
// упавший сервис: она в сводке на дашборде, и о ней уходит письмо.

// backupState — что известно о копиях прямо сейчас.
type backupState struct {
	Scheduled bool          // расписание включено
	Dir       string        // каталог копий
	DirErr    error         // каталог недоступен
	Count     int           // сколько копий лежит
	Newest    time.Time     // время самой свежей
	Interval  time.Duration // как часто положено снимать
	// InstallAge — сколько живёт установка, InstallKnown — удалось ли это
	// выяснить. Нужны, чтобы не поднимать тревогу о ненаснятых копиях на
	// установке, заведённой пять минут назад: первая копия снимается фоном, и
	// пока она не снялась, жаловаться не на что.
	InstallAge   time.Duration
	InstallKnown bool
}

// overdueAfter — с какого запаздывания копия считается несостоявшейся.
//
// Два интервала, но не меньше суток. Один интервал — слишком строго: сервер
// мог быть выключен, копия снимается в начале следующего круга, и тревога
// загоралась бы после каждой ночной перезагрузки. Сутки снизу — чтобы
// расписание «раз в час» не поднимало тревогу через два часа простоя.
func (s backupState) overdueAfter() time.Duration {
	d := 2 * s.Interval
	if d < 24*time.Hour {
		d = 24 * time.Hour
	}
	return d
}

// Problem описывает, что не так с копиями. Пустая строка — всё в порядке.
//
// Выключенное расписание проблемой не считается: это осознанная настройка, и
// звать к ней человека, который её сам и выключил, — способ приучить не читать
// сводку. О том, что копий стоило бы завести, говорит чек-лист первых шагов.
func (s backupState) Problem() (title, detail string) {
	if !s.Scheduled {
		return "", ""
	}
	if s.DirErr != nil {
		return "Каталог копий недоступен", s.DirErr.Error()
	}
	if s.Count == 0 {
		if !s.InstallKnown || s.InstallAge < s.overdueAfter() {
			return "", "" // установка слишком молода, копия ещё впереди
		}
		return "Копий нет ни одной",
			"расписание включено, но ни одна копия так и не снялась"
	}
	if age := time.Since(s.Newest); age > s.overdueAfter() {
		return "Копии перестали сниматься",
			fmt.Sprintf("последняя — %s назад, а расписание раз в %s",
				humanDuration(age), humanDuration(s.Interval))
	}
	return "", ""
}

// SameVolume — копии лежат на том же диске, что и база.
//
// От отказа диска, ради которого копирование и заводят, такая копия не
// спасает: она умрёт вместе с оригиналом. Это не поломка, а недосмотр в
// настройке, поэтому место ему на странице настроек, а не в тревоге.
func (s backupState) SameVolume(dbPath string) bool {
	if s.Dir == "" || s.DirErr != nil {
		return false
	}
	a := strings.ToLower(filepath.VolumeName(mustAbs(s.Dir)))
	b := strings.ToLower(filepath.VolumeName(mustAbs(dbPath)))
	// Пустое имя тома — путь без буквы диска (не Windows): судить не о чем.
	return a != "" && a == b
}

func mustAbs(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return p
}

// backupStatus собирает состояние копий по текущим настройкам.
func backupStatus(cfg config.Config) backupState {
	s := backupState{
		Scheduled: cfg.BackupIntervalHours > 0,
		Interval:  time.Duration(cfg.BackupIntervalHours) * time.Hour,
	}
	dir, err := backup.Dir(config.DataDir(), cfg.BackupDir)
	if err != nil {
		s.DirErr = err
		return s
	}
	s.Dir = dir
	list := backup.List(dir)
	s.Count = len(list)
	// Берём самую позднюю по времени файла, а не первую в списке: List
	// упорядочивает по имени, а имя и время расходятся, стоит файл тронуть.
	for _, b := range list {
		if b.Created.After(s.Newest) {
			s.Newest = b.Created
		}
	}
	return s
}

// backupIssues — строка сводки «Требует внимания» про копии.
func (a *App) backupIssues() issueGroup {
	g := issueGroup{Cause: "Резервное копирование", Crit: true, Href: "/settings"}
	st := backupStatus(config.Load())
	st.InstallAge, st.InstallKnown = a.installedFor()
	title, detail := st.Problem()
	if title == "" {
		return g
	}
	g.Total = 1
	age := ""
	if !st.Newest.IsZero() {
		age = humanDuration(time.Since(st.Newest))
	}
	g.Items = []issueItem{{Title: title, Detail: detail, Age: age, Href: "/settings"}}
	return g
}

// installedFor — сколько живёт эта установка, считая от заведения первой
// учётной записи: её создаёт мастер первого запуска, и другого следа «когда всё
// началось» в базе нет.
func (a *App) installedFor() (time.Duration, bool) {
	var first string
	if a.DB.QueryRow("SELECT MIN(created_at) FROM users").Scan(&first) != nil || first == "" {
		return 0, false
	}
	for _, layout := range []string{"2006-01-02 15:04:05", "2006-01-02T15:04:05Z"} {
		if t, err := time.Parse(layout, first); err == nil {
			return time.Since(t.UTC()), true
		}
	}
	return 0, false
}

// humanDuration — длительность словами, теми же ступенями, что и давность
// проблем в сводке.
func humanDuration(d time.Duration) string {
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%d мин", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%d ч", int(d.Hours()))
	default:
		return fmt.Sprintf("%d дн", int(d.Hours())/24)
	}
}

// backupProblemText — та же проблема, что уходит в сводку, но одной строкой
// для страницы настроек: человек, пришедший сюда чинить, должен увидеть, что
// именно не так, не возвращаясь на дашборд.
func backupProblemText(s backupState) string {
	title, detail := s.Problem()
	if title == "" {
		return ""
	}
	if detail == "" {
		return title
	}
	return title + ": " + detail
}
