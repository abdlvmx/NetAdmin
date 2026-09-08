package handlers

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netadmin/internal/auth"
	"netadmin/internal/web"
)

// Копии — единственная защита от потери всего учёта разом, и молчаливо
// переставшее работать расписание опаснее любой другой поломки в сводке:
// о нём узнают в день, когда копия понадобилась.

func TestBackupProblem(t *testing.T) {
	const day = 24 * time.Hour
	cases := []struct {
		name  string
		state backupState
		want  string // пусто — проблемы нет
	}{
		{
			"расписание выключено — не наше дело",
			backupState{Scheduled: false},
			"",
		},
		{
			"копии снимаются вовремя",
			backupState{Scheduled: true, Interval: day, Count: 7,
				Newest: time.Now().Add(-2 * time.Hour), InstallKnown: true, InstallAge: 30 * day},
			"",
		},
		{
			"расписание есть, копий нет, установка давно живёт",
			backupState{Scheduled: true, Interval: day, Count: 0,
				InstallKnown: true, InstallAge: 30 * day},
			"Копий нет ни одной",
		},
		{
			"копий нет, но и установке час от роду",
			backupState{Scheduled: true, Interval: day, Count: 0,
				InstallKnown: true, InstallAge: time.Hour},
			"",
		},
		{
			"возраст установки неизвестен — молчим",
			backupState{Scheduled: true, Interval: day, Count: 0},
			"",
		},
		{
			"последняя копия неделю назад при суточном расписании",
			backupState{Scheduled: true, Interval: day, Count: 3,
				Newest: time.Now().Add(-7 * day), InstallKnown: true, InstallAge: 30 * day},
			"Копии перестали сниматься",
		},
		{
			"сутки просрочки при часовом расписании — ещё не тревога",
			backupState{Scheduled: true, Interval: time.Hour, Count: 3,
				Newest: time.Now().Add(-3 * time.Hour), InstallKnown: true, InstallAge: 30 * day},
			"",
		},
		{
			"каталог недоступен",
			backupState{Scheduled: true, Interval: day, DirErr: errors.New("отказано в доступе")},
			"Каталог копий недоступен",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, _ := c.state.Problem()
			if got != c.want {
				t.Errorf("получено %q, ожидалось %q", got, c.want)
			}
		})
	}
}

// Ночной перезапуск сервера не должен поднимать тревогу: копия снимается в
// начале следующего круга, и одного пропущенного интервала мало.
func TestBackupToleratesOneMissedInterval(t *testing.T) {
	const day = 24 * time.Hour
	s := backupState{Scheduled: true, Interval: day, Count: 5,
		Newest: time.Now().Add(-30 * time.Hour), InstallKnown: true, InstallAge: 30 * day}
	if got, _ := s.Problem(); got != "" {
		t.Errorf("тревога на 30 часах при суточном расписании: %q", got)
	}
}

// Копия на том же диске, что и база, от отказа диска не спасает — а ради него
// копии и заводят.
func TestBackupSameVolume(t *testing.T) {
	s := backupState{Dir: `C:\ProgramData\NetAdmin\backups`}
	if !s.SameVolume(`C:\ProgramData\NetAdmin\netadmin.db`) {
		t.Error("один диск не распознан")
	}
	if s.SameVolume(`D:\backup\netadmin.db`) {
		t.Error("разные диски приняты за один")
	}

	// Сетевая папка — другой том, и это как раз то, чего мы хотим.
	unc := backupState{Dir: `\\nas\backups`}
	if unc.SameVolume(`C:\ProgramData\NetAdmin\netadmin.db`) {
		t.Error("сетевая папка принята за тот же диск")
	}
	// Каталог не определён — судить не о чем, и молчание лучше догадки.
	if (backupState{}).SameVolume(`C:\netadmin.db`) {
		t.Error("вывод сделан без каталога копий")
	}
}

// Проблема попадает в сводку строкой, а не счётчиком: у неё есть что сказать.
func TestBackupIssueAppearsInSummary(t *testing.T) {
	a := newTestApp(t)
	// Учётная запись, заведённая давно, — установка живёт достаточно, чтобы
	// копия успела не сняться.
	if _, err := a.DB.Exec(`INSERT INTO users (username, role, password_hash, created_at)
		VALUES ('admin','admin','x', datetime('now','-30 days'))`); err != nil {
		t.Fatalf("завести администратора: %v", err)
	}

	var found *issueGroup
	for _, g := range a.issueGroups() {
		if g.Cause == "Резервное копирование" {
			found = &g
			break
		}
	}
	if found == nil {
		t.Fatal("не снявшиеся копии не попали в сводку")
	}
	if !found.Crit {
		t.Error("потеря копий помечена как несрочная")
	}
	if len(found.Items) != 1 || found.Items[0].Href != "/settings" {
		t.Errorf("строка сводки не ведёт в настройки: %+v", found.Items)
	}
}

// На свежей установке тревоги быть не должно: первая копия снимается фоном.
func TestBackupQuietOnFreshInstall(t *testing.T) {
	a := newTestApp(t)
	if _, err := a.DB.Exec(
		`INSERT INTO users (username, role, password_hash) VALUES ('admin','admin','x')`); err != nil {
		t.Fatalf("завести администратора: %v", err)
	}
	for _, g := range a.issueGroups() {
		if g.Cause == "Резервное копирование" {
			t.Fatalf("тревога на установке, заведённой минуту назад: %+v", g.Items)
		}
	}
}

// Страница настроек показывает то же, что и сводка: человек приходит сюда
// чинить и не должен возвращаться на дашборд за подробностями.
func TestSettingsShowsBackupWarnings(t *testing.T) {
	rec := httptest.NewRecorder()
	web.RenderPage(rec, "settings", settingsData{
		User:             &auth.User{ID: 1, Username: "admin", Role: "admin"},
		Active:           "settings",
		BackupProblem:    "Копий нет ни одной: расписание включено, но ни одна копия так и не снялась",
		BackupSameVolume: true,
	})
	body := rec.Body.String()
	if strings.Contains(body, "template error") {
		t.Fatalf("ошибка шаблона: %s", body)
	}
	if !strings.Contains(body, "Копий нет ни одной") {
		t.Error("на странице настроек не сказано, что копии не снимаются")
	}
	if !strings.Contains(body, "том же диске") {
		t.Error("нет предупреждения о копиях на том же диске, что и база")
	}
}
