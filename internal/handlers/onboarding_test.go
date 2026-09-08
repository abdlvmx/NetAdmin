package handlers

import (
	"net/http/httptest"
	"strings"
	"testing"

	"netadmin/internal/auth"
	"netadmin/internal/config"
	"netadmin/internal/web"
)

// Свежая установка: не сделано ничего, и первым раскрыт первый же шаг.
func TestOnboardingOnEmptyInstall(t *testing.T) {
	o := buildOnboarding(onboardingFacts{})
	if o.Done != 0 {
		t.Errorf("пройдено %d шагов из ничего", o.Done)
	}
	if o.Next != 1 {
		t.Errorf("следующий шаг %d, ожидался первый", o.Next)
	}
	if o.Pct != 0 {
		t.Errorf("прогресс %d%%, ожидался 0", o.Pct)
	}
	if !o.Steps[0].Now {
		t.Error("первый шаг не помечен текущим")
	}
	for _, s := range o.Steps[1:] {
		if s.Now {
			t.Errorf("шаг %d тоже помечен текущим — раскрытым должен быть один", s.Num)
		}
	}
}

// Всё пройдено — карточке нечего сказать, и Next это показывает.
func TestOnboardingAllDone(t *testing.T) {
	o := buildOnboarding(onboardingFacts{
		IsService: true, AgentsTotal: 2, Discovered: 3,
		BackupsOn: true, BackupsExist: true, NotifyOn: true,
	})
	if o.Next != 0 {
		t.Errorf("Next = %d, ожидался 0: невыполненных шагов нет", o.Next)
	}
	if o.Done != o.Total || o.Pct != 100 {
		t.Errorf("пройдено %d из %d (%d%%)", o.Done, o.Total, o.Pct)
	}
}

// Текущий — первый невыполненный, а не первый попавшийся: шаг про службу можно
// пройти позже остальных, и чек-лист не должен на нём застревать.
func TestOnboardingNextIsFirstUndone(t *testing.T) {
	o := buildOnboarding(onboardingFacts{IsService: true, AgentsTotal: 1})
	if o.Next != 3 {
		t.Fatalf("Next = %d, ожидался третий шаг (агенты на остальных ПК)", o.Next)
	}
	if o.Done != 2 {
		t.Errorf("пройдено %d, ожидалось 2", o.Done)
	}
	if !o.Steps[2].Now {
		t.Error("третий шаг не раскрыт")
	}
}

// Второй шаг — единственный с кнопкой прямого действия, и она появляется
// только там, где сервер действительно умеет поставить агента себе.
func TestOnboardingLocalAgentButton(t *testing.T) {
	with := buildOnboarding(onboardingFacts{CanInstallLocalAgent: true})
	if with.Steps[1].Post == "" {
		t.Error("кнопка установки на этот компьютер не появилась")
	}
	if with.Steps[1].Ask == "" {
		t.Error("установка агента отправляется без подтверждения")
	}

	without := buildOnboarding(onboardingFacts{})
	if without.Steps[1].Post != "" {
		t.Error("кнопка установки предложена там, где сервер этого не умеет")
	}
	if without.Steps[1].Href == "" || without.Steps[1].Action == "" {
		t.Error("шаг остался без всякого действия — тупик вместо подсказки")
	}
}

// Последний шаг закрывает два дела сразу, и текст обязан называть незакрытое:
// «настройте копии и уведомления» ничего не говорит тому, кто одно уже сделал.
func TestOnboardingBackupNotifyWording(t *testing.T) {
	cases := []struct {
		name  string
		facts onboardingFacts
		want  string
	}{
		{"ничего не настроено", onboardingFacts{}, "копий его пока нет, а о поломках"},
		{"почта есть, копий нет", onboardingFacts{NotifyOn: true}, "копий его пока нет."},
		{"расписание есть, копий нет", onboardingFacts{BackupsOn: true, NotifyOn: true},
			"ни одна копия ещё не снялась"},
		{"копии есть, почты нет", onboardingFacts{BackupsOn: true, BackupsExist: true},
			"почта не настроена"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := backupNotifyDetail(c.facts)
			if !strings.Contains(got, c.want) {
				t.Errorf("текст %q не называет незакрытое (%q)", got, c.want)
			}
		})
	}
}

// Кому чек-лист не показывается.
func TestOnboardingVisibility(t *testing.T) {
	app := newTestApp(t)
	admin := &auth.User{ID: 1, Username: "admin", Role: "admin"}

	if app.onboardingFor(nil, config.Config{}) != nil {
		t.Error("чек-лист показан анониму")
	}
	if app.onboardingFor(&auth.User{ID: 2, Role: "user"}, config.Config{}) != nil {
		t.Error("чек-лист показан роли, которой закрыты настройки")
	}
	if app.onboardingFor(admin, config.Config{OnboardingHidden: true}) != nil {
		t.Error("чек-лист показан после того, как его убрали")
	}

	// Витрина: парк вымышленный, служба не ставилась — советовать смотрящему
	// установить её значит советовать ерунду.
	demo := newTestApp(t)
	demo.Demo = true
	if demo.onboardingFor(admin, config.Config{}) != nil {
		t.Error("чек-лист показан в демонстрационном режиме")
	}

	if app.onboardingFor(admin, config.Config{}) == nil {
		t.Error("на пустой установке чек-лист не показан")
	}
}

// Шаги считаются по следам в системе, а не по отметке «сделано»: заведённый
// агент закрывает свой шаг сам.
func TestOnboardingCountsRealAgents(t *testing.T) {
	app := newTestApp(t)
	admin := &auth.User{ID: 1, Username: "admin", Role: "admin"}

	o := app.onboardingFor(admin, config.Config{})
	if o == nil || o.Steps[1].Done {
		t.Fatal("шаг про первого агента засчитан на пустой базе")
	}

	if _, err := app.DB.Exec(
		`INSERT INTO devices (hostname, agent_token) VALUES ('WS-1','tok')`); err != nil {
		t.Fatalf("завести устройство: %v", err)
	}
	o = app.onboardingFor(admin, config.Config{})
	if o == nil || !o.Steps[1].Done {
		t.Error("устройство с агентом не закрыло свой шаг")
	}
	if o.Steps[2].Done {
		t.Error("одна машина засчитана за «остальные компьютеры»")
	}
}

// Разметка: раскрыт ровно один шаг, и у него есть чем воспользоваться.
func TestDashboardRendersOnboarding(t *testing.T) {
	o := buildOnboarding(onboardingFacts{})
	rec := httptest.NewRecorder()
	web.RenderPage(rec, "dashboard", dashData{
		User:       &auth.User{ID: 1, Username: "admin", Role: "admin"},
		Active:     "dashboard",
		Onboarding: &o,
	})
	body := rec.Body.String()
	if strings.Contains(body, "template error") {
		t.Fatalf("ошибка шаблона: %s", body)
	}
	if !strings.Contains(body, "Начать работу") {
		t.Fatal("карточки чек-листа нет на странице")
	}
	// первый шаг делается в консоли — команда должна быть готова к копированию
	if !strings.Contains(body, "netadmin.exe -install") {
		t.Error("команда установки службой не показана")
	}
	// подробности следующих шагов не раскрыты
	if strings.Contains(body, "ARP-кэш") {
		t.Error("раскрыт не только текущий шаг")
	}
	if !strings.Contains(body, `action="/dashboard/onboarding"`) {
		t.Error("нет кнопки «Скрыть»")
	}
}

// Дашборд без чек-листа не должен ничего терять и ничего показывать лишнего.
func TestDashboardWithoutOnboarding(t *testing.T) {
	rec := httptest.NewRecorder()
	web.RenderPage(rec, "dashboard", dashData{
		User:   &auth.User{ID: 1, Username: "admin", Role: "admin"},
		Active: "dashboard",
	})
	body := rec.Body.String()
	if strings.Contains(body, "template error") {
		t.Fatalf("ошибка шаблона: %s", body)
	}
	if strings.Contains(body, "Начать работу") {
		t.Error("карточка показана, хотя её не передавали")
	}
}
