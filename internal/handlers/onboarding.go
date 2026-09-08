package handlers

import (
	"net/http"

	"netadmin/internal/auth"
	"netadmin/internal/backup"
	"netadmin/internal/config"
)

// Чек-лист первых шагов.
//
// Мастер первого запуска заканчивается созданием администратора — и человек
// попадает на дашборд, где пусто всё: ноль устройств, ноль заявок, ноль
// метрик. Что продукт умеет, видно из меню; что нужно сделать, чтобы он начал
// это уметь, — ниоткуда. Порядок при этом есть, и он неочевиден: сервер, пока
// его не поставили службой, живёт до закрытия окна; агент на своей машине
// ставится одной кнопкой, а на чужие — кодом; копии и письма настраивают,
// когда уже есть что терять и о чём сообщать.
//
// Отсюда карточка на дашборде: пять шагов, у каждого одна кнопка и проверка,
// что шаг действительно сделан. Проверка — по следам в системе, а не по
// отметке «выполнено»: галочка, которую можно поставить, ничего не сделав,
// хуже её отсутствия.
//
// Карточка исчезает сама, когда шаги пройдены, и прячется по кнопке для тех,
// кто держит сервер в консоли намеренно и не хочет об этом читать.

// onboardingFacts — всё, на чём строится чек-лист.
//
// Вынесено отдельной структурой, чтобы шаги считались чистой функцией и
// проверялись тестом: службу Windows, парк машин и настроенную почту в тесте
// не соберёшь, а решение «что показать» проверить надо.
type onboardingFacts struct {
	IsService    bool // сервер запущен диспетчером служб, а не из консоли
	AgentsTotal  int  // устройств с установленным агентом
	Discovered   int  // строк в очереди обнаружения
	BackupsOn    bool // расписание копий включено
	BackupsExist bool // хотя бы одна копия снята
	NotifyOn     bool // SMTP заполнен
	// CanInstallLocalAgent — агента можно поставить на эту машину кнопкой.
	// Иначе шаг ведёт в настройки, где перечислены остальные способы.
	CanInstallLocalAgent bool
}

// onboardingStep — один шаг чек-листа.
//
// Номер и признак «сейчас» считаются здесь, а не в шаблоне: арифметика в
// разметке читается плохо и в html/template требует своих функций.
type onboardingStep struct {
	Num    int
	Now    bool // первый невыполненный — только он раскрыт
	Title  string
	Detail string // зачем это нужно и что произойдёт — только у текущего шага
	Done   bool
	Action string // подпись кнопки; пусто — кнопки нет
	Href   string // действие открывает страницу
	Post   string // действие отправляет форму по этому адресу
	Ask    string // подтверждение перед отправкой формы
	Cmd    string // команда для консоли: в браузере этот шаг не сделать
}

// onboarding — состояние чек-листа для шаблона.
type onboarding struct {
	Steps []onboardingStep
	Done  int
	Total int
	// Next — номер первого невыполненного шага (с единицы). Ноль означает, что
	// невыполненных не осталось.
	Next int
	// Pct — доля пройденного для полосы прогресса.
	Pct int
}

// buildOnboarding раскладывает факты по шагам.
func buildOnboarding(f onboardingFacts) onboarding {
	steps := []onboardingStep{
		{
			Title: "Сервер работает постоянно",
			Done:  f.IsService,
			Detail: "Сейчас сервер живёт, пока открыто окно консоли: закройте его — " +
				"и панель погаснет, а агенты перестанут отчитываться. Установка службой " +
				"запускает его вместе с Windows и не требует, чтобы кто-то был в системе. " +
				"Выполните команду в консоли на этой машине — Windows сама запросит права.",
			Cmd: "netadmin.exe -install",
		},
		{
			Title: "Агент на первом компьютере",
			Done:  f.AgentsTotal >= 1,
			Detail: "Без агента о машине известно только то, что видно снаружи: адрес и " +
				"отвечает ли она на ping. Загрузка, диски, установленные программы, службы " +
				"и удалённые команды появляются вместе с ним. Начните с этого компьютера — " +
				"агент уже внутри сервера, скачивать и копировать ничего не нужно.",
		},
		{
			Title: "Агенты на остальных компьютерах",
			Done:  f.AgentsTotal >= 2,
			Detail: "Создайте одноразовый код и выполните показанную строку на нужной " +
				"машине в PowerShell от имени администратора. Код сам перестаёт действовать " +
				"по сроку и числу установок. Если агент не подключается — скорее всего, " +
				"на этом компьютере закрыт порт 8765: откройте его командой " +
				"netadmin.exe -install -firewall.",
			Action: "Создать код",
			Href:   "/settings",
		},
		{
			Title: "Обнаружение сети",
			Done:  f.Discovered >= 1,
			Detail: "Сервер смотрит ARP-кэш и показывает хосты, которых нет в инвентаре: " +
				"принтеры, коммутаторы, чужие ноутбуки. Активного сканирования при этом не " +
				"идёт, сеть не опрашивается. Найденное можно добавить в инвентарь, отметить " +
				"гостевым или скрыть.",
			Action: "Открыть обнаружение",
			Href:   "/discovery",
		},
		{
			Title: "Резервные копии и уведомления",
			Done:  f.BackupsOn && f.BackupsExist && f.NotifyOn,
			Detail: backupNotifyDetail(f) + " Копия снимается средствами самой базы, на " +
				"работающем сервере; письма уходят, когда сервис упал, диск близок к отказу " +
				"или пришла заявка.",
			Action: "Открыть настройки",
			Href:   "/settings",
		},
	}

	// Кнопка установки агента на эту машину есть не всегда: сервер может быть
	// собран без встроенного агента или запущен не в Windows. Тогда шаг ведёт
	// в настройки, где перечислены остальные способы, — но не исчезает.
	if f.CanInstallLocalAgent {
		steps[1].Action = "Установить на этот компьютер"
		steps[1].Post = "/settings/agent-install-local"
		steps[1].Ask = "Установить агент NetAdmin на этот компьютер?"
	} else {
		steps[1].Action = "Открыть настройки"
		steps[1].Href = "/settings"
	}

	o := onboarding{Steps: steps, Total: len(steps)}
	for i := range o.Steps {
		o.Steps[i].Num = i + 1
		if o.Steps[i].Done {
			o.Done++
			continue
		}
		if o.Next == 0 {
			o.Next = i + 1
			o.Steps[i].Now = true
		}
	}
	o.Pct = o.Done * 100 / o.Total
	return o
}

// backupNotifyDetail называет то, чего не хватает: шаг закрывает сразу два
// дела, и «настройте копии и уведомления» ничего не говорит тому, кто одно из
// двух уже настроил.
func backupNotifyDetail(f onboardingFacts) string {
	switch {
	case !f.BackupsOn && !f.NotifyOn:
		return "Весь учёт лежит в одном файле, и копий его пока нет, а о поломках " +
			"сервер сообщить некому."
	case !f.BackupsOn:
		return "Весь учёт лежит в одном файле, и копий его пока нет."
	case !f.BackupsExist:
		return "Расписание копий задано, но ни одна копия ещё не снялась — " +
			"проверьте, что каталог доступен на запись."
	case !f.NotifyOn:
		return "Копии снимаются, но о поломках сервер сообщить некому: " +
			"почта не настроена."
	}
	return ""
}

// onboardingFor собирает чек-лист для дашборда. Возвращает nil, когда
// показывать нечего.
func (a *App) onboardingFor(user *auth.User, cfg config.Config) *onboarding {
	// Только администратору: три шага из пяти ведут в настройки, куда
	// остальным ролям хода нет, и звать туда их незачем.
	if user == nil || !user.IsAdmin() {
		return nil
	}
	// В витрине чек-лист врал бы: парк вымышленный, служба не ставилась, а
	// советовать смотрящему установить её — последнее, чего он ждёт.
	if a.Demo || cfg.OnboardingHidden {
		return nil
	}

	f := onboardingFacts{
		IsService:            a.IsService,
		CanInstallLocalAgent: a.InstallAgent != nil,
		BackupsOn:            cfg.BackupIntervalHours > 0,
		NotifyOn:             cfg.SMTPHost != "",
	}
	_ = a.DB.QueryRow(
		"SELECT COUNT(*) FROM devices WHERE COALESCE(agent_token,'')<>''").Scan(&f.AgentsTotal)
	_ = a.DB.QueryRow("SELECT COUNT(*) FROM discovery_queue").Scan(&f.Discovered)
	if f.BackupsOn {
		if dir, err := backupDir(cfg); err == nil {
			f.BackupsExist = len(backup.List(dir)) > 0
		}
	}

	o := buildOnboarding(f)
	if o.Next == 0 {
		return nil // всё пройдено — карточке больше нечего сказать
	}
	return &o
}

// HideOnboarding — POST /dashboard/onboarding (admin): скрыть или вернуть
// чек-лист.
//
// Решение живёт в config.json, а не у конкретного администратора: чек-лист
// описывает состояние установки, а не личный прогресс, и скрытый одним он
// скрыт для всех.
func (a *App) HideOnboarding(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil || !user.IsAdmin() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	_ = r.ParseForm()
	hide := r.FormValue("hidden") == "1"

	cfg := config.Load()
	cfg.OnboardingHidden = hide
	if err := config.Save(cfg); err != nil {
		http.Error(w, "не удалось сохранить настройку: "+err.Error(),
			http.StatusInternalServerError)
		return
	}
	action := "onboarding_show"
	if hide {
		action = "onboarding_hide"
	}
	auth.LogAction(a.DB, user.ID, action, "dashboard", "")

	dest := "/dashboard"
	if !hide {
		dest = "/settings?message=onboarding_shown"
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}
