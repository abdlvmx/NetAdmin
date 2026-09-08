package handlers

import (
	"fmt"
	"log"
	"sort"
	"time"
)

// Сводка «Требует внимания».
//
// Раньше это были пять строк со счётчиками: «Сервисы не отвечают — 3», ссылка
// в раздел. Чтобы понять, что случилось, приходилось открывать раздел и искать
// глазами, а до тех пор было известно только количество. Между тем на вопрос
// «что чинить прямо сейчас» отвечают не числа, а имена: какая машина, как
// давно и куда нажать.
//
// Поэтому теперь группа по причине, а внутри — сами проблемы, у каждой имя,
// суть и давность, и каждая ведёт на свой объект, а не в раздел. Давность важна
// не меньше самой проблемы: машина, молчащая три минуты, и машина, молчащая три
// дня, — разные события, а выглядели они одинаково.
//
// Показывается не всё: список из сорока строк — это уже не сводка. Первые
// несколько и ссылка «ещё N» в раздел, где они все.

// issueItem — одна конкретная проблема.
type issueItem struct {
	Title  string // с чем: имя машины, сервиса, устройства
	Detail string // что именно не так
	Age    string // как давно, пусто — если неизвестно
	Href   string // куда идти чинить
}

// issueGroup — проблемы одной причины.
type issueGroup struct {
	Cause string // «Нет связи», «Диски: ожидается отказ»
	Crit  bool   // уже сломано, а не сломается
	Total int    // всего проблем этой причины
	More  int    // сколько не поместилось в список
	Href  string // раздел, где они все
	Items []issueItem
}

// maxIssueItems — сколько проблем одной причины показывать. Четыре: столько
// помещается, не превращая сводку в таблицу, и столько же обычно успевают
// разобрать за раз.
const maxIssueItems = 4

// issueGroups собирает сводку по всем источникам.
//
// Каждый источник — отдельный запрос, потому что «проблема» у них своя:
// у машины это молчание, у сервиса — отказ проверки, у диска — вердикт SMART.
// Свести их в один SQL можно, но читать такой запрос было бы невозможно, а
// меняются они порознь.
func (a *App) issueGroups() []issueGroup {
	groups := []issueGroup{
		a.offlineDevices(),
		a.overloadedDevices(),
		a.downServices(),
		a.downSNMP(),
		a.supplyAlerts(),
		a.backupIssues(),
	}
	groups = append(groups, a.diskGroups()...)

	out := make([]issueGroup, 0, len(groups))
	for _, g := range groups {
		if g.Total > 0 {
			out = append(out, g)
		}
	}
	// Сломанное выше того, что сломается; при равной срочности — где больше.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Crit != out[j].Crit {
			return out[i].Crit
		}
		return out[i].Total > out[j].Total
	})
	return out
}

// offlineDevices — машины, потерявшие связь.
//
// Отбор тот же, что у карточки «Предупреждения», за вычетом перегрузки: она
// отдельная причина, и мешать «машина молчит» с «машине тяжело» — значит
// требовать разных действий в одной строке.
func (a *App) offlineDevices() issueGroup {
	g := issueGroup{Cause: "Нет связи", Crit: true, Href: "/devices?alerts=1"}
	rows, err := a.DB.Query(`SELECT id, hostname, COALESCE(status,''), COALESCE(last_seen,'')
		FROM devices
		WHERE status='offline'
		   OR (last_seen IS NOT NULL AND last_seen < datetime('now','-10 minutes'))
		ORDER BY COALESCE(last_seen,'') ASC`)
	if err != nil {
		log.Printf("сводка, устройства без связи: %v", err)
		return g
	}
	defer rows.Close()
	for rows.Next() {
		var (
			id                     int64
			host, status, lastSeen string
		)
		if rows.Scan(&id, &host, &status, &lastSeen) != nil {
			continue
		}
		g.Total++
		if len(g.Items) < maxIssueItems {
			detail := "не отвечает"
			if status != "offline" {
				detail = "агент молчит"
			}
			g.Items = append(g.Items, issueItem{
				Title:  host,
				Detail: detail,
				Age:    humanAgo(lastSeen),
				Href:   fmt.Sprintf("/devices/%d", id),
			})
		}
	}
	g.More = g.Total - len(g.Items)
	return g
}

// overloadedDevices — машины на пределе по ресурсу.
func (a *App) overloadedDevices() issueGroup {
	g := issueGroup{Cause: "Ресурсы на пределе", Href: "/devices?alerts=1"}
	rows, err := a.DB.Query(`SELECT id, hostname, cpu_usage, ram_usage, disk_usage,
			COALESCE(last_seen,'')
		FROM devices
		WHERE status<>'offline' AND (cpu_usage>=90 OR ram_usage>=90 OR disk_usage>=90)
		ORDER BY MAX(cpu_usage, ram_usage, disk_usage) DESC`)
	if err != nil {
		log.Printf("сводка, перегруженные устройства: %v", err)
		return g
	}
	defer rows.Close()
	for rows.Next() {
		var (
			id             int64
			host, lastSeen string
			cpu, ram, disk float64
		)
		if rows.Scan(&id, &host, &cpu, &ram, &disk, &lastSeen) != nil {
			continue
		}
		g.Total++
		if len(g.Items) < maxIssueItems {
			g.Items = append(g.Items, issueItem{
				Title:  host,
				Detail: worstResource(cpu, ram, disk),
				Age:    humanAgo(lastSeen),
				Href:   fmt.Sprintf("/devices/%d", id),
			})
		}
	}
	g.More = g.Total - len(g.Items)
	return g
}

// worstResource называет то, чего не хватает сильнее прочего: перечислять все
// три показателя в строке сводки незачем, решение принимается по худшему.
func worstResource(cpu, ram, disk float64) string {
	switch {
	case cpu >= ram && cpu >= disk:
		return fmt.Sprintf("CPU %.0f%%", cpu)
	case ram >= disk:
		return fmt.Sprintf("память %.0f%%", ram)
	default:
		return fmt.Sprintf("диск занят на %.0f%%", disk)
	}
}

// downServices — проверки сервисов, которые не проходят.
func (a *App) downServices() issueGroup {
	g := issueGroup{Cause: "Сервисы не отвечают", Crit: true, Href: "/monitoring"}
	rows, err := a.DB.Query(`SELECT COALESCE(name,''), COALESCE(type,''), COALESCE(target,''),
			COALESCE(last_check,'')
		FROM service_checks
		WHERE enabled=1 AND last_status='down'
		ORDER BY COALESCE(last_check,'') ASC`)
	if err != nil {
		log.Printf("сводка, упавшие сервисы: %v", err)
		return g
	}
	defer rows.Close()
	for rows.Next() {
		var name, kind, target, checked string
		if rows.Scan(&name, &kind, &target, &checked) != nil {
			continue
		}
		g.Total++
		if len(g.Items) < maxIssueItems {
			if name == "" {
				name = target
			}
			g.Items = append(g.Items, issueItem{
				Title:  name,
				Detail: describeCheck(kind, target),
				Age:    humanAgo(checked),
				Href:   "/monitoring",
			})
		}
	}
	g.More = g.Total - len(g.Items)
	return g
}

// describeCheck — чем именно проверялся сервис. Тип проверки без адреса
// («HTTP») не говорит ничего, адрес без типа — почти ничего.
func describeCheck(kind, target string) string {
	switch {
	case kind == "" && target == "":
		return "проверка не проходит"
	case kind == "":
		return target
	case target == "":
		return kind
	}
	return kind + " " + target
}

// downSNMP — сетевое оборудование, которое не отвечает на опрос.
func (a *App) downSNMP() issueGroup {
	g := issueGroup{Cause: "SNMP-устройства недоступны", Crit: true, Href: "/snmp"}
	rows, err := a.DB.Query(`SELECT id, COALESCE(name,''), COALESCE(ip,''), COALESCE(last_poll,'')
		FROM snmp_devices
		WHERE enabled=1 AND last_status='down'
		ORDER BY COALESCE(last_poll,'') ASC`)
	if err != nil {
		log.Printf("сводка, недоступные SNMP: %v", err)
		return g
	}
	defer rows.Close()
	for rows.Next() {
		var (
			id             int64
			name, ip, poll string
		)
		if rows.Scan(&id, &name, &ip, &poll) != nil {
			continue
		}
		g.Total++
		if len(g.Items) < maxIssueItems {
			if name == "" {
				name = ip
			}
			g.Items = append(g.Items, issueItem{
				Title:  name,
				Detail: "не отвечает на опрос " + ip,
				Age:    humanAgo(poll),
				Href:   fmt.Sprintf("/snmp/%d/ports", id),
			})
		}
	}
	g.More = g.Total - len(g.Items)
	return g
}

// supplyAlerts — заканчивающийся тонер и ИБП на батарее.
func (a *App) supplyAlerts() issueGroup {
	g := issueGroup{Cause: "Расходники и батареи на исходе", Href: "/snmp"}
	rows, err := a.DB.Query(`SELECT id, COALESCE(name,''), COALESCE(ip,''),
			COALESCE(detail,''), COALESCE(last_poll,'')
		FROM snmp_devices
		WHERE enabled=1 AND COALESCE(supply_alert,0)=1
		ORDER BY COALESCE(name,'')`)
	if err != nil {
		log.Printf("сводка, расходники: %v", err)
		return g
	}
	defer rows.Close()
	for rows.Next() {
		var (
			id                     int64
			name, ip, detail, poll string
		)
		if rows.Scan(&id, &name, &ip, &detail, &poll) != nil {
			continue
		}
		g.Total++
		if len(g.Items) < maxIssueItems {
			if name == "" {
				name = ip
			}
			if detail == "" {
				detail = "расходники на исходе"
			}
			g.Items = append(g.Items, issueItem{
				Title:  name,
				Detail: detail,
				Age:    humanAgo(poll),
				Href:   fmt.Sprintf("/snmp/%d/ports", id),
			})
		}
	}
	g.More = g.Total - len(g.Items)
	return g
}

// diskGroups — диски с замечаниями, отдельно критические и предупреждения.
//
// Отбор в SQL заведомо шире любого вердикта, а решение принимает та же
// assessDisk, что и страница дисков: две оценки одного диска иначе разошлись
// бы, и сводка спорила бы с разделом, куда сама же и ведёт.
func (a *App) diskGroups() []issueGroup {
	crit := issueGroup{Cause: "Диски: ожидается отказ", Crit: true, Href: "/disk-health"}
	warn := issueGroup{Cause: "Диски с предупреждением SMART", Href: "/disk-health"}

	rows, err := a.DB.Query(`SELECT d.id, d.hostname, COALESCE(k.model,''),
			COALESCE(k.health,''), k.temperature, k.wear_pct, k.read_errors, k.predict_fail,
			COALESCE(k.updated_at,'')
		FROM disks k JOIN devices d ON d.id = k.device_id
		WHERE k.predict_fail=1 OR k.wear_pct>=80 OR k.temperature>=60 OR k.read_errors>0
		   OR LOWER(COALESCE(k.health,'')) IN ('unhealthy','warning')
		ORDER BY k.predict_fail DESC, k.wear_pct DESC`)
	if err != nil {
		log.Printf("сводка, диски: %v", err)
		return []issueGroup{crit, warn}
	}
	defer rows.Close()

	for rows.Next() {
		var (
			id      int64
			host    string
			d       diskInfo
			pf      int
			updated string
		)
		if rows.Scan(&id, &host, &d.Model, &d.Health, &d.Temperature, &d.WearPct,
			&d.ReadErrors, &pf, &updated) != nil {
			continue
		}
		d.PredictFail = pf == 1

		v := assessDisk(d)
		var g *issueGroup
		switch v.Severity {
		case "critical":
			g = &crit
		case "warning":
			g = &warn
		default:
			continue
		}
		g.Total++
		if len(g.Items) < maxIssueItems {
			title := host
			if d.Model != "" {
				title += " · " + d.Model
			}
			g.Items = append(g.Items, issueItem{
				Title:  title,
				Detail: v.Issue,
				Age:    humanAgo(updated),
				Href:   fmt.Sprintf("/devices/%d", id),
			})
		}
	}
	if err := rows.Err(); err != nil {
		log.Printf("сводка, диски: %v", err)
	}
	crit.More = crit.Total - len(crit.Items)
	warn.More = warn.Total - len(warn.Items)
	return []issueGroup{crit, warn}
}

// humanAgo — сколько прошло с момента, записанного в базе (UTC).
//
// Пустая строка на выходе означает «неизвестно»: у машины, не выходившей на
// связь ни разу, времени последнего контакта нет, и показывать вместо него
// «53 года назад» — хуже, чем не показывать ничего.
func humanAgo(ts string) string {
	if ts == "" {
		return ""
	}
	var t time.Time
	var err error
	for _, layout := range []string{"2006-01-02 15:04:05", "2006-01-02T15:04:05Z", "2006-01-02 15:04"} {
		if t, err = time.Parse(layout, ts); err == nil {
			break
		}
	}
	if err != nil {
		return ""
	}
	d := time.Since(t.UTC())
	switch {
	case d < time.Minute:
		return "только что"
	case d < time.Hour:
		return fmt.Sprintf("%d мин", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%d ч", int(d.Hours()))
	default:
		return fmt.Sprintf("%d дн", int(d.Hours())/24)
	}
}

// issuesTotal — сколько всего проблем в сводке: числом их показывает заголовок.
func issuesTotal(groups []issueGroup) int {
	n := 0
	for _, g := range groups {
		n += g.Total
	}
	return n
}
