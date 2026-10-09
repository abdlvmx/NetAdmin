//go:build securityevents

package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"netadmin/internal/auth"
	"netadmin/internal/securityevents"
	"netadmin/internal/web"
)

type eventsPCRow struct {
	ID                  int64
	Hostname, IP        string
	Enrolled, Supported bool
	CanEnable           bool
	RegistrationChanged bool
	Policy              securityevents.Policy
	Status              securityevents.DeviceStatus
	StateLabel          string
	Channels            []eventsChannelRow
	Health              securityevents.DeliveryHealth
}

type eventsChannelRow struct{ Channel, State, Error string }

type eventsDisplayRow struct {
	securityevents.StoredEvent
	securityevents.EventDescription
	Hostname string
}

type eventsGapRow struct {
	securityevents.StoredGap
	Hostname, ReasonLabel string
}

func eventsStateLabel(state string) string {
	switch state {
	case "collecting":
		return "Сбор работает"
	case "paused":
		return "Сбор приостановлен"
	case "error":
		return "Ошибка сбора"
	case "disabled":
		return "Сбор выключен"
	case "pending":
		return "Ожидание агента"
	case "ready":
		return "Доступен"
	case "unavailable":
		return "Недоступен"
	case "":
		return "Нет данных"
	default:
		return state
	}
}

func eventsGapLabel(reason string) string {
	switch reason {
	case "log_cleared", "cleared":
		return "Журнал Windows очищен; чтение продолжено с новой закладкой"
	case "bookmark_invalid", "invalid_bookmark", "invalid_cursor":
		return "Закладка устарела или недоступна; сбор начат с текущего конца журнала"
	case "bookmark_unavailable":
		return "Сохранённая закладка отсутствует; сбор начат с текущего конца журнала"
	case "bookmark_reused":
		return "Журнал заменён или очищен; сбор начат с текущего конца журнала"
	case "channel_changed":
		return "Изменился источник журнала; сбор начат с текущего конца журнала"
	case "record_order_changed":
		return "Изменилась последовательность записей; часть старого журнала недоступна"
	case "log_wrapped", "overwritten", "retention":
		return "Старые записи журнала перезаписаны; часть событий недоступна"
	default:
		return reason
	}
}

type eventsPageData struct {
	User                      *auth.User
	Active, Msg               string
	HTTPS, Demo               bool
	Devices                   []eventsPCRow
	Events                    []eventsDisplayRow
	Gaps                      []eventsGapRow
	DeviceID                  int64
	Channel, From, To         string
	Findings                  []findingRow
	Rules                     []securityevents.Rule
	Exceptions                []exceptionRow
	FindingStatus, RuleFilter string
	Backup                    eventsBackupPanel
	DeliveryProblems          []eventsPCRow
	Tab                       string
	Navigation                eventsNavigation
}

type eventsNavigation struct{ Findings, Logs, Collection, Rules, Backups string }

func eventsTab(q url.Values) (string, error) {
	tab := q.Get("tab")
	if tab == "" {
		tab = "findings"
		// Keep old links to journal filters useful without requiring JavaScript.
		if q.Get("channel") != "" || q.Get("from") != "" || q.Get("to") != "" {
			tab = "logs"
		}
	}
	switch tab {
	case "findings", "logs", "collection", "rules", "backups":
		return tab, nil
	}
	return "", securityevents.ErrInvalid
}

func eventsNavigationFor(q url.Values) eventsNavigation {
	link := func(tab string) string {
		values := url.Values{"tab": {tab}}
		for _, key := range []string{"device", "channel", "from", "to", "finding_status", "rule"} {
			if value := q.Get(key); value != "" {
				values.Set(key, value)
			}
		}
		return "/events?" + values.Encode()
	}
	return eventsNavigation{Findings: link("findings"), Logs: link("logs"), Collection: link("collection"), Rules: link("rules"), Backups: link("backups")}
}

func eventsFilterTime(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse("2006-01-02T15:04", value); err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339, value)
}

// SecurityEventsPage is intentionally restricted to administrators even if
// the separate store has not started or cannot be opened.
func (a *App) SecurityEventsPage(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if !user.IsAdmin() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if a.Events == nil {
		http.Error(w, "Events unavailable", http.StatusServiceUnavailable)
		return
	}
	q := r.URL.Query()
	data := eventsPageData{User: user, Active: "securityevents", Msg: q.Get("message"), HTTPS: eventsNativeTLSConfigured(r), Demo: a.Demo,
		Channel: q.Get("channel"), From: q.Get("from"), To: q.Get("to"), FindingStatus: q.Get("finding_status"), RuleFilter: q.Get("rule")}
	var err error
	data.Tab, err = eventsTab(q)
	if err != nil {
		http.Error(w, "Неизвестный раздел Events", http.StatusBadRequest)
		return
	}
	data.Navigation = eventsNavigationFor(q)
	if raw := q.Get("device"); raw != "" {
		id, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || id < 0 {
			http.Error(w, "invalid device filter", http.StatusBadRequest)
			return
		}
		data.DeviceID = id
	}
	if data.Channel != "" && data.Channel != "System" && data.Channel != "Security" {
		http.Error(w, "invalid channel filter", http.StatusBadRequest)
		return
	}
	from, fromErr := eventsFilterTime(data.From)
	to, toErr := eventsFilterTime(data.To)
	if fromErr != nil || toErr != nil || (!from.IsZero() && !to.IsZero() && from.After(to)) {
		http.Error(w, "invalid time filter", http.StatusBadRequest)
		return
	}
	rows, err := a.DB.QueryContext(r.Context(), `SELECT id,hostname,COALESCE(ip_address,''),COALESCE(agent_token,''),
		COALESCE(agent_capabilities,''),COALESCE(device_type,''),COALESCE(os_type,''),COALESCE(manufacturer,''),COALESCE(open_ports,'')
		FROM devices ORDER BY hostname,id`)
	if err != nil {
		http.Error(w, "devices unavailable", http.StatusServiceUnavailable)
		return
	}
	var devices []eventsDevice
	names := map[int64]string{}
	for rows.Next() {
		var d eventsDevice
		if err = rows.Scan(&d.ID, &d.Hostname, &d.IP, &d.Token, &d.Caps, &d.DeviceType, &d.OS, &d.Vendor, &d.Ports); err != nil {
			break
		}
		names[d.ID] = d.Hostname
		if d.isPC() {
			devices = append(devices, d)
		}
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		http.Error(w, "devices unavailable", http.StatusServiceUnavailable)
		return
	}
	for _, d := range devices {
		pc := eventsPCRow{ID: d.ID, Hostname: d.Hostname, IP: d.IP, Enrolled: d.Token != "", Supported: eventsHasCapability(d.Caps)}
		if data.Tab == "collection" {
			pc.RegistrationChanged, err = a.Events.RegistrationChanged(r.Context(), d.ID, d.Token)
		}
		if err == nil {
			pc.Policy, err = a.Events.Policy(r.Context(), d.ID, d.Token)
		}
		if err == nil && data.Tab == "collection" {
			pc.Status, err = a.Events.GetStatus(r.Context(), d.ID)
		}
		if err != nil {
			http.Error(w, "Events state unavailable", http.StatusServiceUnavailable)
			return
		}
		pc.CanEnable = data.HTTPS && !data.Demo && pc.Enrolled && pc.Supported
		pc.StateLabel = eventsStateLabel(pc.Status.State)
		pc.Health = securityevents.AssessDelivery(pc.Policy, pc.Status, time.Now().UTC())
		if pc.Health.Level == "warning" || pc.Health.Level == "error" {
			data.DeliveryProblems = append(data.DeliveryProblems, pc)
		}
		for _, c := range pc.Status.Channels {
			pc.Channels = append(pc.Channels, eventsChannelRow{Channel: c.Channel, State: eventsStateLabel(c.State), Error: c.Error})
		}
		data.Devices = append(data.Devices, pc)
	}
	name := func(id int64) string {
		if n := names[id]; n != "" {
			return n
		}
		return fmt.Sprintf("Устройство #%d", id)
	}
	if data.Tab == "logs" {
		events, err := a.Events.EventsFiltered(r.Context(), securityevents.EventFilter{DeviceID: data.DeviceID, Channel: data.Channel, From: from, To: to, Limit: 100})
		if err != nil {
			http.Error(w, "Events unavailable", http.StatusServiceUnavailable)
			return
		}
		for _, e := range events {
			data.Events = append(data.Events, eventsDisplayRow{StoredEvent: e, EventDescription: securityevents.DescribeEvent(e.Event), Hostname: name(e.DeviceID)})
		}
		gaps, err := a.Events.Gaps(r.Context(), data.DeviceID, 100)
		if err != nil {
			http.Error(w, "Events gaps unavailable", http.StatusServiceUnavailable)
			return
		}
		for _, gap := range gaps {
			if data.Channel != "" && gap.Channel != data.Channel || !from.IsZero() && gap.TimeUTC.Before(from) || !to.IsZero() && gap.TimeUTC.After(to) {
				continue
			}
			data.Gaps = append(data.Gaps, eventsGapRow{StoredGap: gap, Hostname: name(gap.DeviceID), ReasonLabel: eventsGapLabel(gap.Reason)})
		}
	}
	if data.Tab == "backups" {
		data.Backup = a.eventsBackupPanel()
	}
	if data.Tab == "findings" {
		err = a.loadFindingsPanel(r, &data, names)
	}
	if data.Tab == "rules" {
		err = a.loadRulesPanel(r, &data, names)
	}
	if err != nil {
		if errors.Is(err, securityevents.ErrInvalid) {
			http.Error(w, "Неверный фильтр обнаружений", http.StatusBadRequest)
		} else {
			http.Error(w, "Карточки недоступны", http.StatusServiceUnavailable)
		}
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	web.RenderPage(w, "securityevents", data)
}
