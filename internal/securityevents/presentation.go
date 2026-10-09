//go:build securityevents

package securityevents

import (
	"encoding/json"
	"strings"
)

type DisplayField struct{ Label, Value string }
type EventDescription struct {
	Title, Summary, JSON string
	Fields               []DisplayField
}

func displayValue(s string) string {
	if s == "" || s == "-" {
		return "не указано"
	}
	return s
}
func AccountName(e Event) string {
	name := e.Fields["TargetUserName"]
	if domain := e.Fields["TargetDomainName"]; domain != "" && domain != "-" && name != "" {
		return domain + "\\" + name
	}
	return name
}
func ClearedChannel(e Event) string {
	if e.EventID == 1102 {
		return "Security"
	}
	if channel := e.Fields["Channel"]; channel != "" {
		return channel
	}
	return e.Channel
}

func DescribeEvent(e Event) EventDescription {
	d := EventDescription{}
	switch e.EventID {
	case 4625:
		d.Title = "Неудачный вход"
		d.Summary = "Учётная запись: " + displayValue(AccountName(e)) + "; IP: " + displayValue(e.Fields["IpAddress"])
	case 1102, 104:
		d.Title = "Журнал очищен"
		d.Summary = "Канал: " + ClearedChannel(e)
	case 7045:
		d.Title = "Установлена служба"
		d.Summary = "Служба: " + displayValue(e.Fields["ServiceName"])
	case 6005:
		d.Title = "Служба журналов запущена"
	case 6006:
		d.Title = "Служба журналов остановлена"
	case 6008:
		d.Title = "Зарегистрировано неожиданное выключение"
	default:
		d.Title = "Событие Windows"
	}
	fields := []struct{ key, label string }{
		{"ServiceName", "Имя службы"}, {"ServiceType", "Тип службы"}, {"StartType", "Режим запуска"},
		{"Channel", "Очищенный канал"}, {"TargetUserName", "Учётная запись"}, {"TargetDomainName", "Домен / компьютер"},
		{"IpAddress", "IP источника"}, {"LogonType", "Тип входа"}, {"Status", "Код отказа"}, {"SubStatus", "Дополнительный код"}, {"FailureReason", "Причина отказа (данные Windows)"},
	}
	for _, field := range fields {
		if value, ok := e.Fields[field.key]; ok {
			if field.key == "LogonType" {
				if name := map[string]string{"2": "Локальный", "3": "Сетевой", "4": "Пакетный", "5": "Служба", "7": "Разблокировка", "10": "Удалённый рабочий стол", "11": "Вход с сохранёнными данными"}[value]; name != "" {
					value = name + " (" + value + ")"
				}
			}
			d.Fields = append(d.Fields, DisplayField{Label: field.label, Value: displayValue(value)})
		}
	}
	var b strings.Builder
	encoder := json.NewEncoder(&b)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(e)
	d.JSON = strings.TrimSpace(b.String())
	return d
}

func FindingStateLabel(state string) string {
	switch state {
	case "new":
		return "Новое"
	case "in_progress":
		return "Разбирается"
	case "closed":
		return "Закрыто"
	case "false_positive":
		return "Ложное срабатывание"
	}
	return state
}
func SeverityLabel(severity string) string {
	switch severity {
	case "high":
		return "Высокая"
	case "medium":
		return "Средняя"
	case "info":
		return "Информация"
	}
	return severity
}
