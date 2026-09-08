// Package tz — время для показа человеку.
//
// Хранение в базе остаётся в UTC (`datetime('now')`), зона применяется только
// на вывод. Так и было, но зона была прибита к московской — константой в коде.
// Для организации в Екатеринбурге или Калининграде это означало неверные метки
// везде: в списке устройств, на графиках, в журнале действий, в письмах. Причём
// неверные тихо — выглядит как обычное время, просто не то, и понять, что это
// настройка, а не ошибка, было неоткуда.
//
// По умолчанию берётся зона самого сервера: он обычно стоит там же, где и люди,
// которые на него смотрят. Когда это не так — зона задаётся в настройках.
package tz

import (
	"fmt"
	"sync/atomic"
	"time"

	// База часовых поясов внутрь бинарника. В Windows своей копии нет: без
	// этого time.LoadLocation("Asia/Yekaterinburg") отказывает на любой машине,
	// где не установлен Go, — то есть на всех, куда продукт ставят. Обходится
	// примерно в 450 КБ и снимает единственную внешнюю зависимость, которая
	// здесь могла бы появиться.
	_ "time/tzdata"
)

// current — действующая зона. Меняется из настроек на работающем сервере, а
// читается из каждого запроса, поэтому не обычная переменная: смена зоны на
// ходу иначе была бы гонкой.
var current atomic.Pointer[time.Location]

func init() { current.Store(time.Local) }

// Loc — действующая зона.
func Loc() *time.Location { return current.Load() }

// Set устанавливает зону по названию IANA («Asia/Novosibirsk»). Пустое имя
// возвращает к зоне самого сервера.
//
// Отказ возвращается, а не гасится: неизвестное имя означает, что человек
// написал его сам и ошибся, и молча показывать ему московское время вместо
// новосибирского — ровно то, от чего этот пакет и избавляет.
func Set(name string) error {
	if name == "" {
		current.Store(time.Local)
		return nil
	}
	l, err := time.LoadLocation(name)
	if err != nil {
		return fmt.Errorf("неизвестный часовой пояс %q: %w", name, err)
	}
	current.Store(l)
	return nil
}

// Label — как называется действующая зона для показа: «Asia/Yekaterinburg,
// UTC+5». Смещение считается на текущий момент — у зон с переходом на летнее
// время оно не постоянно.
func Label() string {
	l := Loc()
	name := l.String()
	if name == "Local" {
		name = "зона сервера"
	}
	return name + ", " + Offset()
}

// Offset — смещение действующей зоны в виде «UTC+5».
func Offset() string {
	_, sec := time.Now().In(Loc()).Zone()
	return offsetOf(sec)
}

// offsetOf переводит смещение в секундах в «UTC+5» или «UTC+5:30» — получасовые
// зоны есть, и округлять их до часа значило бы врать.
func offsetOf(sec int) string {
	sign, min := "+", sec/60
	if min < 0 {
		sign, min = "-", -min
	}
	if min%60 == 0 {
		return fmt.Sprintf("UTC%s%d", sign, min/60)
	}
	return fmt.Sprintf("UTC%s%d:%02d", sign, min/60, min%60)
}

var monthsGen = [...]string{
	"января", "февраля", "марта", "апреля", "мая", "июня",
	"июля", "августа", "сентября", "октября", "ноября", "декабря",
}

// parse разбирает отметку времени в том виде, в каком её отдаёт SQLite.
//
// Разобранное считается временем UTC: именно так пишет `datetime('now')`, и
// именно на этом держится весь перевод в зону показа.
func parse(s string) (time.Time, bool) {
	for _, layout := range []string{"2006-01-02 15:04:05", "2006-01-02T15:04:05Z", "2006-01-02 15:04"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// DateTime: «02.01 15:04» в действующей зоне (или исходная строка, если не
// разобралось).
func DateTime(s string) string {
	if t, ok := parse(s); ok {
		return t.In(Loc()).Format("02.01 15:04")
	}
	return s
}

// Time: «15:04» в действующей зоне.
func Time(s string) string {
	if t, ok := parse(s); ok {
		return t.In(Loc()).Format("15:04")
	}
	return s
}

// Full: «2006-01-02 15:04:05» в действующей зоне (для меток графиков).
func Full(s string) string {
	if t, ok := parse(s); ok {
		return t.In(Loc()).Format("2006-01-02 15:04:05")
	}
	return s
}

// TodayRU: текущая дата в действующей зоне, напр. «2 июня 2026».
func TodayRU() string {
	now := time.Now().In(Loc())
	return fmt.Sprintf("%d %s %d", now.Day(), monthsGen[now.Month()-1], now.Year())
}

// Zones — пояса России от западного к восточному, для выбора в настройках.
//
// Список, а не свободное поле: набирать «Asia/Krasnoyarsk» руками — способ
// ошибиться в одну букву и не понять почему. Кому нужна зона за пределами
// списка, задаёт её в config.json — Set принимает любое имя IANA.
var Zones = []struct{ Name, Title string }{
	{"Europe/Kaliningrad", "Калининград"},
	{"Europe/Moscow", "Москва, Санкт-Петербург"},
	{"Europe/Samara", "Самара, Ижевск"},
	{"Asia/Yekaterinburg", "Екатеринбург, Пермь, Уфа"},
	{"Asia/Omsk", "Омск"},
	{"Asia/Novosibirsk", "Новосибирск"},
	{"Asia/Krasnoyarsk", "Красноярск"},
	{"Asia/Irkutsk", "Иркутск, Улан-Удэ"},
	{"Asia/Yakutsk", "Якутск, Чита"},
	{"Asia/Vladivostok", "Владивосток, Хабаровск"},
	{"Asia/Magadan", "Магадан, Южно-Сахалинск"},
	{"Asia/Kamchatka", "Петропавловск-Камчатский"},
}

// ZoneOffset — смещение названной зоны на текущий момент, «UTC+5». Считается,
// а не вписано в список: смещения меняются законом, а переход на летнее время
// делает их непостоянными в пределах года.
func ZoneOffset(name string) string {
	l, err := time.LoadLocation(name)
	if err != nil {
		return ""
	}
	_, sec := time.Now().In(l).Zone()
	return offsetOf(sec)
}
