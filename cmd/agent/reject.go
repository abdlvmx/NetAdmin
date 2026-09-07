package main

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

// Разбор отказов сервера.
//
// Раньше при расхождении токенов агент писал в журнал одно и то же «сервер
// отверг (HTTP 403): bad signature» — по строке на каждую отправку, то есть
// шесть строк за круг и каждые пятнадцать секунд заново. Причина из этого не
// следовала никак, а понять по такому журналу, что делать, нельзя.
//
// Теперь отказ объясняется по существу, а повтор одной и той же беды
// придерживается: смысла печатать её четыре раза в минуту нет.

// rejectRepeat — как часто повторять сообщение об одной и той же причине.
const rejectRepeat = 5 * time.Minute

// rejectHint возвращает объяснение отказа и то, что с ним делать.
// Пустая строка — объяснять нечего, хватит кода ответа.
func rejectHint(status int, body string) string {
	b := strings.ToLower(body)
	switch {
	case status == 403 && strings.Contains(b, "signature"):
		return "Ключ регистрации не подошёл.\n" +
			"        Либо код регистрации истёк или исчерпал число установок,\n" +
			"        либо на сервере сменили токен агента — например, пересоздали\n" +
			"        config.json, перенеся или очистив каталог данных.\n" +
			"        Что делать: возьмите на сервере новый код (Настройки →\n" +
			"        Установка агента) и поставьте агента заново.\n" +
			"        agent.exe -check покажет, откуда агент берёт настройки."
	case status == 403 && strings.Contains(b, "сети"):
		return "Сервер не обслуживает эту подсеть. Проверьте «Сеть и доступ» в Настройках."
	case status == 401:
		return "Сервер не принял ключ. Возьмите новый код на странице «Настройки»."
	case status == 409:
		return "Устройство с таким именем уже зарегистрировано под другим токеном.\n" +
			"        Переустановка проходит по одноразовому коду: возьмите его на\n" +
			"        сервере — Настройки, Установка агента. Если ставите по\n" +
			"        постоянному токену, сбросьте токен в карточке устройства."
	case status == 429:
		return "Слишком много запросов — сервер придерживает агента, это временно."
	case status >= 500:
		return "Ошибка на стороне сервера. Смотрите его журнал."
	}
	return ""
}

// rejectLog печатает отказы, придерживая повторы одной и той же причины.
type rejectLog struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

var rejects = &rejectLog{seen: map[string]time.Time{}}

// report печатает отказ с объяснением. Повторный отказ по той же причине
// молчит до истечения rejectRepeat — тогда сообщение выходит снова, чтобы
// проблема не потерялась из виду совсем.
func (r *rejectLog) report(what string, status int, body string) {
	body = strings.TrimSpace(body)
	hint := rejectHint(status, body)

	// Ключ по причине, а не по вызвавшей её отправке: heartbeat и пять видов
	// инвентаря спотыкаются об одно и то же, и шесть одинаковых объяснений
	// подряд не нужны никому.
	key := fmt.Sprintf("%d|%s", status, body)

	r.mu.Lock()
	last, ok := r.seen[key]
	quiet := ok && time.Since(last) < rejectRepeat
	if !quiet {
		r.seen[key] = time.Now()
	}
	r.mu.Unlock()

	if quiet {
		return
	}
	if hint == "" {
		log.Printf("%s — сервер отверг (HTTP %d): %s", what, status, body)
		return
	}
	log.Printf("%s — сервер отверг (HTTP %d): %s\n        %s", what, status, body, hint)
}

// reportOnce печатает сообщение без кода ответа, с той же выдержкой повторов.
func (r *rejectLog) reportOnce(key, msg string) {
	r.mu.Lock()
	last, ok := r.seen[key]
	quiet := ok && time.Since(last) < rejectRepeat
	if !quiet {
		r.seen[key] = time.Now()
	}
	r.mu.Unlock()

	if !quiet {
		log.Print(msg)
	}
}

// clear забывает причину: после удачного обмена прошлые жалобы неактуальны,
// и если беда вернётся, сказать о ней нужно сразу, а не через пять минут.
func (r *rejectLog) clear() {
	r.mu.Lock()
	clear(r.seen)
	r.mu.Unlock()
}
