package main

import "testing"

// Решение о брандмауэре должно быть одним и тем же по обе стороны UAC.
//
// Установщик без прав перезапускает себя через UAC и передаёт флаги новой
// копии. Раньше две ветки читали флаги по-разному: сборка аргументов смотрела
// сначала на -firewall, а firewallFromFlags — сначала на -no-firewall. При
// обоих флагах сразу неповышенная копия решала «не трогать брандмауэр», а
// повышенная — «открыть порт»: одна команда означала разное в зависимости от
// того, была ли консоль запущена от администратора.
func TestFirewallChoiceSurvivesElevation(t *testing.T) {
	for _, c := range []struct{ yes, no bool }{
		{false, false}, {true, false}, {false, true}, {true, true},
	} {
		want := firewallFromFlags(c.yes, c.no)

		// что уедет повышенной копии и как она это прочитает
		var yes, no bool
		for _, a := range firewallArgs(want) {
			switch a {
			case "-firewall":
				yes = true
			case "-no-firewall":
				no = true
			}
		}
		if got := firewallFromFlags(yes, no); got != want {
			t.Errorf("флаги -firewall=%v -no-firewall=%v: до UAC решение %d, после — %d",
				c.yes, c.no, want, got)
		}
	}
}
