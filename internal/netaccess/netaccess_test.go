package netaccess

import "testing"

func TestDefaultAllowsPrivateBlocksPublic(t *testing.T) {
	l := Default()
	allowed := []string{"127.0.0.1", "10.1.2.3", "192.168.1.64", "172.16.5.1", "::1"}
	for _, ip := range allowed {
		if !l.Allows(ip) {
			t.Errorf("%s должен быть разрешён по умолчанию", ip)
		}
	}
	blocked := []string{"8.8.8.8", "203.0.113.7", "172.32.0.1", "2001:4860:4860::8888"}
	for _, ip := range blocked {
		if l.Allows(ip) {
			t.Errorf("%s не должен быть разрешён по умолчанию", ip)
		}
	}
}

// Нулевое значение List не должно открывать доступ наружу: незаполненная
// конфигурация обязана вести себя как список по умолчанию.
func TestZeroValueIsSafe(t *testing.T) {
	var l List
	if !l.Allows("192.168.0.10") {
		t.Error("частный адрес должен проходить")
	}
	if l.Allows("8.8.8.8") {
		t.Error("нулевое значение не должно пускать публичные адреса")
	}
}

func TestParseExplicitSubnets(t *testing.T) {
	l, err := Parse("192.168.1.0/24, 10.10.0.5")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !l.Allows("192.168.1.200") {
		t.Error("адрес из разрешённой подсети должен проходить")
	}
	if !l.Allows("10.10.0.5") {
		t.Error("явно указанный адрес должен проходить")
	}
	// заданный список полностью заменяет умолчания
	if l.Allows("192.168.2.1") || l.Allows("127.0.0.1") {
		t.Error("явный список не должен расширяться умолчаниями")
	}
}

func TestParseAnyAndErrors(t *testing.T) {
	l, err := Parse("any")
	if err != nil {
		t.Fatalf("parse any: %v", err)
	}
	if !l.Allows("8.8.8.8") || !l.Unrestricted() {
		t.Error("режим any должен пропускать всё")
	}
	if _, err := Parse("не-подсеть"); err == nil {
		t.Error("мусор в списке должен давать ошибку")
	}
}

// Разбор пустой строки даёт умолчания, а не пустой список.
func TestParseEmptyIsDefault(t *testing.T) {
	l, err := Parse("   ")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !l.Allows("192.168.1.1") || l.Allows("1.1.1.1") {
		t.Error("пустая строка должна давать список по умолчанию")
	}
}

// Адрес в форме IPv4-in-IPv6 должен сопоставляться с IPv4-подсетями,
// иначе клиент по dual-stack получил бы отказ.
func TestMappedIPv4(t *testing.T) {
	if !Default().Allows("::ffff:192.168.1.10") {
		t.Error("IPv4-in-IPv6 должен распознаваться")
	}
}

// Нераспознанный адрес не проходит: при сомнении отказываем.
func TestGarbageDenied(t *testing.T) {
	if Default().Allows("не адрес") {
		t.Error("мусорный адрес должен отвергаться")
	}
}
