package netiface

import (
	"net"
	"testing"
)

// Первый в списке становится выбором по умолчанию — и в установщике агента,
// и в приветствии сервера. Ошибка здесь выглядит как «агент поставили, а
// устройство не появилось»: адрес туннеля или Docker агентам недоступен.
func TestVirtualIfacesRankedLast(t *testing.T) {
	for _, name := range []string{"happ-tun", "docker0", "vEthernet (WSL)", "wg0",
		"Tailscale", "VirtualBox Host-Only Network", "tap0", "VMware Network Adapter"} {
		if !Virtual(name) {
			t.Errorf("%q должен считаться виртуальным", name)
		}
	}
	for _, name := range []string{"Ethernet", "Wi-Fi", "eth0", "Подключение по локальной сети"} {
		if Virtual(name) {
			t.Errorf("%q — обычный адаптер, не виртуальный", name)
		}
	}

	seenVirtual := false
	for _, a := range LocalIPv4s() {
		if Virtual(a.Iface) {
			seenVirtual = true
		} else if seenVirtual {
			t.Errorf("физический адаптер %s (%s) оказался после виртуального", a.IP, a.Iface)
		}
	}
}

// Имя адаптера распознаётся не всегда, поэтому диапазон адреса — второй
// признак: 172.16/12 по умолчанию раздаёт Docker, и настоящей сетью
// организации он бывает заметно реже, чем 192.168.
func TestRangeScorePrefersHomeNetworks(t *testing.T) {
	cases := []struct {
		ip     string
		better string
	}{
		{"192.168.1.64", "172.18.0.1"},
		{"192.168.1.64", "10.0.0.5"},
		{"10.0.0.5", "172.18.0.1"},
	}
	for _, c := range cases {
		hi, lo := rangeScore(net.ParseIP(c.ip)), rangeScore(net.ParseIP(c.better))
		if hi <= lo {
			t.Errorf("%s должен быть предпочтительнее %s (%d против %d)",
				c.ip, c.better, hi, lo)
		}
	}
}

// LocalIPv4s не должен возвращать адреса, по которым агент до сервера не
// достучится: петля, link-local и всё публичное.
func TestLocalIPv4sReturnsOnlyPrivate(t *testing.T) {
	for _, a := range LocalIPv4s() {
		ip := net.ParseIP(a.IP)
		if ip == nil {
			t.Errorf("неразбираемый адрес %q", a.IP)
			continue
		}
		if !ip.IsPrivate() {
			t.Errorf("%s (%s) не из частного диапазона", a.IP, a.Iface)
		}
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			t.Errorf("%s (%s) непригоден для агентов", a.IP, a.Iface)
		}
	}
}
