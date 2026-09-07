// Package netiface — выбор адреса, по которому агенты должны обращаться к серверу.
//
// Вопрос кажется простым ровно до первой машины с Docker, WSL или VPN: у неё
// несколько частных адресов, и агенты найдут сервер только по одному из них.
// Ошибиться тут дорого — агент встанет, но подключиться не сможет, а выглядеть
// это будет как «поставил, и ничего не появилось».
//
// Порядок выбора собран из двух признаков: имя адаптера и диапазон адреса.
// Первый ловит распознаваемые туннели и виртуальные коммутаторы, второй
// работает и с незнакомыми именами — 172.16/12 у Docker встречается чаще, чем
// в настоящих сетях небольших организаций.
//
// Свой похожий список есть в internal/netscan, и он намеренно отдельный: там
// решается другой вопрос — какую сеть сканировать, — и совпадение этих правил
// было бы случайным.
package netiface

import (
	"net"
	"sort"
	"strings"
)

// Addr — частный IPv4-адрес поднятого интерфейса.
type Addr struct {
	IP    string // 192.168.1.64
	Iface string // Ethernet
}

// Virtual распознаёт по имени адаптеры, которые не ведут в локальную сеть:
// VPN-туннели, Docker/WSL, виртуальные коммутаторы гипервизоров. Список имён
// заведомо неполон, поэтому такие адреса не скрываются — только опускаются
// ниже в выборе.
func Virtual(name string) bool {
	n := strings.ToLower(name)
	for _, mark := range []string{
		"tun", "tap", "vpn", "wg", "wireguard", "zerotier", "tailscale",
		"docker", "wsl", "vethernet", "virtual", "vbox", "virtualbox",
		"vmware", "hyper-v", "loopback",
	} {
		if strings.Contains(n, mark) {
			return true
		}
	}
	return false
}

// rangeScore — насколько диапазон похож на настоящую сеть организации.
// 172.16/12 стоит ниже прочих: этот диапазон по умолчанию раздаёт Docker.
func rangeScore(ip net.IP) int {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	switch {
	case ip4[0] == 192 && ip4[1] == 168:
		return 3
	case ip4[0] == 10:
		return 2
	default: // 172.16.0.0/12
		return 1
	}
}

// LocalIPv4s перечисляет частные IPv4-адреса поднятых интерфейсов, начиная с
// самого правдоподобного для агентов.
func LocalIPv4s() []Addr {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	type entry struct {
		Addr
		virtual bool
		score   int
	}
	var list []entry
	for _, i := range ifaces {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			if !ok || n.IP.To4() == nil || !n.IP.IsPrivate() || n.IP.IsLinkLocalUnicast() {
				continue
			}
			list = append(list, entry{
				Addr:    Addr{IP: n.IP.String(), Iface: i.Name},
				virtual: Virtual(i.Name),
				score:   rangeScore(n.IP),
			})
		}
	}

	// Физические адаптеры вперёд, среди равных — более правдоподобный диапазон.
	// Первый пункт становится выбором по умолчанию, и им должен быть адрес
	// настоящей сети, а не туннеля или виртуального коммутатора.
	sort.SliceStable(list, func(i, j int) bool {
		if list[i].virtual != list[j].virtual {
			return !list[i].virtual
		}
		return list[i].score > list[j].score
	})

	out := make([]Addr, 0, len(list))
	for _, e := range list {
		out = append(out, e.Addr)
	}
	return out
}

// First — первый адрес из LocalIPv4s или пустая строка.
func First() string {
	if l := LocalIPv4s(); len(l) > 0 {
		return l[0].IP
	}
	return ""
}
