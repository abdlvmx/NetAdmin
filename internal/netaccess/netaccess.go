// Package netaccess — ограничение доступа к серверу по подсетям.
//
// Продукт рассчитан на локальную сеть и не шифрует канал, поэтому доступ
// снаружи должен быть закрыт. Сервер по умолчанию слушает 0.0.0.0, чтобы
// агенты могли подключаться с любых интерфейсов, — но обслуживает только
// адреса из разрешённых подсетей.
package netaccess

import (
	"errors"
	"net/netip"
	"strings"
)

// defaults — подсети, разрешённые, когда список не задан явно: локальные
// и частные диапазоны (RFC 1918, link-local, IPv6 ULA).
var defaults = []string{
	"127.0.0.0/8", "::1/128",
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
	"169.254.0.0/16", "fe80::/10", "fc00::/7",
}

// List — набор разрешённых подсетей.
//
// Нулевое значение действует как список по умолчанию (только локальные
// и частные сети): незаполненная конфигурация не должна открывать доступ наружу.
type List struct {
	prefixes []netip.Prefix
	all      bool // доступ отовсюду — только по явному «any»
}

func defaultPrefixes() []netip.Prefix {
	out := make([]netip.Prefix, 0, len(defaults))
	for _, s := range defaults {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// Default возвращает список по умолчанию: локальные и частные сети.
func Default() List { return List{prefixes: defaultPrefixes()} }

// Parse разбирает список подсетей, разделённых запятой, точкой с запятой или
// пробелом. Пустая строка даёт список по умолчанию. Значение «any» снимает
// ограничение целиком — это осознанно небезопасный режим.
//
// Принимаются как CIDR (192.168.1.0/24), так и отдельные адреса (192.168.1.5).
func Parse(spec string) (List, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return Default(), nil
	}
	if strings.EqualFold(spec, "any") {
		return List{all: true}, nil
	}
	fields := strings.FieldsFunc(spec, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n'
	})
	var out []netip.Prefix
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if p, err := netip.ParsePrefix(f); err == nil {
			out = append(out, p.Masked())
			continue
		}
		// отдельный адрес — как подсеть из одного адреса
		addr, err := netip.ParseAddr(f)
		if err != nil {
			return List{}, errors.New("не удалось разобрать подсеть: " + f)
		}
		out = append(out, netip.PrefixFrom(addr, addr.BitLen()))
	}
	if len(out) == 0 {
		return List{}, errors.New("список подсетей пуст")
	}
	return List{prefixes: out}, nil
}

// Allows сообщает, разрешён ли доступ с указанного адреса.
// Нераспознанный адрес не допускается: при сомнении отказываем.
func (l List) Allows(ip string) bool {
	if l.all {
		return true
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		// адрес мог прийти с зоной (fe80::1%eth0) или в форме [::1]
		if i := strings.IndexByte(ip, '%'); i > 0 {
			addr, err = netip.ParseAddr(strings.TrimSpace(ip[:i]))
		}
		if err != nil {
			return false
		}
	}
	addr = addr.Unmap() // ::ffff:192.168.0.1 → 192.168.0.1
	prefixes := l.prefixes
	if prefixes == nil {
		prefixes = defaultPrefixes()
	}
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// Unrestricted сообщает, снято ли ограничение полностью (режим «any»).
func (l List) Unrestricted() bool { return l.all }

// String — человекочитаемое описание для журнала запуска.
func (l List) String() string {
	if l.all {
		return "любые адреса (ограничение снято)"
	}
	prefixes := l.prefixes
	if prefixes == nil {
		prefixes = defaultPrefixes()
	}
	parts := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		parts = append(parts, p.String())
	}
	return strings.Join(parts, ", ")
}
