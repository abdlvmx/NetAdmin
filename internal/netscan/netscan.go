// Package netscan — сетевые операции: ping и сканирование сети (ARP+ICMP).
package netscan

import (
	_ "embed"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var ttlRe = regexp.MustCompile(`(?i)ttl=(\d+)`)

// pingTTL пингует хост и парсит TTL из ответа (для определения ОС).
func pingTTL(ip string) (alive bool, ttl int) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("ping", "-n", "1", "-w", "300", ip)
	} else {
		cmd = exec.Command("ping", "-c", "1", "-W", "1", ip)
	}
	out, _ := cmd.Output()
	if m := ttlRe.FindStringSubmatch(string(out)); m != nil {
		ttl, _ = strconv.Atoi(m[1])
	}
	return ttl > 0, ttl // живой только при реальном echo-reply (есть TTL)
}

// osByTTL — грубое определение ОС по TTL ответа.
func osByTTL(ttl int) string {
	switch {
	case ttl == 0:
		return ""
	case ttl <= 64:
		return "Linux/Unix"
	case ttl <= 128:
		return "Windows"
	default:
		return "Сетевое устройство"
	}
}

// CommonPorts — критичные порты для лёгкого скана.
var CommonPorts = []int{21, 22, 23, 80, 135, 139, 443, 445, 3389, 8080}

// ScanPorts параллельно проверяет CommonPorts TCP-коннектом (таймаут 500мс на порт).
func ScanPorts(ip string) []int {
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		open []int
	)
	for _, p := range CommonPorts {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			c, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(p)), 500*time.Millisecond)
			if err == nil {
				c.Close()
				mu.Lock()
				open = append(open, p)
				mu.Unlock()
			}
		}(p)
	}
	wg.Wait()
	sort.Ints(open)
	return open
}

//go:embed oui.csv
var ouiData string

// карта OUI (первые 3 байта MAC, hex без разделителей) -> производитель
var ouiMap = buildOUI()

func buildOUI() map[string]string {
	m := make(map[string]string, 40000)
	for _, line := range strings.Split(ouiData, "\n") {
		if i := strings.IndexByte(line, '\t'); i > 0 {
			m[line[:i]] = line[i+1:]
		}
	}
	return m
}

// VendorByMAC возвращает производителя по MAC (по OUI) или "".
// Пробует блоки от длинного к короткому: MA-S (/36), MA-M (/28), MA-L (/24).
func VendorByMAC(mac string) string {
	s := strings.ToLower(strings.NewReplacer(":", "", "-", "").Replace(mac))
	for _, n := range []int{9, 7, 6} {
		if len(s) >= n {
			if v, ok := ouiMap[s[:n]]; ok {
				return v
			}
		}
	}
	return ""
}

// PingHost проверяет доступность хоста. «Живой» — только при наличии TTL в
// ответе (настоящий echo-reply); это отсекает Windows-ответы вида
// «Destination host unreachable», которые возвращают код 0.
func PingHost(ip string) bool {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("ping", "-n", "1", "-w", "600", ip)
	} else {
		cmd = exec.Command("ping", "-c", "1", "-W", "1", ip)
	}
	out, _ := cmd.Output()
	return ttlRe.Match(out)
}

// ScanResult — найденное устройство.
type ScanResult struct {
	IP       string
	MAC      string
	Hostname string
	Vendor   string
	OSGuess  string // предполагаемая ОС по TTL
}

// virtualIface — интерфейсы виртуальных/контейнерных сетей (их пропускаем).
func virtualIface(name string) bool {
	n := strings.ToLower(name)
	for _, s := range []string{"docker", "vethernet", "wsl", "virtual", "vmware", "vbox", "hyper-v", "loopback", "tailscale", "zerotier"} {
		if strings.Contains(n, s) {
			return true
		}
	}
	return false
}

// privScore — приоритет приватного диапазона: 192.168 > 10 > 172.16/12 (часто Docker).
func privScore(ip4 net.IP) int {
	switch {
	case ip4[0] == 192 && ip4[1] == 168:
		return 3
	case ip4[0] == 10:
		return 2
	default:
		return 1
	}
}

// LocalIPv4 выбирает приватный IPv4 «настоящей» LAN: пропускает виртуальные
// интерфейсы (Docker/WSL/VM) и предпочитает 192.168/10 поверх 172.x.
func LocalIPv4() (string, bool) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", false
	}
	best := ""
	bestScore := -1
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 || virtualIface(ifc.Name) {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipnet.IP.To4()
			if ip4 == nil || ip4.IsLoopback() || !ip4.IsPrivate() {
				continue
			}
			if s := privScore(ip4); s > bestScore {
				bestScore = s
				best = ip4.String()
			}
		}
	}
	return best, best != ""
}

// Scan пингует /24 вокруг локального адреса и собирает MAC из ARP-таблицы.
// Возвращает CIDR сети и найденные устройства.
func Scan() (string, []ScanResult) {
	ip, ok := LocalIPv4()
	if !ok {
		return "", nil
	}
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return "", nil
	}
	base := strings.Join(parts[:3], ".")
	network := base + ".0/24"

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		results []ScanResult
		sem     = make(chan struct{}, 14) // worker pool: не более 14 одновременных пингов
	)
	// ping + обратный DNS параллельно (DNS — главный тормоз при последовательном проходе)
	for i := 1; i <= 254; i++ {
		host := fmt.Sprintf("%s.%d", base, i)
		wg.Add(1)
		sem <- struct{}{}
		time.Sleep(3 * time.Millisecond) // rate-limit: не заваливаем сетевой стек пачками
		go func(h string) {
			defer wg.Done()
			defer func() { <-sem }()
			alive, ttl := pingTTL(h)
			if !alive {
				return
			}
			res := ScanResult{IP: h, Hostname: resolveHost(h), OSGuess: osByTTL(ttl)}
			mu.Lock()
			results = append(results, res)
			mu.Unlock()
		}(host)
	}
	wg.Wait()

	// MAC из ARP-таблицы (заполняется после ping)
	arp := arpTable()
	for i := range results {
		if mac := arp[results[i].IP]; mac != "" {
			results[i].MAC = mac
			results[i].Vendor = VendorByMAC(mac)
		} else {
			results[i].MAC = "unknown"
		}
	}
	return network, results
}

var macRe = regexp.MustCompile(`([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}`)
var ipRe = regexp.MustCompile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`)

// ARPTable возвращает системную ARP-таблицу (ip -> mac) — пассивный источник
// обнаружения устройств (кэш заполняется обычным трафиком LAN, без активного скана).
func ARPTable() map[string]string { return arpTable() }

// ResolveHost — обратное разрешение имени (экспортируемая обёртка, таймаут 800мс).
func ResolveHost(ip string) string { return resolveHost(ip) }

// arpTable читает системную ARP-таблицу: ip -> mac.
func arpTable() map[string]string {
	out := map[string]string{}
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("arp", "-a")
	} else {
		cmd = exec.Command("arp", "-n")
	}
	data, err := cmd.Output()
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(data), "\n") {
		ip := ipRe.FindString(line)
		mac := macRe.FindString(line)
		if ip != "" && mac != "" {
			out[ip] = strings.ToLower(strings.ReplaceAll(mac, "-", ":"))
		}
	}
	return out
}

// resolveHost — обратное разрешение имени с ЖЁСТКИМ таймаутом.
// На Windows системный LookupAddr не отменяется по context, поэтому ждём
// результат через канал и при превышении 800мс возвращаем IP (зависшая
// горутина завершится сама и не тормозит скан).
func resolveHost(ip string) string {
	ch := make(chan string, 1)
	go func() {
		if names, err := net.LookupAddr(ip); err == nil && len(names) > 0 {
			ch <- strings.TrimSuffix(names[0], ".")
			return
		}
		ch <- ip
	}()
	select {
	case n := <-ch:
		return n
	case <-time.After(800 * time.Millisecond):
		return ip
	}
}
