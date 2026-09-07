// Package agentbin — сборка агента, встроенная в сервер.
//
// Раньше, чтобы поставить агента, администратор сначала загружал `agent.exe`
// в раздел «Установка ПО». Шаг ничем не объяснимый: файл лежит рядом с
// сервером, и непонятно, зачем его куда-то загружать, чтобы сервер смог его
// отдать. Теперь сборка едет внутри серверного бинарника.
//
// Файл появляется в bin/ на этапе сборки (см. .github/workflows/release.yml и
// docs/deploy.md), в репозитории его нет. Поэтому встраивается каталог, а не
// файл: `go:embed bin/agent.exe` не собрался бы на свежем клоне, где файла ещё
// нет, и `go build ./...` ломался бы у каждого, кто просто скачал исходники.
package agentbin

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"sync"
)

//go:embed bin
var fsys embed.FS

const name = "bin/agent.exe"

var (
	once sync.Once
	data []byte
	sum  string
)

func load() {
	once.Do(func() {
		b, err := fsys.ReadFile(name)
		if err != nil || len(b) == 0 {
			return
		}
		h := sha256.Sum256(b)
		data, sum = b, hex.EncodeToString(h[:])
	})
}

// Available сообщает, встроена ли сборка агента в этот бинарник.
func Available() bool {
	load()
	return len(data) > 0
}

// Bytes возвращает встроенную сборку и её SHA-256. Второе значение — false,
// если сервер собран без агента: интерфейс тогда предлагает загрузить сборку
// в «Установку ПО», как раньше.
func Bytes() ([]byte, string, bool) {
	load()
	if len(data) == 0 {
		return nil, "", false
	}
	return data, sum, true
}

// Size — размер встроенной сборки в байтах.
func Size() int {
	load()
	return len(data)
}
