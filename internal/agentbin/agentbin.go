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
	"bytes"
	"crypto/sha256"
	"debug/buildinfo"
	"embed"
	"encoding/hex"
	"runtime/debug"
	"sync"
	"time"
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

// --- Из чего собран встроенный агент ---
//
// Сервер встраивает через go:embed то, что лежит в bin/ на момент его сборки.
// Порядок «сначала агент, потом сервер» нигде не проверялся, а промах молчаливый
// и отложенный: сервер трое суток раздавал сборку агента трёхдневной давности, и
// узнали об этом только когда та отказалась ставиться поверх своей же службы.
//
// Сверять нечего было бы, если бы не сведения о сборке, которые Go кладёт в
// бинарник сам: ревизия git, её время и признак правок в дереве. Их достаточно,
// чтобы заметить главное — агент собран не из той ревизии, что сервер.

// Build — из чего собран бинарник.
type Build struct {
	Revision string    // ревизия git целиком
	Time     time.Time // время ревизии
	Modified bool      // дерево на момент сборки было с правками
}

// Short — ревизия в коротком виде, как её показывает git log --oneline.
func (b Build) Short() string {
	if len(b.Revision) > 7 {
		return b.Revision[:7]
	}
	return b.Revision
}

// Match — что показало сравнение встроенного агента с сервером.
type Match int

const (
	MatchUnknown Match = iota // сведений о сборке нет: сравнивать не с чем
	MatchSame                 // одна ревизия — порядок сборки соблюдён
	MatchStale                // разные ревизии: агента забыли пересобрать
)

var (
	infoOnce  sync.Once
	agentInfo Build
	agentOK   bool
)

// Info — из чего собран встроенный агент. Второе значение false, если сведений
// нет: сборка без git или с -buildvcs=false.
func Info() (Build, bool) {
	load()
	infoOnce.Do(func() {
		if len(data) == 0 {
			return
		}
		bi, err := buildinfo.Read(bytes.NewReader(data))
		if err != nil {
			return
		}
		agentInfo, agentOK = fromBuildInfo(bi)
	})
	return agentInfo, agentOK
}

// Self — из чего собран сам сервер.
func Self() (Build, bool) {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return Build{}, false
	}
	return fromBuildInfo(bi)
}

func fromBuildInfo(bi *debug.BuildInfo) (Build, bool) {
	var b Build
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			b.Revision = s.Value
		case "vcs.time":
			b.Time, _ = time.Parse(time.RFC3339, s.Value)
		case "vcs.modified":
			b.Modified = s.Value == "true"
		}
	}
	return b, b.Revision != ""
}

// Compare сообщает, собран ли встроенный агент из той же ревизии, что сервер.
func Compare() Match {
	agent, aok := Info()
	server, sok := Self()
	return compare(agent, aok, server, sok)
}

// compare вынесена отдельно, чтобы сравнение проверялось тестом: сведения о
// сборке самого тестового бинарника подставить нельзя.
//
// Совпадение ревизий при правках в дереве — не доказательство: две сборки из
// одного коммита в разные дни неотличимы. Но и жаловаться на это нельзя, иначе
// предупреждение горело бы всю разработку и его перестали бы читать.
func compare(agent Build, agentOK bool, server Build, serverOK bool) Match {
	if !agentOK || !serverOK {
		return MatchUnknown
	}
	if agent.Revision != server.Revision {
		return MatchStale
	}
	return MatchSame
}
