// Package agentcfg — настройки, вшитые в конец файла агента.
//
// Установка агента на чужую машину до сих пор требовала консоли: строка в
// PowerShell с адресом и кодом либо .bat, который качает бинарник и заводит
// службу. Строку нельзя набрать руками — код регистрации это 43 случайных
// символа, — значит, на каждой машине нужен буфер обмена, то есть удалённый
// доступ. А .bat, скачивающий исполняемый файл и создающий службу, выглядит
// как вредонос и для антивируса, и для человека, которого попросили его
// запустить.
//
// Поэтому сервер отдаёт агента с уже вписанным адресом и кодом. Файл кладут на
// сетевую папку, обходят машины, запускают двойным щелчком — и всё, что
// остаётся человеку, это ответить на запрос прав. Ни консоли, ни политик
// PowerShell, ни набора текста.
//
// Значения дописываются хвостом за концом образа PE. Windows грузит файл по
// заголовкам и лишние байты в конце не читает — так же устроены
// самораспаковывающиеся архивы. Цифровую подпись такой хвост сломал бы, но
// подписи у сборок нет (см. docs/security.md), так что терять нечего.
//
// Формат хвоста, от конца файла к началу:
//
//	<полезная нагрузка JSON> <длина uint32 LE> <метка magic>
//
// Метка стоит последней, чтобы её можно было найти, не читая файл целиком:
// у агента это десять мегабайт, и разбирать их при каждом запуске незачем.
package agentcfg

import (
	"encoding/binary"
	"encoding/json"
	"os"
)

// magic — метка хвоста. Номер в конце — версия формата: если состав значений
// когда-нибудь изменится несовместимо, старый агент не примет новый хвост за
// свой и честно скажет, что настроек нет, вместо разбора мусора.
const magic = "NETADMIN-AGENT-CFG-1"

// maxPayload — верхняя граница разумного размера настроек. Нужна не ради
// экономии, а чтобы случайное совпадение метки в чужих данных не заставило
// прочитать в память гигабайт.
const maxPayload = 64 << 10

// trailerSize — сколько байт занимают длина и метка.
const trailerSize = 4 + len(magic)

// Settings — то, что вшивается в файл.
//
// Имена полей совпадают с agent_config.json: это одни и те же значения, и
// разные имена для них означали бы только лишний повод перепутать.
type Settings struct {
	ServerURL string `json:"server_url"`
	Token     string `json:"enroll_token,omitempty"`
}

// Empty — в настройках нет ничего полезного.
func (s Settings) Empty() bool { return s.ServerURL == "" && s.Token == "" }

// Append дописывает настройки в конец готовой сборки агента.
//
// Прежний хвост, если он есть, срезается: иначе многократная выдача одного и
// того же файла наращивала бы его слоями, а действующим оставался бы самый
// первый.
func Append(exe []byte, s Settings) ([]byte, error) {
	exe = strip(exe)

	payload, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(exe)+len(payload)+trailerSize)
	out = append(out, exe...)
	out = append(out, payload...)
	out = binary.LittleEndian.AppendUint32(out, uint32(len(payload)))
	return append(out, magic...), nil
}

// strip убирает хвост, если он есть, возвращая исходный файл.
func strip(exe []byte) []byte {
	n, ok := payloadAt(exe)
	if !ok {
		return exe
	}
	return exe[:len(exe)-n-trailerSize]
}

// payloadAt возвращает длину полезной нагрузки в конце буфера.
func payloadAt(exe []byte) (int, bool) {
	if len(exe) < trailerSize {
		return 0, false
	}
	if string(exe[len(exe)-len(magic):]) != magic {
		return 0, false
	}
	n := int(binary.LittleEndian.Uint32(exe[len(exe)-trailerSize : len(exe)-len(magic)]))
	if n <= 0 || n > maxPayload || n+trailerSize > len(exe) {
		return 0, false
	}
	return n, true
}

// Read достаёт настройки из буфера с готовым файлом.
func Read(exe []byte) (Settings, bool) {
	n, ok := payloadAt(exe)
	if !ok {
		return Settings{}, false
	}
	var s Settings
	body := exe[len(exe)-n-trailerSize : len(exe)-trailerSize]
	if json.Unmarshal(body, &s) != nil || s.Empty() {
		return Settings{}, false
	}
	return s, true
}

// ReadFile достаёт настройки из файла, не читая его целиком: метка и длина
// лежат в конце, и с них достаточно прочитать несколько десятков байт.
//
// Ошибки не возвращаются намеренно: для вызывающего «настроек нет» и «файл не
// открылся» — одно и то же, дальше он в любом случае берёт значения из других
// источников.
func ReadFile(path string) (Settings, bool) {
	f, err := os.Open(path)
	if err != nil {
		return Settings{}, false
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil || st.Size() < int64(trailerSize) {
		return Settings{}, false
	}

	tail := make([]byte, trailerSize)
	if _, err := f.ReadAt(tail, st.Size()-int64(trailerSize)); err != nil {
		return Settings{}, false
	}
	if string(tail[4:]) != magic {
		return Settings{}, false
	}
	n := int64(binary.LittleEndian.Uint32(tail[:4]))
	if n <= 0 || n > maxPayload || n+int64(trailerSize) > st.Size() {
		return Settings{}, false
	}

	body := make([]byte, n)
	if _, err := f.ReadAt(body, st.Size()-int64(trailerSize)-n); err != nil {
		return Settings{}, false
	}
	var s Settings
	if json.Unmarshal(body, &s) != nil || s.Empty() {
		return Settings{}, false
	}
	return s, true
}

// ReadSelf достаёт настройки из файла запущенной программы.
func ReadSelf() (Settings, bool) {
	exe, err := os.Executable()
	if err != nil {
		return Settings{}, false
	}
	return ReadFile(exe)
}
