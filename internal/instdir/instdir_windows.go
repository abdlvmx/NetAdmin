//go:build windows

package instdir

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// sddl — список доступа, который получает каталог установки.
//
//	D:PAI            — собственный список, наследование от родителя отключено;
//	(A;OICI;FA;;;SY) — SYSTEM, полный доступ, наследуется файлами и папками;
//	(A;OICI;FA;;;BA) — то же встроенной группе «Администраторы».
//
// Больше никого, и читать в том числе: служба работает от SYSTEM, ставит её
// администратор, а внутри лежат токены агентов и хеши паролей.
//
// Отключённое наследование здесь и есть вся суть. C:\ProgramData по умолчанию
// разрешает BUILTIN\Users создавать файлы и подкаталоги, а CREATOR OWNER даёт
// создателю полный доступ к созданному, — и всё это досталось бы каталогу
// установки вместе с наследством.
const sddl = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

// ourFiles — по чему видно, что каталог оставила прежняя установка.
//
// Список нужен ровно для одного решения: чинить права существующему каталогу
// или отказаться его трогать. Пустой каталог с наследованными правами — это не
// «наша установка без прав», а тот самый случай, ради которого всё затевалось.
var ourFiles = []string{
	"netadmin.exe", "netadmin.db", "config.json",
	"agent.exe", "agent_config.json", "agent_state.json",
}

// Secure приводит каталог установки к состоянию «доступ только у SYSTEM и
// администраторов» и возвращает true, если права пришлось чинить у уже
// существующего каталога: установщику есть что сказать об этом человеку.
//
// Отказывается работать с чужим каталогом. Занять место до установщика —
// самый дешёвый способ провести подмену: каталог создаётся заранее обычным
// пользователем, тот остаётся его владельцем с полными правами, и файл службы
// оказывается в его власти.
func Secure(dir string) (tightened bool, err error) {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return false, fmt.Errorf("список доступа: %w", err)
	}

	switch _, err := os.Stat(dir); {
	case errors.Is(err, os.ErrNotExist):
		return false, create(dir, sd)
	case err != nil:
		return false, fmt.Errorf("каталог %s: %w", dir, err)
	}

	closed, err := restricted(dir)
	if err != nil {
		return false, fmt.Errorf("права каталога %s: %w", dir, err)
	}
	if closed {
		return false, nil
	}
	if !ours(dir) {
		return false, fmt.Errorf(
			"каталог %s уже существует, открыт на запись обычным пользователям и не содержит "+
				"ничего от прежней установки NetAdmin.\n"+
				"Так выглядит попытка занять его до установщика: подменив файл службы, работающей "+
				"от SYSTEM, обычный пользователь получил бы полные права на машину.\n"+
				"Посмотрите, что внутри, удалите или переименуйте каталог и повторите установку.", dir)
	}

	dacl, _, err := sd.DACL()
	if err != nil {
		return false, fmt.Errorf("список доступа: %w", err)
	}
	// PROTECTED_DACL_SECURITY_INFORMATION — не просто записать список, но и
	// отрезать наследование: без него унаследованные разрешения останутся.
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		return false, fmt.Errorf("не удалось закрыть доступ к каталогу %s: %w", dir, err)
	}
	return true, nil
}

// create заводит каталог сразу с нужными правами.
func create(dir string, sd *windows.SECURITY_DESCRIPTOR) error {
	// Родителя создаём обычным способом: %ProgramData% есть всегда, а важны
	// права последнего каталога — данные лежат в нём.
	if parent := filepath.Dir(dir); parent != dir {
		if err := os.MkdirAll(parent, 0o755); err != nil {
			return fmt.Errorf("каталог %s: %w", parent, err)
		}
	}
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	sa := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}
	// Права задаются при создании, а не следующей строкой: между обычным
	// MkdirAll и правкой прав каталог существует открытым, и успеть положить
	// в него файл — обычная гонка, а не теоретическая.
	if err := windows.CreateDirectory(p, &sa); err != nil {
		return fmt.Errorf("каталог %s: %w", dir, err)
	}
	return nil
}

// restricted сообщает, что каталог уже закрыт: наследование отключено и
// разрешающие записи есть только у SYSTEM и администраторов.
func restricted(dir string) (bool, error) {
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false, err
	}
	ctrl, _, err := sd.Control()
	if err != nil {
		return false, err
	}
	if ctrl&windows.SE_DACL_PROTECTED == 0 {
		return false, nil // права наследуются от %ProgramData%
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return false, err
	}
	if dacl == nil {
		return false, nil // NULL DACL — доступ открыт всем
	}

	trusted, err := trustedSIDs()
	if err != nil {
		return false, err
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return false, err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue // запрещающая запись прав не даёт
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !trustedSID(trusted, sid) {
			return false, nil
		}
	}
	return true, nil
}

// trustedSIDs — те, кому каталог установки принадлежит по существу.
func trustedSIDs() ([]*windows.SID, error) {
	var out []*windows.SID
	for _, t := range []windows.WELL_KNOWN_SID_TYPE{
		windows.WinLocalSystemSid, windows.WinBuiltinAdministratorsSid,
	} {
		sid, err := windows.CreateWellKnownSid(t)
		if err != nil {
			return nil, err
		}
		out = append(out, sid)
	}
	return out, nil
}

func trustedSID(trusted []*windows.SID, sid *windows.SID) bool {
	for _, t := range trusted {
		if sid.Equals(t) {
			return true
		}
	}
	return false
}

// ours — в каталоге лежит хоть что-то от прежней установки.
func ours(dir string) bool {
	for _, name := range ourFiles {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			return true
		}
	}
	return false
}
