//go:build windows

package instdir

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"netadmin/internal/winsvc"

	"golang.org/x/sys/windows"
)

// sddl — список доступа, который получает каталог установки.
//
//	O:BA             — владелец: встроенная группа «Администраторы»;
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
//
// Владелец задаётся не для порядка. Владельцу Windows всегда неявно даёт
// WRITE_DAC — право переписать список доступа, — и пока каталог принадлежит
// постороннему, любой выставленный нами список он может отменить. Сменить же
// владельца можно только на тот SID, который есть в собственном токене, а
// группы «Администраторы» у обычного пользователя там нет: подделать такого
// владельца он не может. Это и есть признак, по которому свой каталог
// отличается от занятого заранее.
const sddl = "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

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

	// Владелец проверяется раньше списка доступа и решает всё.
	//
	// Список подделать можно: тот, кто занял каталог до установщика, сам
	// выставит на него ровно те записи, которые мы ищем, останется владельцем
	// и потом вернёт себе доступ через WRITE_DAC. Владельца подделать нельзя,
	// поэтому чужой каталог отвергается независимо от того, как выглядят права
	// и что лежит внутри.
	owner, name, err := ownerOf(dir)
	if err != nil {
		return false, fmt.Errorf("владелец каталога %s: %w", dir, err)
	}
	if !trustedOwner(owner) {
		return false, fmt.Errorf(
			"каталог %s уже существует и принадлежит %s, а не системе или администраторам.\n"+
				"Так выглядит попытка занять его до установщика: владелец в любой момент вернёт "+
				"себе полный доступ и подменит файл службы, работающей от SYSTEM.\n"+
				"Посмотрите, что внутри, удалите или переименуйте каталог и повторите установку.",
			dir, name)
	}

	closed, err := restricted(dir)
	if err != nil {
		return false, fmt.Errorf("права каталога %s: %w", dir, err)
	}
	if closed {
		return false, nil
	}

	dacl, _, err := sd.DACL()
	if err != nil {
		return false, fmt.Errorf("список доступа: %w", err)
	}
	admins, _, err := sd.Owner()
	if err != nil {
		return false, fmt.Errorf("владелец: %w", err)
	}
	// Владелец выставляется заодно с правами: приводим его к группе, чтобы
	// каталог не зависел от того, какая учётная запись ставила прошлый раз.
	// PROTECTED_DACL отрезает наследование: без него унаследованные разрешения
	// остались бы.
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|
			windows.PROTECTED_DACL_SECURITY_INFORMATION,
		admins, nil, dacl, nil); err != nil {
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

// ownerOf — владелец каталога и его читаемое имя для сообщения об отказе.
func ownerOf(dir string) (*windows.SID, string, error) {
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return nil, "", err
	}
	sid, _, err := sd.Owner()
	if err != nil {
		return nil, "", err
	}
	return sid, ownerName(sid), nil
}

// ownerName — «DESKTOP\\user» там, где имя удалось разобрать, иначе сам SID:
// человеку в отказе полезнее имя, но отказ не должен зависеть от того,
// разрешается ли учётная запись.
func ownerName(sid *windows.SID) string {
	if account, domain, _, err := sid.LookupAccount(""); err == nil {
		if domain != "" {
			return domain + `\` + account
		}
		return account
	}
	return sid.String()
}

// trustedOwner — каталог принадлежит системе или встроенным администраторам.
//
// Обычный пользователь такого владельца не поставит: сменить владельца можно
// только на SID из собственного токена, а группы «Администраторы» у него там
// нет. Потому проверка и неподделываема — в отличие от списка доступа, который
// владелец волен выставить любой.
func trustedOwner(sid *windows.SID) bool {
	trusted, err := trustedSIDs()
	if err != nil {
		return false // не смогли выяснить — значит не доверяем
	}
	return trustedSID(trusted, sid)
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
	if sid, ok := installerAccount(); ok {
		out = append(out, sid)
	}
	return out, nil
}

// installerAccount — учётная запись, от имени которой идёт установка.
//
// Считается доверенным владельцем только у процесса с правами администратора.
// Нужна потому, что владелец каталога, заведённого прошлой установкой, зависит
// от политики машины «владелец объектов, создаваемых администраторами»: обычно
// это группа, но может быть и конкретный администратор — и тогда без этой
// оговорки установка отвергла бы собственный каталог вместе с базой внутри.
//
// Дыры это не открывает: обычный пользователь, занявший каталог заранее, не
// станет тем, кто запускает установщик с правами, а тот, кто им становится,
// и так имеет на машине всё.
func installerAccount() (*windows.SID, bool) {
	if !winsvc.Elevated() {
		return nil, false
	}
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, false
	}
	return u.User.Sid, true
}

func trustedSID(trusted []*windows.SID, sid *windows.SID) bool {
	for _, t := range trusted {
		if sid.Equals(t) {
			return true
		}
	}
	return false
}
