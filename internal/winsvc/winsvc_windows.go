//go:build windows

package winsvc

import (
	"fmt"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// IsService сообщает, что процесс запущен диспетчером служб, а не из консоли.
func IsService() bool {
	is, err := svc.IsWindowsService()
	return err == nil && is
}

// Elevated сообщает, что процесс запущен с правами администратора. Нужен, чтобы
// объяснить причину отказа заранее: без этой проверки менеджер служб отвечает
// «Access is denied», и человек не понимает, что достаточно открыть консоль
// от имени администратора.
func Elevated() bool {
	var sid *windows.SID
	// S-1-5-32-544 — встроенная группа «Администраторы»
	err := windows.AllocateAndInitializeSid(&windows.SECURITY_NT_AUTHORITY, 2,
		windows.SECURITY_BUILTIN_DOMAIN_RID, windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0, &sid)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)
	member, err := windows.Token(0).IsMember(sid)
	return err == nil && member
}

// Install регистрирует службу и запускает её. Если служба уже есть, обновляет
// путь к файлу и перезапускает: так выглядит обновление версии, и требовать
// ради него сначала -uninstall незачем.
func Install(c Config) error {
	if !Elevated() {
		return fmt.Errorf("нужны права администратора: откройте PowerShell или командную строку «от имени администратора»")
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("менеджер служб: %w", err)
	}
	defer m.Disconnect()

	conf := mgr.Config{
		// ServiceType задаётся явно: значения по умолчанию подставляет только
		// CreateService, а UpdateConfig передаёт структуру в систему как есть,
		// и нулевой тип она отвергает с «The parameter is incorrect». Из-за
		// этого повторная установка поверх существующей службы — то есть
		// обновление версии — не работала вовсе.
		ServiceType:    windows.SERVICE_WIN32_OWN_PROCESS,
		DisplayName:    c.DisplayName,
		Description:    c.Description,
		StartType:      mgr.StartAutomatic,
		ErrorControl:   mgr.ErrorNormal,
		BinaryPathName: quoteExec(c.Exe, c.Args),
	}

	s, err := m.OpenService(c.Name)
	if err == nil {
		defer s.Close()
		if err := stop(s); err != nil {
			return err
		}
		if err := s.UpdateConfig(conf); err != nil {
			return fmt.Errorf("обновление службы: %w", err)
		}
	} else {
		s, err = m.CreateService(c.Name, c.Exe, conf, c.Args...)
		if err != nil {
			return fmt.Errorf("создание службы: %w", err)
		}
		defer s.Close()
	}

	// Перезапуск при падении. Ради этого служба и выбрана вместо задачи
	// планировщика: задача с триггером onstart поднимает процесс только
	// при загрузке, а упавший агент оставался лежать до перезагрузки.
	_ = s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
	}, 86400)

	if err := s.Start(); err != nil {
		return fmt.Errorf("запуск службы: %w", err)
	}
	return nil
}

// Uninstall останавливает и удаляет службу. Отсутствие службы ошибкой не
// считается: команда должна доводить систему до нужного состояния, а не падать
// на повторном запуске.
func Uninstall(name string) error {
	if !Elevated() {
		return fmt.Errorf("нужны права администратора: откройте PowerShell или командную строку «от имени администратора»")
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("менеджер служб: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(name)
	if err != nil {
		return nil // службы нет — цель достигнута
	}
	defer s.Close()

	if err := stop(s); err != nil {
		return err
	}
	if err := s.Delete(); err != nil {
		return fmt.Errorf("удаление службы: %w", err)
	}
	return nil
}

// Stop останавливает службу, если она установлена и работает. Нужна отдельно
// от Install: подменить файл работающей службы Windows не даёт, поэтому
// обновление версии начинается именно с остановки.
func Stop(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("менеджер служб: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(name)
	if err != nil {
		return nil // не установлена — останавливать нечего
	}
	defer s.Close()
	return stop(s)
}

// Restart останавливает и снова запускает службу.
//
// Нужна там, где сервер меняет то, что читается только при старте: адрес
// прослушивания, разрешённые подсети, восстановленную из копии базу. Служба
// не может перезапустить себя изнутри — процесс, вызывающий Stop, будет
// остановлен вместе с ней, — поэтому Restart вызывается из отдельного
// процесса (`netadmin.exe -restart`).
func Restart(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("менеджер служб: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("служба %s не установлена", name)
	}
	defer s.Close()

	if err := stop(s); err != nil {
		return err
	}
	if err := s.Start(); err != nil {
		return fmt.Errorf("запуск службы: %w", err)
	}
	return nil
}

// State возвращает состояние службы одним из State* значений.
func State(name string) (string, error) {
	m, err := mgr.Connect()
	if err != nil {
		return "", fmt.Errorf("менеджер служб: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(name)
	if err != nil {
		return StateNotInstalled, nil
	}
	defer s.Close()

	st, err := s.Query()
	if err != nil {
		return "", fmt.Errorf("состояние службы: %w", err)
	}
	if st.State == svc.Running {
		return StateRunning, nil
	}
	return StateStopped, nil
}

// Run выполняет serve под управлением диспетчера служб: serve обязан вернуться,
// когда закроется переданный ему канал.
func Run(name string, serve func(stop <-chan struct{}) error) error {
	h := &handler{serve: serve}
	if err := svc.Run(name, h); err != nil {
		return err
	}
	return h.err
}

type handler struct {
	serve func(stop <-chan struct{}) error
	// err — с чем завершился serve. Пишется в горутине, читается после
	// возврата из Execute, то есть после её завершения: гонки нет.
	err error
}

func (h *handler) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.err = h.serve(stop)
	}()

	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				close(stop)
				<-done
				return false, 0
			}
		case <-done:
			// serve завершился сам, не дожидаясь команды, — это авария.
			// Код помечается специфичным для службы: иначе диспетчер толкует
			// единицу как ERROR_INVALID_FUNCTION и пишет в журнал не про то.
			status <- svc.Status{State: svc.StopPending}
			return true, 1
		}
	}
}

// stop останавливает службу и дожидается фактической остановки: сразу после
// команды служба ещё в StopPending, и удаление или подмена файла в этот момент
// не проходят.
func stop(s *mgr.Service) error {
	st, err := s.Query()
	if err != nil {
		return fmt.Errorf("состояние службы: %w", err)
	}
	if st.State == svc.Stopped {
		return nil
	}
	if _, err := s.Control(svc.Stop); err != nil {
		return fmt.Errorf("остановка службы: %w", err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(300 * time.Millisecond)
		st, err := s.Query()
		if err != nil {
			return fmt.Errorf("состояние службы: %w", err)
		}
		if st.State == svc.Stopped {
			return nil
		}
	}
	return fmt.Errorf("служба не остановилась за 30 секунд")
}

// quoteExec собирает командную строку службы ровно так же, как это делает
// mgr.CreateService: экранированием через syscall.EscapeArg. Нужна только для
// UpdateConfig (путь обновляемой службы), но расходиться с путём, который
// записывает создание службы, она не должна — иначе после обновления версии
// служба указывала бы на файл с иначе расставленными кавычками.
func quoteExec(exe string, args []string) string {
	s := syscall.EscapeArg(exe)
	for _, a := range args {
		s += " " + syscall.EscapeArg(a)
	}
	return s
}
