//go:build windows

package winsvc

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

// CaptureConfig preserves the service command line and metadata independently
// of the installation files. The returned function reopens SCM only on rollback
// and does not start or stop a service. An absent service has nothing to restore.
func CaptureConfig(name string) (func() error, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, fmt.Errorf("менеджер служб для сохранения настроек: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return func() error { return nil }, nil
	}
	if err != nil {
		return nil, fmt.Errorf("чтение настроек службы %s: %w", name, err)
	}
	defer s.Close()
	config, err := s.Config()
	if err != nil {
		return nil, fmt.Errorf("сохранение настроек службы %s: %w", name, err)
	}
	actions, err := s.RecoveryActions()
	if err != nil {
		return nil, fmt.Errorf("сохранение восстановления службы %s: %w", name, err)
	}
	resetPeriod, err := s.ResetPeriod()
	if err != nil {
		return nil, fmt.Errorf("сохранение периода восстановления службы %s: %w", name, err)
	}
	// QueryServiceConfig cannot reveal an account password. x/sys translates an
	// empty Password to a nil argument, preserving the stored SCM password. The
	// installer also leaves the account unchanged, so do not rewrite it here.
	config = configSnapshotValue(config)
	actions = append([]mgr.RecoveryAction(nil), actions...)
	return func() error {
		manager, err := mgr.Connect()
		if err != nil {
			return fmt.Errorf("менеджер служб при откате: %w", err)
		}
		defer manager.Disconnect()
		service, err := manager.OpenService(name)
		if err != nil {
			return fmt.Errorf("служба %s при откате: %w", name, err)
		}
		defer service.Close()
		if err := service.UpdateConfig(config); err != nil {
			return fmt.Errorf("восстановление настроек службы %s: %w", name, err)
		}
		if config.Description == "" {
			// mgr.UpdateConfig passes nil for an empty description, which means
			// "unchanged". An empty UTF-16 string explicitly removes the text.
			empty, err := syscall.UTF16PtrFromString("")
			if err != nil {
				return err
			}
			description := windows.SERVICE_DESCRIPTION{Description: empty}
			if err := windows.ChangeServiceConfig2(service.Handle, windows.SERVICE_CONFIG_DESCRIPTION, (*byte)(unsafe.Pointer(&description))); err != nil {
				return fmt.Errorf("восстановление пустого описания службы %s: %w", name, err)
			}
		}
		if err := restoreRecoveryActions(service.Handle, actions, resetPeriod); err != nil {
			return fmt.Errorf("восстановление действий службы %s: %w", name, err)
		}
		return nil
	}, nil
}

func configSnapshotValue(config mgr.Config) mgr.Config {
	config.Password = ""
	config.ServiceStartName = ""
	config.Dependencies = append([]string(nil), config.Dependencies...)
	return config
}

// x/sys.SetRecoveryActions indexes element zero even for an empty slice. Use a
// nonnil pointer with count zero to remove actions for services that had none.
func restoreRecoveryActions(handle windows.Handle, actions []mgr.RecoveryAction, resetPeriod uint32) error {
	items := make([]windows.SC_ACTION, max(1, len(actions)))
	for i, action := range actions {
		items[i] = windows.SC_ACTION{Type: uint32(action.Type), Delay: uint32(action.Delay.Milliseconds())}
	}
	config := windows.SERVICE_FAILURE_ACTIONS{ResetPeriod: resetPeriod, ActionsCount: uint32(len(actions)), Actions: &items[0]}
	return windows.ChangeServiceConfig2(handle, windows.SERVICE_CONFIG_FAILURE_ACTIONS, (*byte)(unsafe.Pointer(&config)))
}
