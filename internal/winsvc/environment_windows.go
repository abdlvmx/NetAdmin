//go:build windows

package winsvc

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// Environment reads service and machine environment values from their Windows
// configuration, never a per-user override inherited by this installer.
func Environment(name, key string) (string, error) {
	if name == "" || key == "" || strings.ContainsAny(name, `\/`) || strings.ContainsRune(key, '=') {
		return "", fmt.Errorf("неверное имя службы или переменной окружения")
	}
	service, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\`+name, registry.QUERY_VALUE)
	if err == nil {
		values, _, readErr := service.GetStringsValue("Environment")
		service.Close()
		if readErr != nil && !errors.Is(readErr, registry.ErrNotExist) {
			return "", fmt.Errorf("окружение службы %s: %w", name, readErr)
		}
		if value, found := serviceEnvironmentValue(values, key); found {
			return expandServiceEnvironment(value)
		}
	} else if !errors.Is(err, registry.ErrNotExist) {
		return "", fmt.Errorf("настройки службы %s: %w", name, err)
	}
	machine, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`, registry.QUERY_VALUE)
	if err != nil {
		return "", fmt.Errorf("машинное окружение службы: %w", err)
	}
	defer machine.Close()
	value, kind, err := machine.GetStringValue(key)
	if errors.Is(err, registry.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("машинная переменная %s: %w", key, err)
	}
	if kind == registry.EXPAND_SZ {
		return expandServiceEnvironment(value)
	}
	return value, nil
}

func expandServiceEnvironment(value string) (string, error) {
	// ExpandEnvironmentStrings uses the caller's environment, which may differ
	// from the cached SYSTEM/SCM environment. Never guess a rollback directory.
	if strings.Contains(value, "%") {
		return "", fmt.Errorf("путь службы содержит переменную вида %%ИМЯ%%: задайте полный абсолютный путь без переменных в настройках службы и перезапустите Windows перед обновлением")
	}
	return value, nil
}
