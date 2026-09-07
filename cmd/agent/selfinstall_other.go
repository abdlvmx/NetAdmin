//go:build !windows

package main

import "errors"

// Установка службой существует только в Windows: на прочих ОС агент шлёт лишь
// heartbeat и запускается средствами системы (systemd, launchd, cron).

// Имя службы объявлено и здесь: main общий для всех ОС и ссылается на него,
// хотя вне Windows эта ветка недостижима.
const agentServiceName = "NetAdminAgent"

var errInstallUnsupported = errors.New("установка службой доступна только в Windows: " +
	"запустите агента средствами своей ОС, задав NETADMIN_SERVER_URL и NETADMIN_AGENT_TOKEN")

func installAgent(string, string) error { return errInstallUnsupported }
func uninstallAgent() error             { return errInstallUnsupported }

func startServiceLog() {}
