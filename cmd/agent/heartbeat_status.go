package main

import (
	"fmt"
	"strings"
)

func heartbeatRejection(status int, body []byte) string {
	switch status {
	case 401:
		return "HTTP 401: код регистрации истёк, отозван или не принят; получите новый код в настройках сервера"
	case 403:
		if strings.Contains(strings.ToLower(string(body)), "timestamp") || strings.Contains(strings.ToLower(string(body)), "time") {
			return "HTTP 403: часы компьютера расходятся с сервером; синхронизируйте время"
		}
		return "HTTP 403: сервер отверг подпись; проверьте адрес сервера и регистрацию устройства"
	case 409:
		return "HTTP 409: устройство уже зарегистрировано; проверьте его карточку и регистрацию"
	default:
		return fmt.Sprintf("сервер не принял данные: HTTP %d", status)
	}
}
