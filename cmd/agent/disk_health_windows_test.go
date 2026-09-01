//go:build windows

package main

import "testing"

// Отказ предсказывается только при явно неисправном состоянии. Раньше отказом
// считалось всё, кроме «Healthy», и диск в состоянии Warning поднимал на
// сервере критический инцидент с письмом.
func TestSmartPredictsFail(t *testing.T) {
	for _, h := range []string{"Unhealthy", "unhealthy", " Failed ", "fail"} {
		if !smartPredictsFail(h) {
			t.Errorf("%q должно считаться предсказанным отказом", h)
		}
	}
	for _, h := range []string{"", "Healthy", "healthy", "Warning", "warning", "Unknown"} {
		if smartPredictsFail(h) {
			t.Errorf("%q не должно считаться предсказанным отказом", h)
		}
	}
}
