package config

import "testing"

// TestNetworkSettingSources — порядок источников определяет, что реально
// применится при запуске, и ошибка здесь проявляется как «задал, а не
// сработало»: именно так вело себя окружение консоли для установленной службы.
func TestNetworkSettingSources(t *testing.T) {
	cases := []struct {
		name       string
		env, file  string
		wantValue  string
		wantSource string
	}{
		{"ничего не задано", "", "", "", SourceDefault},
		{"только настройка", "", "192.168.1.0/24", "192.168.1.0/24", SourceConfig},
		{"только переменная", "10.0.0.0/8", "", "10.0.0.0/8", SourceEnv},
		{"переменная важнее настройки", "10.0.0.0/8", "192.168.1.0/24", "10.0.0.0/8", SourceEnv},
		{"пробелы не считаются значением", "   ", "  192.168.1.0/24  ", "192.168.1.0/24", SourceConfig},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("NETADMIN_ALLOW", c.env)
			got := Config{AllowSubnets: c.file}.AllowSubnetsSetting()
			if got.Value != c.wantValue || got.Source != c.wantSource {
				t.Errorf("получено %q (%s), ожидалось %q (%s)",
					got.Value, got.Source, c.wantValue, c.wantSource)
			}
		})
	}
}

// TestListenAddrSetting — тот же порядок для адреса прослушивания.
func TestListenAddrSetting(t *testing.T) {
	t.Setenv("NETADMIN_ADDR", "")
	if got := (Config{ListenAddr: "127.0.0.1:9000"}).ListenAddrSetting(); got.Value != "127.0.0.1:9000" || got.Source != SourceConfig {
		t.Errorf("настройка из файла не применилась: %+v", got)
	}

	t.Setenv("NETADMIN_ADDR", ":9100")
	if got := (Config{ListenAddr: "127.0.0.1:9000"}).ListenAddrSetting(); got.Value != ":9100" || got.Source != SourceEnv {
		t.Errorf("переменная окружения не перекрыла настройку: %+v", got)
	}
}
