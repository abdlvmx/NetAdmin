package agentbin

import (
	"testing"
	"time"
)

// Забытая пересборка агента должна быть видна.
//
// Сервер встраивает то, что лежит в bin/ на момент его сборки. Порядок «агент
// первым» ничем не проверялся, и сервер трое суток раздавал сборку агента
// трёхдневной давности — молча, пока та не отказалась ставиться поверх своей же
// службы. Разные ревизии — единственный надёжный признак этого.
func TestDifferentRevisionIsStale(t *testing.T) {
	agent := Build{Revision: "f72009bb363aa5255a9a23594c9e9431a712a095", Time: time.Now().Add(-72 * time.Hour)}
	server := Build{Revision: "282cae71999119fc86ece6009b4bd75832f789ec", Time: time.Now()}

	if got := compare(agent, true, server, true); got != MatchStale {
		t.Errorf("сравнение дало %v, ожидалось MatchStale", got)
	}
}

// Одна ревизия — порядок соблюдён, и молчать здесь правильно.
func TestSameRevisionIsFine(t *testing.T) {
	b := Build{Revision: "282cae71999119fc86ece6009b4bd75832f789ec"}
	if got := compare(b, true, b, true); got != MatchSame {
		t.Errorf("сравнение дало %v, ожидалось MatchSame", got)
	}
}

// Правки в дереве при совпавшей ревизии поводом для жалобы не считаются.
//
// Две сборки из одного коммита в разные дни неотличимы, и предупреждать об этом
// значило бы жечь предупреждение всю разработку — после чего его перестают
// читать, и оно не сработает там, где нужно.
func TestModifiedTreeIsNotAComplaint(t *testing.T) {
	agent := Build{Revision: "282cae7", Modified: true}
	server := Build{Revision: "282cae7", Modified: true}
	if got := compare(agent, true, server, true); got != MatchSame {
		t.Errorf("сравнение дало %v, ожидалось MatchSame", got)
	}
}

// Без сведений о сборке (сборка не из git или с -buildvcs=false) сравнивать
// не с чем — и делать вид, что всё в порядке, тоже нельзя.
func TestWithoutBuildInfoNothingIsClaimed(t *testing.T) {
	b := Build{Revision: "282cae7"}
	if got := compare(b, false, b, true); got != MatchUnknown {
		t.Errorf("без сведений об агенте дало %v, ожидалось MatchUnknown", got)
	}
	if got := compare(b, true, b, false); got != MatchUnknown {
		t.Errorf("без сведений о сервере дало %v, ожидалось MatchUnknown", got)
	}
}

// Short режет ревизию до привычного вида и не ломается на коротких строках.
func TestShortRevision(t *testing.T) {
	if got := (Build{Revision: "282cae71999119fc86ece6009b4bd75832f789ec"}).Short(); got != "282cae7" {
		t.Errorf("получено %q", got)
	}
	if got := (Build{Revision: "abc"}).Short(); got != "abc" {
		t.Errorf("короткая ревизия испорчена: %q", got)
	}
}
