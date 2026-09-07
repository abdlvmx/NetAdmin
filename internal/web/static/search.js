// Глобальный поиск: Ctrl+K с любой страницы.
//
// Скрипт вынесен из разметки, потому что политика безопасности запрещает
// исполняемый код внутри страницы (script-src 'self' без unsafe-inline).

// Всё внутри функции. Объявления в блоке `if` всплывают в глобальную
// область (правила веб-совместимости), и функция render отсюда перекрывала
// одноимённую функцию карты сети — карта переставала рисоваться. Заодно
// перестают течь наружу open и close, затенявшие window.open.
(function () {
  const box = document.getElementById('gsearch');
  if (box) {
    const input = document.getElementById('gsearch-input');
    const list = document.getElementById('gsearch-results');
    const hint = document.getElementById('gsearch-hint');
    let items = [];   // плоский список ссылок для навигации стрелками
    let active = -1;
    let seq = 0;      // номер запроса: ответы могут прийти не в том порядке

    const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g,
      c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

    function open() {
      box.classList.add('on');
      input.value = '';
      list.innerHTML = '';
      items = []; active = -1;
      hint.textContent = 'Устройства, сотрудники, программы, заявки';
      input.focus();
    }

    function close() {
      box.classList.remove('on');
    }

    function highlight(n) {
      items.forEach((el, i) => el.classList.toggle('on', i === n));
      if (n >= 0 && items[n]) items[n].scrollIntoView({ block: 'nearest' });
      active = n;
    }

    function render(groups) {
      list.innerHTML = '';
      items = []; active = -1;
      if (!groups.length) {
        hint.textContent = 'Ничего не найдено';
        return;
      }
      hint.textContent = '↑↓ — выбор, Enter — открыть, Esc — закрыть';
      for (const g of groups) {
        const h = document.createElement('div');
        h.className = 'gs-group';
        h.textContent = g.title;
        list.appendChild(h);
        for (const it of g.items) {
          const a = document.createElement('a');
          a.className = 'gs-item';
          a.href = it.href;
          a.innerHTML = `<span class="gs-label">${esc(it.label)}</span>` +
            (it.sub ? `<span class="gs-sub">${esc(it.sub)}</span>` : '');
          list.appendChild(a);
          items.push(a);
        }
      }
      highlight(0);
    }

    let timer = null;
    input.addEventListener('input', () => {
      clearTimeout(timer);
      const q = input.value.trim();
      if (q.length < 2) {
        list.innerHTML = '';
        items = []; active = -1;
        hint.textContent = 'Введите хотя бы два символа';
        return;
      }
      // ждём паузу в наборе: иначе на каждую букву уходит запрос
      timer = setTimeout(async () => {
        const mine = ++seq;
        try {
          const res = await fetch('/api/search?q=' + encodeURIComponent(q));
          if (!res.ok) throw new Error(res.status);
          const data = await res.json();
          if (mine !== seq) return; // пришёл ответ на устаревший запрос
          render(data.groups || []);
        } catch (e) {
          if (mine === seq) hint.textContent = 'Поиск недоступен';
        }
      }, 180);
    });

    document.addEventListener('keydown', e => {
      // Ctrl+K (Cmd+K на Mac) — открыть; браузерный поиск по строке не трогаем
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        box.classList.contains('on') ? close() : open();
        return;
      }
      if (!box.classList.contains('on')) return;
      if (e.key === 'Escape') { e.preventDefault(); close(); return; }
      if (e.key === 'ArrowDown' && items.length) {
        e.preventDefault(); highlight((active + 1) % items.length);
      } else if (e.key === 'ArrowUp' && items.length) {
        e.preventDefault(); highlight((active - 1 + items.length) % items.length);
      } else if (e.key === 'Enter' && active >= 0) {
        e.preventDefault(); items[active].click();
      }
    });

    // клик мимо окна закрывает поиск
    box.addEventListener('click', e => { if (e.target === box) close(); });

    const opener = document.getElementById('gsearch-open');
    if (opener) opener.addEventListener('click', open);
  }
})();
