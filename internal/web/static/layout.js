// toast(msg, type) — всплывающее уведомление (type: 'ok' | 'err' | '' для инфо).
// Скрипт целиком в функции: объявления внутри блоков всплывают в общую
// область, а её делят layout.js, search.js и скрипт страницы. Наружу
// отдаётся только то, что явно положено в window.
(function () {
  function toast(msg, type) {
    if (!msg) return;
    var wrap = document.getElementById('toast-wrap');
    if (!wrap) return;
    var t = document.createElement('div');
    t.className = 'toast' + (type ? ' ' + type : '');
    t.textContent = (type === 'ok' ? '✓ ' : type === 'err' ? '⚠ ' : '') + msg;
    wrap.appendChild(t);
    setTimeout(function () { t.classList.add('fade'); setTimeout(function () { t.remove(); }, 380); }, 3600);
  }
  // Показ тостов из ?message= / ?error= (после redirect) + очистка URL, чтобы F5 не повторял.
  (function () {
    try {
      var p = new URLSearchParams(location.search);
      var ok = p.get('message'), err = p.get('error');
      if (ok) toast(ok, 'ok');
      if (err) toast(err, 'err');
      if (ok || err) {
        p.delete('message'); p.delete('error');
        var q = p.toString();
        history.replaceState(null, '', location.pathname + (q ? '?' + q : ''));
      }
    } catch (e) {}
  })();

  // Значок темы переключается сменой ссылки в <use>. Раньше здесь стоял
  // textContent с эмодзи, который затирал вставленный в кнопку <svg>.
  function applyThemeIcon() {
    var dark = document.documentElement.getAttribute('data-theme') === 'dark';
    var u = document.querySelector('#theme-toggle use');
    if (u) u.setAttribute('href', dark ? '#i-sun' : '#i-moon');
  }
  function toggleTheme() {
    var dark = document.documentElement.getAttribute('data-theme') === 'dark';
    if (dark) document.documentElement.removeAttribute('data-theme');
    else document.documentElement.setAttribute('data-theme', 'dark');
    try { localStorage.setItem('theme', dark ? 'light' : 'dark'); } catch (e) {}
    applyThemeIcon();
  }
  applyThemeIcon();

  // CSRF double-submit.
  window.csrfToken = (function () {
    const m = document.cookie.match('(^|;)\\s*csrf\\s*=\\s*([^;]+)');
    return m ? m.pop() : '';
  })();
  document.addEventListener('submit', function (e) {
    const f = e.target;
    if (f.method && f.method.toLowerCase() === 'post' && !f.querySelector('input[name=csrf_token]')) {
      const i = document.createElement('input');
      i.type = 'hidden'; i.name = 'csrf_token'; i.value = window.csrfToken;
      f.appendChild(i);
    }
  }, true);

  // Универсальные фильтры и сортировка таблиц.
  (function () {
    const groups = {};
    document.querySelectorAll('[data-filter-target]').forEach(function (ctrl) {
      const key = ctrl.getAttribute('data-filter-target');
      (groups[key] = groups[key] || []).push(ctrl);
      const ev = ctrl.tagName === 'SELECT' ? 'change' : 'input';
      ctrl.addEventListener(ev, function () { applyGroup(key, groups[key]); });
    });
    function applyGroup(sel, ctrls) {
      const tbody = document.querySelector(sel);
      if (!tbody) return;
      tbody.querySelectorAll('tr').forEach(function (tr) {
        if (!tr.querySelector('td')) return;
        let show = true;
        for (const c of ctrls) {
          const v = (c.value || '').trim().toLowerCase();
          if (!v || v === 'all') continue;
          if (c.tagName === 'SELECT' && c.dataset.col) {
            const attr = (tr.dataset[c.dataset.col] || '').toLowerCase();
            if (attr !== v) show = false;
          } else if (!tr.textContent.toLowerCase().includes(v)) show = false;
        }
        tr.style.display = show ? '' : 'none';
      });
    }
    // ipToInt — IPv4 «a.b.c.d» → 32-битное число для корректной сортировки (или null).
    function ipToInt(s) {
      const m = /^\s*(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\s*$/.exec(s || '');
      if (!m) return null;
      const p = [+m[1], +m[2], +m[3], +m[4]];
      if (p.some(function (n) { return n > 255; })) return null;
      return ((p[0] * 256 + p[1]) * 256 + p[2]) * 256 + p[3];
    }
    document.querySelectorAll('th[data-sort]').forEach(function (th) {
      th.addEventListener('click', function () {
        const table = th.closest('table');
        const tbody = table.querySelector('tbody');
        const idx = Array.prototype.indexOf.call(th.parentNode.children, th);
        const asc = th.dataset.asc !== 'true';
        th.parentNode.querySelectorAll('th[data-sort]').forEach(function (o) { if (o !== th) o.removeAttribute('data-asc'); });
        th.dataset.asc = asc;
        const rows = Array.prototype.slice.call(tbody.querySelectorAll('tr')).filter(function (r) { return r.querySelector('td'); });
        // ключ сортировки: data-sort-val ячейки (если задан) иначе её текст
        const keyOf = function (r) {
          const c = r.children[idx];
          if (!c) return '';
          return (c.dataset && c.dataset.sortVal != null) ? c.dataset.sortVal : c.textContent.trim();
        };
        rows.sort(function (a, b) {
          const x = keyOf(a), y = keyOf(b);
          let cmp;
          const ix = ipToInt(x), iy = ipToInt(y);
          const nx = parseFloat(x.replace(',', '.')), ny = parseFloat(y.replace(',', '.'));
          if (ix !== null && iy !== null) cmp = ix - iy;            // оба — IPv4: числовая сортировка
          else if (ix !== null) cmp = -1;                           // адреса выше «прочерков»/пустых
          else if (iy !== null) cmp = 1;
          else if (!isNaN(nx) && !isNaN(ny)) cmp = nx - ny;         // оба числа
          else cmp = x.localeCompare(y, 'ru');                      // иначе — строки
          return asc ? cmp : -cmp;
        });
        rows.forEach(function (r) { tbody.appendChild(r); });
      });
    });
  })();

  // ── Делегирование действий ───────────────────────────────────────────────────
  // Политика безопасности запрещает исполняемый код в атрибутах (onclick и
  // подобные), поэтому разметка лишь объявляет намерение через data-атрибуты,
  // а слушатель один на документ. Страницы регистрируют свои действия
  // Общие помощники интерфейса. Отдаются наружу явно: скрипт обёрнут в
  // функцию, и без этого страничные скрипты их не видят. Раньше они были
  // глобальными просто потому, что глобальным было всё, — и первая же обёртка
  // молча оторвала уведомления у сканирования, пинга и удалённых команд.
  window.toast = toast;
  window.openModal = openModal;
  window.closeModal = closeModal;

  // в window.actions — их вызывают с элементом и событием.
  window.actions = window.actions || {};

  function openModal(id) { var m = document.getElementById(id); if (m) m.classList.add('open'); }
  function closeModal(id) { var m = document.getElementById(id); if (m) m.classList.remove('open'); }

  function runAction(name, el, e) {
    var fn = window.actions[name];
    if (fn) fn(el, e);
  }

  document.addEventListener('click', function (e) {
    var ov = e.target.closest('[data-modal-overlay]');
    if (ov && e.target === ov) { closeModal(ov.dataset.modalOverlay); return; }

    var op = e.target.closest('[data-modal-open]');
    if (op) { openModal(op.dataset.modalOpen); return; }

    var cl = e.target.closest('[data-modal-close]');
    if (cl) { closeModal(cl.dataset.modalClose); return; }

    var go = e.target.closest('[data-href]');
    if (go) { location.href = go.dataset.href; return; }

    var a = e.target.closest('[data-act]');
    if (a) runAction(a.dataset.act, a, e);
  });

  // Подтверждение висит на форме, а не на кнопке: иначе клик и отправка
  // спрашивали бы дважды.
  document.addEventListener('submit', function (e) {
    var f = e.target.closest('form[data-confirm]');
    if (f && !confirm(f.dataset.confirm)) { e.preventDefault(); return; }
    var s = e.target.closest('form[data-act-submit]');
    if (s) runAction(s.dataset.actSubmit, s, e);
  });

  document.addEventListener('input', function (e) {
    var t = e.target.closest('[data-act-input]');
    if (t) runAction(t.dataset.actInput, t, e);
  });

  document.addEventListener('change', function (e) {
    var t = e.target.closest('[data-act-change]');
    if (t) runAction(t.dataset.actChange, t, e);
  });

  // Действия, общие для всех страниц.
  window.actions.theme = function () { toggleTheme(); };
  window.actions.selectAll = function (el) { el.select(); };
  // Копирование в буфер. Выделения мало: команда установки уезжает на другую
  // машину, и лишний шаг «теперь нажмите Ctrl+C» — тот самый, на котором
  // строка теряется, стоит случайно кликнуть мимо.
  //
  // Clipboard API требует защищённого соединения, а панель работает по
  // обычному HTTP: с самого сервера (localhost считается защищённым) он есть,
  // с соседней машины — нет. Поэтому старый execCommand здесь не запасной
  // путь, а основной для половины случаев.
  window.actions.copy = function (el) {
    var src = document.getElementById(el.dataset.target);
    if (!src) return;
    var text = src.value !== undefined ? src.value : src.textContent;

    function ok() { toast('Скопировано', 'ok'); }
    function legacy() {
      try {
        src.removeAttribute('readonly');
        src.select();
        src.setSelectionRange(0, text.length);
        document.execCommand('copy');
        src.setAttribute('readonly', '');
        ok();
      } catch (e) {
        src.select();
        toast('Скопируйте выделенное: Ctrl+C', '');
      }
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(ok, legacy);
    } else {
      legacy();
    }
  };
  // Показ/скрытие списка устройств по флажку «все ПК».
  window.actions.toggleList = function (el) {
    var box = document.getElementById(el.dataset.target);
    if (box) box.style.display = el.checked ? 'none' : 'block';
  };
})();
