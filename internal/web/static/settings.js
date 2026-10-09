// Ожидание первого подключения агента и выбор адреса сервера.
//
// Установка агента на чужой машине заканчивается тем, что там закрывается
// окно. Состоялась она или нет, видно только на сервере — и до сих пор за этим
// надо было уходить в список устройств и обновлять его, гадая, сколько ждать.
// Страница теперь ждёт сама и говорит, кто подключился.
(function () {
  // Скрипт страницы может выполняться раньше layout.js. Обе стороны сохраняют
  // общий объект действий, поэтому выбор адреса работает при любом порядке.
  window.actions = window.actions || {};

  var page = document.getElementById('settings-page');
  if (page) {
    var pendingKey = 'netadmin.settings.pending.' + page.dataset.userId;
    // После возврата формы с общей ошибкой открываем раздел, который сохраняли.
    // В хранилище попадает только ID раздела: значения полей и ключи не сохраняются.
    var pendingSection = '';
    try {
      pendingSection = sessionStorage.getItem(pendingKey) || '';
      sessionStorage.removeItem(pendingKey);
    } catch (_) { /* браузер может запрещать хранилище */ }
    if (page.dataset.feedback && pendingSection) openSection(pendingSection, false);

    page.addEventListener('submit', function (event) {
      var section = event.target.closest('[data-settings-section]');
      try {
        if (section) sessionStorage.setItem(pendingKey, section.id);
        else sessionStorage.removeItem(pendingKey);
      } catch (_) { /* сохранение формы от этого не зависит */ }
    });

    function revealHash() {
      var id;
      try { id = decodeURIComponent(location.hash.slice(1)); }
      catch (_) { return; }
      openSection(id, true);
    }
    function openSection(id, scroll) {
      var target = document.getElementById(id);
      if (!target || !page.contains(target)) return;
      var section = target.closest('[data-settings-section]');
      if (section) section.open = true;
      if (scroll) target.scrollIntoView({ block: 'start' });
    }
    window.addEventListener('hashchange', revealHash);
    revealHash();
  }

  var box = document.getElementById('agent-wait');
  if (box) {
    var base = parseInt(box.dataset.base, 10) || 0;
    var text = box.querySelector('[data-wait-text]');
    // Ждём не вечно: страницу оставляют открытой на весь день, и опрос,
    // который никто уже не читает, — это только запросы на ровном месте.
    var until = Date.now() + 20 * 60 * 1000;
    var timer = null;

    function stop(html, cls) {
      clearInterval(timer);
      box.className = 'agent-wait ' + cls;
      text.innerHTML = html;
    }

    function check() {
      if (Date.now() > until) {
        stop('Ожидание прекращено. Обновите страницу, если установка ещё идёт.', 'idle');
        return;
      }
      if (document.hidden) return; // вкладка не на виду — спрашивать незачем

      fetch('/api/agents/enrolled', { headers: { 'Accept': 'application/json' } })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (d) {
          if (!d || d.count <= base) return;
          var name = d.last ? d.last.hostname : '';
          var href = d.last ? '/devices/' + d.last.id : '/devices';
          stop('Подключился <a href="' + href + '">' + escapeHTML(name) + '</a>. ' +
            'Ставьте на следующей машине — код действует, пока не кончится срок ' +
            'или число установок.', 'done');
        })
        .catch(function () { /* сеть моргнула — попробуем на следующем круге */ });
    }

    timer = setInterval(check, 5000);
    check();
  }

  // Выбор адреса перезагружает страницу: от него зависит и команда, и готовый
  // файл, и установщик .bat — собираются они на сервере, и менять адрес
  // где-то одном значило бы показывать рядом два разных сервера.
  window.actions.pickHost = function (el) {
    var p = new URLSearchParams(location.search);
    p.set('host', el.value);
    location.search = p.toString();
  };

  function escapeHTML(s) {
    var d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
  }
})();
