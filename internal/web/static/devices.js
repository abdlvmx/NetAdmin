
// Скрипт целиком в функции: объявления внутри блоков всплывают в общую
// область, а её делят layout.js, search.js и скрипт страницы. Наружу
// отдаётся только то, что явно положено в window.
(function () {
  let updateList = function () {}, saveList = function () {};
  async function scanNetwork(){
    const b = document.getElementById('scan-btn');
    const old = b.textContent;
    b.disabled = true; b.textContent = 'Сканирование…';
    try{
      const r = await fetch('/api/scan',{method:'POST',headers:{'X-CSRF-Token':window.csrfToken}});
      const d = await r.json();
      b.textContent = `Найдено: ${d.found}`;
      toast(`Сканирование завершено: найдено устройств — ${d.found}`, 'ok');
      setTimeout(()=>location.reload(), 900);
    }catch(e){
      b.textContent = 'Ошибка'; b.disabled = false;
      toast('Ошибка сканирования сети', 'err');
      setTimeout(()=>{ b.textContent = old; }, 1500);
    }
  }

  async function pingDevice(ip,id){
    const el = document.getElementById('status-'+id);
    el.innerHTML = '<span class="badge badge-amber">пинг…</span>';
    try{
      const r = await fetch('/api/ping',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':window.csrfToken},body:JSON.stringify({ip})});
      const d = await r.json();
      if (!r.ok) throw new Error(d.error || 'Ошибка пинга');
      el.innerHTML = d.status==='online'
        ? '<span class="badge badge-green">онлайн</span>'
        : '<span class="badge badge-red">оффлайн</span>';
      const row = document.getElementById('row-'+id);
      if (row) row.dataset.status = d.status;
      updateList();
      await refreshStatuses();
    }catch(e){ el.innerHTML = '<span class="badge badge-gray">ошибка</span>'; }
  }

  async function scanPorts(id, btn){
    const old = btn.textContent; btn.disabled = true; btn.textContent = 'Скан…';
    try{
      const r = await fetch(`/devices/${id}/scan-ports`,{method:'POST',headers:{'X-CSRF-Token':window.csrfToken}});
      const d = await r.json();
      if(d.ok){ toast('Открытые порты: ' + (d.ports && d.ports.length ? d.ports.join(', ') : 'нет'), 'ok'); setTimeout(()=>location.reload(), 900); }
      else { toast(d.error || 'Ошибка', 'err'); btn.disabled=false; btn.textContent=old; }
    }catch(e){ toast('Ошибка сканирования портов', 'err'); btn.disabled=false; btn.textContent=old; }
  }

  // ── авто-обновление статусов устройств (без перезагрузки) ──
  function statusBadge(s){
    if(s==='online')  return '<span class="badge badge-green">онлайн</span>';
    if(s==='offline') return '<span class="badge badge-red">оффлайн</span>';
    return '<span class="badge badge-gray">неизвестно</span>';
  }
  async function refreshStatuses(){
    if(document.hidden) return; // не дёргаем сервер, если вкладка не активна
    try{
      const r = await fetch('/api/devices/status');
      if (!r.ok) return;
      const d = await r.json();
      (d.devices||[]).forEach(dev=>{
        const st = document.getElementById('status-'+dev.id);
        if(st) st.innerHTML = statusBadge(dev.status);
        const sn = document.getElementById('seen-'+dev.id);
        if(sn) { sn.textContent = dev.last_seen || '—'; sn.dataset.sortVal = dev.last_seen_sort || ''; }
        const row = document.getElementById('row-'+dev.id);
        if(row) {
          row.dataset.status = dev.status;
          row.dataset.alert = dev.alert ? '1' : '0';
          row.dataset.agent = dev.has_agent ? 'yes' : 'no';
        }
        const agent = document.getElementById('agent-'+dev.id);
        if (agent) {
          agent.dataset.sortVal = dev.has_agent ? '1' : '0';
          agent.innerHTML = dev.has_agent ? '<span class="badge badge-green" title="агент зарегистрирован">✓ агент</span>' : '<span class="text-muted">—</span>';
        }
      });
      updateList();
    }catch(e){}
  }
  setInterval(refreshStatuses, 20000);

  // Состояние списка — на вкладку и пользователя. Явная ссылка с дашборда
  // задаёт новую выборку; обычный возврат /devices восстанавливает предыдущую.
  window.addEventListener('DOMContentLoaded', ()=>{
    const toolbar = document.getElementById('device-filters');
    const body = document.getElementById('dev-body');
    if (!toolbar || !body || !window.tableFilters) return;
    const controls = [...toolbar.querySelectorAll('[data-filter-key]')];
    const table = body.closest('table'), wrap = table.closest('.table-wrap');
    const storageKey = 'netadmin.devices.' + toolbar.dataset.stateUser;
    const allowed = { status: ['all','online','offline','unknown'], agent: ['all','yes','no'], alerts: ['all','1'] };
    const sortKeys = ['ip','agent','status','seen'];
    let restoring = true, stored = null;
    try { stored = JSON.parse(sessionStorage.getItem(storageKey)); } catch (e) {}
    const p = new URLSearchParams(location.search);
    const explicit = ['q','status','agent','alerts','sort','dir'].some(k => p.has(k));
    const source = explicit ? Object.fromEntries(p) : (stored && stored.filters) || {};
    controls.forEach(c => {
      const key = c.dataset.filterKey, value = source[key];
      c.value = key === 'q' ? (typeof value === 'string' ? value : '') : (allowed[key].includes(value) ? value : 'all');
    });
    const sortKey = explicit ? p.get('sort') : stored && stored.sort && stored.sort.key;
    const sortAsc = explicit ? p.get('dir') !== 'desc' : !(stored && stored.sort && stored.sort.asc === false);
    if (sortKeys.includes(sortKey)) {
      window.tableFilters.sort(table.querySelector('[data-sort-key="'+sortKey+'"]'), sortAsc);
    }
    function view() {
      const filters = Object.fromEntries(controls.map(c => [c.dataset.filterKey, c.value]));
      const th = table.querySelector('th[data-asc]');
      return { filters: filters, sort: th ? { key: th.dataset.sortKey, asc: th.dataset.asc === 'true' } : null };
    }
    function updateURL(state) {
      const params = new URLSearchParams(location.search);
      controls.forEach(c => {
        const key = c.dataset.filterKey, value = state.filters[key];
        if (value && value !== 'all') params.set(key, value); else params.delete(key);
      });
      if (state.sort) { params.set('sort', state.sort.key); params.set('dir', state.sort.asc ? 'asc' : 'desc'); }
      else { params.delete('sort'); params.delete('dir'); }
      const query = params.toString();
      history.replaceState(history.state, '', location.pathname + (query ? '?' + query : ''));
    }
    saveList = function () {
      if (restoring) return;
      const state = view();
      state.scrollTop = window.scrollY;
      state.scrollLeft = wrap.scrollLeft;
      try { sessionStorage.setItem(storageKey, JSON.stringify(state)); } catch (e) {}
    };
    body.addEventListener('table:filtered', e => {
      const n = e.detail;
      const count = document.getElementById('dev-count'), text = 'Показано ' + n.shown + ' из ' + n.total;
      if (count.textContent !== text) count.textContent = text;
      document.getElementById('dev-filter-empty').hidden = n.shown > 0 || n.total === 0;
      syncBulk();
      if (!restoring) { updateURL(view()); saveList(); }
    });
    table.addEventListener('table:sorted', () => { if (!restoring) { updateURL(view()); saveList(); } });
    updateList = function () {
      const th = table.querySelector('th[data-asc]');
      if (th) window.tableFilters.sort(th, th.dataset.asc === 'true');
      window.tableFilters.apply('#dev-body');
    };
    window.actions.resetDeviceFilters = function () {
      controls.forEach(c => { c.value = c.dataset.filterKey === 'q' ? '' : 'all'; });
      window.tableFilters.apply('#dev-body');
    };
    initBulk();
    updateList();
    const state = view();
    const sameView = stored && JSON.stringify(stored.filters) === JSON.stringify(state.filters) && JSON.stringify(stored.sort) === JSON.stringify(state.sort);
    updateURL(state);
    requestAnimationFrame(() => {
      if (sameView) {
        const top = Number(stored.scrollTop), left = Number(stored.scrollLeft);
        if (Number.isFinite(top) && top >= 0) window.scrollTo(0, top);
        if (Number.isFinite(left) && left >= 0) wrap.scrollLeft = left;
      }
      restoring = false;
      saveList();
    });
    let scrollTimer;
    function onScroll() { clearTimeout(scrollTimer); scrollTimer = setTimeout(saveList, 120); }
    window.addEventListener('scroll', onScroll, { passive: true });
    wrap.addEventListener('scroll', onScroll, { passive: true });
    window.addEventListener('pagehide', saveList);
    document.addEventListener('click', e => { if (e.target.closest('a[href]')) saveList(); }, true);
  });

  // Регистрация действий разметки (диспетчер — в layout.js).
  window.actions = window.actions || {};
  window.actions.scanNetwork = function () { scanNetwork(); };
  window.actions.ping = function (el) { pingDevice(el.dataset.ip, Number(el.dataset.id)); };
  window.actions.ports = function (el) { scanPorts(Number(el.dataset.id), el); };

  // ── Групповые действия ───────────────────────────────────────────────────────
  // Панель показывается, только когда что-то выбрано. Поле значения меняется под
  // выбранное действие: для владельца нужен список, для важности — да/нет,
  // для удаления значение не нужно вовсе.
  let syncBulk = function () {};
  function initBulk() {
    const form = document.getElementById('bulk-form');
    if (!form) return;                       // у наблюдателя панели нет
    const all = document.getElementById('dev-all');
    const action = document.getElementById('bulk-action');
    const fields = {
      text: document.getElementById('bulk-text'),
      employee: document.getElementById('bulk-employee'),
      critical: document.getElementById('bulk-critical'),
    };
    const picks = () => [...document.querySelectorAll('.dev-pick')];
    const chosen = () => picks().filter(c => c.checked);
    const isVisible = c => c.closest('tr').style.display !== 'none';
    let allowSubmit = false, reviewed = '';

    // Отключённое поле не уходит в запрос — так на сервер попадает ровно одно
    // значение, хотя полей с именем value три.
    function showField() {
      const a = action.value;
      const use = a === 'employee' ? 'employee' : a === 'critical' ? 'critical' : a === 'delete' ? null : 'text';
      for (const [k, el] of Object.entries(fields)) {
        const on = k === use;
        el.hidden = !on;
        el.disabled = !on;
      }
    }

    function sync() {
      const n = chosen().length;
      document.getElementById('bulk-n').textContent = n;
      form.hidden = n === 0;
      const hidden = chosen().filter(c => !isVisible(c)).length;
      const warning = document.getElementById('bulk-hidden');
      warning.hidden = hidden === 0;
      warning.textContent = hidden + ' скрыто фильтром';
      if (all) {
        const visible = picks().filter(isVisible);
        all.checked = visible.length > 0 && visible.every(c => c.checked);
        all.indeterminate = visible.some(c => c.checked) && !all.checked;
      }
      // выбранные уезжают в форму скрытыми полями: чекбоксы лежат в таблице
      form.querySelectorAll('input[name="device"]').forEach(el => el.remove());
      for (const c of chosen()) {
        const h = document.createElement('input');
        h.type = 'hidden'; h.name = 'device'; h.value = c.value;
        form.appendChild(h);
      }
    }
    syncBulk = sync;

    function signature() {
      const field = Object.values(fields).find(el => !el.disabled);
      return JSON.stringify([chosen().map(c => c.value).sort(), action.value, field ? field.value : '']);
    }
    function review() {
      sync();
      const selected = chosen();
      if (!selected.length) { toast('Выберите устройства', 'err'); return; }
      const field = Object.values(fields).find(el => !el.disabled);
      const value = field && field.tagName === 'SELECT' ? field.selectedOptions[0].textContent : field ? field.value : '';
      const verb = action.value === 'delete' ? 'Удалить выбранные устройства' : action.selectedOptions[0].textContent + ': ' + (value || '—');
      document.getElementById('bulk-review-action').textContent = verb;
      const hidden = selected.filter(c => !isVisible(c)).length;
      document.getElementById('bulk-review-count').textContent = 'Выбранные устройства: ' + selected.length + (hidden ? '. Скрыто фильтром: ' + hidden + '. Они тоже участвуют в действии.' : '.');
      const list = document.getElementById('bulk-review-list');
      list.replaceChildren();
      selected.forEach(c => {
        const row = c.closest('tr'), item = document.createElement('li');
        const name = document.createElement('strong'), meta = document.createElement('span');
        name.textContent = row.querySelector('.dev-link').textContent;
        meta.textContent = row.querySelector('.device-meta').textContent + (isVisible(c) ? '' : ' · скрыто фильтром');
        item.append(name, meta); list.appendChild(item);
      });
      const button = document.getElementById('bulk-review-apply');
      button.disabled = false;
      button.textContent = action.value === 'delete' ? 'Удалить устройства' : 'Применить';
      button.className = 'btn ' + (action.value === 'delete' ? 'btn-danger' : 'btn-primary');
      reviewed = signature();
      openModal('modal-bulk-review');
    }

    document.addEventListener('change', e => {
      if (e.target.classList && e.target.classList.contains('dev-pick')) sync();
      if (e.target === all) {
        picks().filter(isVisible)
               .forEach(c => { c.checked = all.checked; });
        sync();
      }
      if (e.target === action) showField();
    });

    window.actions = window.actions || {};
    window.actions.bulkClear = function () {
      picks().forEach(c => { c.checked = false; });
      if (all) all.checked = false;
      sync();
    };
    window.actions.bulkReview = review;
    window.actions.bulkConfirm = function (el, e) {
      if (allowSubmit) { allowSubmit = false; saveList(); return; }
      e.preventDefault(); review();
    };
    window.actions.bulkApply = function () {
      if (reviewed !== signature()) { review(); toast('Выбор или действие изменились. Проверьте их ещё раз.', ''); return; }
      if (!form.reportValidity()) return;
      allowSubmit = true;
      document.getElementById('bulk-review-apply').disabled = true;
      form.requestSubmit();
    };

    showField();
    sync();
  }
})();
