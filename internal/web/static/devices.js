
// Скрипт целиком в функции: объявления внутри блоков всплывают в общую
// область, а её делят layout.js, search.js и скрипт страницы. Наружу
// отдаётся только то, что явно положено в window.
(function () {
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
      el.innerHTML = d.status==='online'
        ? '<span class="badge badge-green">онлайн</span>'
        : '<span class="badge badge-red">оффлайн</span>';
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
      const d = await (await fetch('/api/devices/status')).json();
      (d.devices||[]).forEach(dev=>{
        const st = document.getElementById('status-'+dev.id);
        if(st) st.innerHTML = statusBadge(dev.status);
        const sn = document.getElementById('seen-'+dev.id);
        if(sn) sn.textContent = dev.last_seen || '—';
        const row = document.getElementById('row-'+dev.id);
        if(row) row.dataset.status = dev.status;
      });
    }catch(e){}
  }
  setInterval(refreshStatuses, 20000);

  // ── применить фильтр из URL (клики с дашборда: ?status=offline, ?alerts=1) ──
  window.addEventListener('DOMContentLoaded', ()=>{
    const p = new URLSearchParams(location.search);
    const status = p.get('status');
    if(status){
      const sel = document.querySelector('select[data-col="status"]');
      if(sel){ sel.value = status; sel.dispatchEvent(new Event('change')); }
    }
    if(p.get('alerts')==='1'){
      document.querySelectorAll('#dev-body tr').forEach(tr=>{
        if(tr.querySelector('td')) tr.style.display = (tr.dataset.alert==='1') ? '' : 'none';
      });
      toast('Показаны устройства с предупреждениями (оффлайн / перегруз / нет связи)', '');
    }
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
  (function () {
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
      if (all) {
        const visible = picks().filter(c => c.closest('tr').style.display !== 'none');
        all.checked = visible.length > 0 && visible.every(c => c.checked);
      }
      // выбранные уезжают в форму скрытыми полями: чекбоксы лежат в таблице
      form.querySelectorAll('input[name="device"]').forEach(el => el.remove());
      for (const c of chosen()) {
        const h = document.createElement('input');
        h.type = 'hidden'; h.name = 'device'; h.value = c.value;
        form.appendChild(h);
      }
    }

    document.addEventListener('change', e => {
      if (e.target.classList && e.target.classList.contains('dev-pick')) sync();
      if (e.target === all) {
        picks().filter(c => c.closest('tr').style.display !== 'none')
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

    showField();
    sync();
  })();
})();
