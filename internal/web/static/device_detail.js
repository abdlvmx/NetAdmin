// Данные устройства приходят из data-атрибутов: файл статический и шаблон
// в нём не подставляется.
const DD = document.getElementById('dd-root').dataset;
const DEV_ID = Number(DD.id), DEV_IP = DD.ip, DEV_HOST = DD.host;
const esc = s => (s||'').replace(/</g,'&lt;');
function loadingRow(cols){ return `<tr><td colspan="${cols}" class="loading-row"><span class="spinner"></span>Загрузка…</td></tr>`; }
function ddFilter(searchId, bodyId, countId){
  const q = (document.getElementById(searchId).value || '').toLowerCase();
  const rows = document.querySelectorAll('#'+bodyId+' tr');
  let shown = 0;
  rows.forEach(tr=>{ const m = !q || tr.textContent.toLowerCase().includes(q); tr.style.display = m ? '' : 'none'; if(m) shown++; });
  const c = document.getElementById(countId);
  if(c) c.textContent = rows.length ? (q ? shown+' из '+rows.length : ''+rows.length) : '';
}

// generic loader: fetch url, map list → rows
async function loadTable(url, key, bodyId, emptyId, countId, searchId, rowFn, cols){
  const body = document.getElementById(bodyId), empty = document.getElementById(emptyId);
  body.innerHTML = loadingRow(cols); empty.style.display = 'none';
  try{
    const d = await (await fetch(url)).json();
    const list = d[key] || [];
    if(!list.length){ body.innerHTML=''; empty.style.display='block'; if(countId) document.getElementById(countId).textContent=''; return; }
    body.innerHTML = list.map(rowFn).join('');
    if(searchId) ddFilter(searchId, bodyId, countId);
  }catch(e){ body.innerHTML=''; empty.style.display='block'; }
}

const loaders = {
  software: () => loadTable(`/api/devices/${DEV_ID}/software`, 'software', 'sw-body', 'sw-empty', 'sw-count', 'sw-search',
    s=>`<tr><td>${esc(s.name)}</td><td class="text-muted">${esc(s.version)}</td><td class="text-muted">${esc(s.install_date)}</td></tr>`, 3),
  services: () => loadTable(`/api/devices/${DEV_ID}/services`, 'services', 'svc-body', 'svc-empty', 'svc-count', 'svc-search',
    s=>`<tr><td>${esc(s.display_name||s.name)}</td><td class="text-muted">${esc(s.start_type)}</td><td class="text-muted" style="word-break:break-all">${esc(s.path)}</td></tr>`, 3),
  autoruns: () => loadTable(`/api/devices/${DEV_ID}/autoruns`, 'autoruns', 'ar-body', 'ar-empty', 'ar-count', 'ar-search',
    s=>`<tr><td class="text-muted">${esc(s.location)}</td><td>${esc(s.name)}</td><td class="text-muted" style="word-break:break-all">${esc(s.command)}</td></tr>`, 3),
  schtasks: () => loadTable(`/api/devices/${DEV_ID}/schtasks`, 'tasks', 'task-body', 'task-empty', 'task-count', 'task-search',
    s=>`<tr><td>${esc((s.path||'')+(s.name||''))}</td><td class="text-muted">${esc(s.state)}</td><td class="text-muted" style="word-break:break-all">${esc(s.action)}</td></tr>`, 3),
  history: () => loadTable(`/api/devices/${DEV_ID}/changes`, 'changes', 'chg-body', 'chg-empty', 'chg-count', 'chg-search',
    c=>`<tr><td class="text-muted" style="white-space:nowrap">${esc(c.ts)}</td><td><b>${esc(c.field)}</b></td><td>${c.old?esc(c.old):'—'} <span class="text-muted">→</span> ${c.new?esc(c.new):'—'}</td></tr>`, 3),
  disks: () => loadTable(`/api/devices/${DEV_ID}/disks`, 'disks', 'disk-body', 'disk-empty', 'disk-count', 'disk-search',
    d=>{ const sev = d.severity==='critical' ? `<span class="badge badge-red">⚠ ${esc(d.issue)}</span>`
        : (d.severity==='warning' ? `<span class="badge badge-amber">${esc(d.issue)}</span>` : '<span class="badge badge-green">исправен</span>');
      return `<tr><td>${esc(d.model)||'—'}${d.serial?`<div class="text-muted" style="font-size:12px">S/N ${esc(d.serial)}</div>`:''}</td>`+
        `<td>${esc(d.media_type)||'—'}</td><td>${d.size_gb?d.size_gb+' ГБ':'—'}</td>`+
        `<td>${d.wear_pct?d.wear_pct+'%':'—'}</td><td>${d.temperature?d.temperature+'°C':'—'}</td>`+
        `<td class="text-muted">${d.power_on_hours?d.power_on_hours+' ч':'—'}</td><td>${sev}</td></tr>`; }, 7),
  tasks: () => loadTable(`/api/devices/${DEV_ID}/tasks`, 'tasks', 'task-act-body', 'task-act-empty', 'task-act-count', 'task-act-search',
    t=>{ const st = t.status==='done' ? '<span class="badge badge-green">выполнено</span>'
        : t.status==='failed' ? '<span class="badge badge-red">ошибка</span>'
        : t.status==='sent' ? '<span class="badge badge-accent">отправлено</span>'
        : '<span class="badge badge-amber">ожидает</span>';
      return `<tr><td class="text-muted" style="white-space:nowrap">${esc(t.created)}</td><td>${esc(t.label||t.kind)}</td><td>${st}</td><td class="text-muted" style="word-break:break-word">${esc(t.result)||'—'}</td></tr>`; }, 4),
  metrics: () => loadMetrics(),
};
const loaded = {};

document.getElementById('dd-tabs').addEventListener('click', e=>{
  const b = e.target.closest('button[data-tab]'); if(!b) return;
  const tab = b.dataset.tab;
  document.querySelectorAll('#dd-tabs button').forEach(x=>x.classList.toggle('on', x===b));
  document.querySelectorAll('.tab-pane').forEach(p=>p.hidden = (p.id !== 'pane-'+tab));
  if(loaders[tab] && !loaded[tab]){ loaded[tab] = true; loaders[tab](); }
  if(tab==='metrics') loadMetrics(); // перерисовать под актуальный размер
});

// ── метрики ──
let ddHours = 24;
document.getElementById('dd-range').addEventListener('click', e=>{
  const b = e.target.closest('button[data-h]'); if(!b) return;
  ddHours = +b.dataset.h;
  document.querySelectorAll('#dd-range button').forEach(x=>x.classList.toggle('on', x===b));
  loadMetrics();
});
async function loadMetrics(){
  const canvas = document.getElementById('dd-canvas'), empty = document.getElementById('dd-canvas-empty');
  try{
    const d = await (await fetch(`/api/devices/${DEV_ID}/metrics?hours=${ddHours}`)).json();
    if(!d.points || !d.points.length){ canvas.style.display='none'; empty.style.display='block'; return; }
    empty.style.display='none'; canvas.style.display='block';
    drawLines(canvas, d.points);
  }catch(e){ canvas.style.display='none'; empty.style.display='block'; }
}
function drawLines(canvas, points){
  const dpr = window.devicePixelRatio||1, w = canvas.clientWidth, h = canvas.clientHeight;
  // Вкладка может быть ещё скрыта — тогда размеры нулевые. Рисовать в такой
  // холст нельзя: canvas.width задаёт и внутренний размер, и, при отсутствии
  // CSS-размера, внешний — картинка поехала бы при каждой перерисовке.
  if(!w || !h) return;
  canvas.width=w*dpr; canvas.height=h*dpr;
  const ctx = canvas.getContext('2d'); ctx.setTransform(dpr,0,0,dpr,0,0); ctx.clearRect(0,0,w,h);
  const padL=34,padR=10,padT=10,padB=22, plotW=w-padL-padR, plotH=h-padT-padB;
  const yOf=v=>padT+plotH*(1-v/100), xOf=i=>padL+(points.length===1?plotW/2:plotW*i/(points.length-1));
  const css=getComputedStyle(document.documentElement);
  ctx.strokeStyle=css.getPropertyValue('--border').trim(); ctx.fillStyle=css.getPropertyValue('--muted').trim();
  ctx.font='11px sans-serif'; ctx.lineWidth=1; ctx.textAlign='right'; ctx.textBaseline='middle';
  for(let v=0;v<=100;v+=25){const y=yOf(v);ctx.beginPath();ctx.moveTo(padL,y);ctx.lineTo(w-padR,y);ctx.stroke();ctx.fillText(v+'%',padL-6,y);}
  ctx.textBaseline='top'; ctx.textAlign='left'; ctx.fillText((points[0].ts||'').slice(5,16),padL,h-padB+5);
  if(points.length>1){ctx.textAlign='right';ctx.fillText((points[points.length-1].ts||'').slice(5,16),w-padR,h-padB+5);}
  for(const [k,c] of [['cpu','#0d9488'],['ram','#7c3aed'],['disk','#d97706']]){
    ctx.strokeStyle=c; ctx.lineWidth=1.8; ctx.beginPath(); let st=false;
    points.forEach((p,i)=>{const v=p[k]; if(v==null){st=false;return;} const x=xOf(i),y=yOf(v); st?ctx.lineTo(x,y):(ctx.moveTo(x,y),st=true);});
    ctx.stroke();
  }
}

// ── действия ──
async function ddPing(){
  const el = document.getElementById('dd-status');
  el.innerHTML = '<span class="badge badge-amber">пинг…</span>';
  try{
    const d = await (await fetch('/api/ping',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':window.csrfToken},body:JSON.stringify({ip:DEV_IP})})).json();
    el.innerHTML = d.status==='online' ? '<span class="badge badge-green">онлайн</span>' : '<span class="badge badge-red">оффлайн</span>';
    toast(d.status==='online' ? 'Устройство в сети' : 'Устройство не отвечает', d.status==='online'?'ok':'err');
  }catch(e){ el.innerHTML='<span class="badge badge-gray">ошибка</span>'; toast('Ошибка пинга','err'); }
}
const POWER_LABELS = {wol:'включить (Wake-on-LAN)', reboot:'ПЕРЕЗАГРУЗИТЬ', shutdown:'ВЫКЛЮЧИТЬ', logoff:'завершить сессию пользователя на'};
async function ddRunCommand(){
  const sel = document.getElementById('cmd-select');
  const key = sel.value; if(!key){ toast('Выберите команду','err'); return; }
  const o = sel.options[sel.selectedIndex];
  if(o.dataset.danger==='1' && !confirm('Команда прервёт работу пользователя. Выполнить?')) return;
  try{
    const fd = new URLSearchParams({cmd:key});
    const d = await (await fetch(`/devices/${DEV_ID}/run-command`,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded','X-CSRF-Token':window.csrfToken},body:fd})).json();
    toast(d.ok ? (d.message||'Задача поставлена') : (d.error||'Ошибка'), d.ok?'ok':'err');
    if(d.ok){ loaded['tasks']=false; loaders.tasks(); loaded['tasks']=true; }
  }catch(e){ toast('Ошибка запуска команды','err'); }
}
async function ddPower(action){
  if(action!=='wol' && !confirm(`Точно ${POWER_LABELS[action]} устройство ${DEV_HOST}?`)) return;
  try{
    const fd = new URLSearchParams({action});
    const d = await (await fetch(`/devices/${DEV_ID}/power`,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded','X-CSRF-Token':window.csrfToken},body:fd})).json();
    toast(d.ok ? (d.message||'Готово') : (d.error||'Ошибка'), d.ok?'ok':'err');
    if(d.ok){ loaded['tasks']=false; }
  }catch(e){ toast('Ошибка выполнения действия','err'); }
}
async function ddScanPorts(btn){
  const old = btn.textContent; btn.disabled=true; btn.textContent='Скан…';
  try{
    const d = await (await fetch(`/devices/${DEV_ID}/scan-ports`,{method:'POST',headers:{'X-CSRF-Token':window.csrfToken}})).json();
    if(d.ok){ toast('Открытые порты: ' + (d.ports && d.ports.length ? d.ports.join(', ') : 'нет'), 'ok'); setTimeout(()=>location.reload(),900); }
    else { toast(d.error || 'Ошибка', 'err'); btn.disabled=false; btn.textContent=old; }
  }catch(e){ toast('Ошибка сканирования портов','err'); btn.disabled=false; btn.textContent=old; }
}

// Регистрация действий разметки: атрибуты data-act/data-act-input вместо
// обработчиков в HTML (см. диспетчер в layout.js).
window.actions = window.actions || {};
window.actions.filter = function (el) {
  var p = el.dataset.filter.split('|');
  ddFilter(p[0], p[1], p[2]);
};
window.actions.power = function (el) { ddPower(el.dataset.power); };
window.actions.ping = function () { ddPing(); };
window.actions.scanPorts = function (el) { ddScanPorts(el); };
window.actions.runCommand = function () { ddRunCommand(); };
