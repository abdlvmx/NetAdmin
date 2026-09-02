const SVGNS = "http://www.w3.org/2000/svg";
const css = getComputedStyle(document.documentElement);
const cv = n => css.getPropertyValue(n).trim();
const ACCENT = cv('--accent'), ACCENT2 = cv('--accent-hov') || ACCENT, TEXT = cv('--text');

// i — идентификатор значка в общем спрайте (layout.html), s — радиус узла.
const TYPE = {
  pc:      { i:'devices', l:'ПК',              s:8 },
  server:  { i:'server',  l:'Сервер',          s:12 },
  phone:   { i:'phone',   l:'Телефон',         s:5 },
  camera:  { i:'camera',  l:'Камера',          s:6 },
  ap:      { i:'antenna', l:'Точка доступа',    s:9 },
  printer: { i:'printer', l:'Принтер',         s:7 },
  network: { i:'switch',  l:'Сеть/коммутатор', s:12 },
  other:   { i:'dot',     l:'Прочее',          s:7 },
};

// tico — значок типа для вставки в HTML (подсказка, легенда, список проблем).
const tico = t => `<svg class="ico ico-sm"><use href="#i-${(TYPE[t]||TYPE.other).i}"/></svg>`;
const STC = { online: cv('--green'), stale: cv('--amber'), offline: cv('--red'), unknown: '#9aa6bd' };
const STL = { online:'онлайн', stale:'давно не отвечал', offline:'оффлайн', unknown:'неизвестно' };
const SORD = { online:0, stale:1, unknown:2, offline:3 };

let allNodes = [], allLinks = [];
const statusOn = new Set(['online','stale','offline','unknown']);
const typeOn = new Set();
let groupBy = 'type';

function el(tag, attrs) { const e = document.createElementNS(SVGNS, tag); for (const k in attrs) e.setAttribute(k, attrs[k]); return e; }
function esc(s){ return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function trunc(s,n){ s=s||''; return s.length>n ? s.slice(0,n-1)+'…' : s; }
function nodeKey(n){ return (n.hostname+' '+n.ip+' '+n.mac+' '+n.vendor).toLowerCase(); }

// blockLayout раскладывает узлы блоками по группам: внутри блока — сетка,
// блоки переносятся по строкам. Раньше был круг, где положение узла не значило
// ничего, а подписи отключались уже на 40 устройствах.
const CELL_W = 104, CELL_H = 74, BOX_PAD = 14, BOX_HEAD = 22, BOX_GAP = 18;

function blockLayout(groups, maxW) {
  const boxes = [];
  let x = 0, y = 0, rowH = 0;
  for (const g of groups) {
    const cols = Math.max(1, Math.min(8, Math.ceil(Math.sqrt(g.nodes.length))));
    const rows = Math.ceil(g.nodes.length / cols);
    const w = BOX_PAD * 2 + cols * CELL_W;
    const h = BOX_PAD * 2 + BOX_HEAD + rows * CELL_H;
    if (x > 0 && x + w > maxW) { x = 0; y += rowH + BOX_GAP; rowH = 0; }
    const pos = g.nodes.map((n, i) => ({
      node: n,
      x: x + BOX_PAD + (i % cols) * CELL_W + CELL_W / 2,
      y: y + BOX_PAD + BOX_HEAD + Math.floor(i / cols) * CELL_H + 22,
    }));
    boxes.push({ title: g.title, x, y, w, h, pos });
    x += w + BOX_GAP;
    rowH = Math.max(rowH, h);
  }
  const width = boxes.length ? Math.max(...boxes.map(b => b.x + b.w)) : 0;
  const height = y + rowH;
  return { boxes, width, height };
}

function visibleNodes(){ return allNodes.filter(n => statusOn.has(n.status) && typeOn.has(n.type)); }
function groupKeyOf(n){ return groupBy==='type' ? (TYPE[n.type]?.l || n.type) : groupBy==='subnet' ? (n.subnet||'—') : ''; }

function render() {
  const svg = document.getElementById('netmap');
  const empty = document.getElementById('map-empty');
  const tip = document.getElementById('map-tip');
  const nodes = visibleNodes();

  svg.innerHTML = '';
  if (!nodes.length) { empty.style.display='block'; svg.style.display='none'; applySearch(); return; }
  empty.style.display='none'; svg.style.display='block';

  // группируем и сортируем: проблемные вперёд, чтобы взгляд цеплялся за них
  const byKey = new Map();
  nodes.forEach(n => {
    const k = groupKeyOf(n) || 'Все устройства';
    if (!byKey.has(k)) byKey.set(k, []);
    byKey.get(k).push(n);
  });
  const groups = [...byKey.entries()].sort((a,b)=> a[0]<b[0]?-1:1).map(([title, list]) => ({
    title,
    nodes: list.sort((a,b)=> (SORD[a.status]??2)-(SORD[b.status]??2) ||
                             (a.hostname||a.ip||'').localeCompare(b.hostname||b.ip||'')),
  }));

  const wrapW = svg.closest('.map-wrap').clientWidth - 24;
  const { boxes, width, height } = blockLayout(groups, Math.max(420, wrapW));
  const M = 12;
  svg.setAttribute('viewBox', `${-M} ${-M} ${width + M*2} ${height + M*2}`);

  // рамки групп
  const gBoxes = el('g', {});
  boxes.forEach(b => {
    gBoxes.appendChild(el('rect', {class:'gbox', x:b.x, y:b.y, width:b.w, height:b.h, rx:6}));
    const t = el('text', {class:'gtitle', x:b.x + BOX_PAD, y:b.y + 15});
    t.textContent = b.title + ' · ' + b.pos.length;
    gBoxes.appendChild(t);
  });
  svg.appendChild(gBoxes);

  // рёбра — только объявленные связи, у которых видны оба конца
  const at = new Map();
  boxes.forEach(b => b.pos.forEach(p => at.set(p.node.id, p)));
  const gEdges = el('g', {});
  allLinks.forEach(l => {
    const a = at.get(l.from), b = at.get(l.to);
    if (!a || !b) return;
    const ln = el('line', {class:'edge', x1:a.x, y1:a.y, x2:b.x, y2:b.y});
    ln.dataset.a = l.from; ln.dataset.b = l.to;
    gEdges.appendChild(ln);
  });
  svg.appendChild(gEdges);

  // узлы
  boxes.forEach(b => b.pos.forEach(p => {
    const n = p.node, t = TYPE[n.type] || TYPE.other;
    const g = el('g', {});
    const c = el('circle', {class:'node', cx:p.x, cy:p.y, r:9,
      fill: STC[n.status] || STC.unknown,
      stroke: n.critical ? 'var(--accent)' : 'var(--surface)', 'stroke-width': n.critical ? 2.5 : 2});
    c.dataset.key = nodeKey(n);
    g.appendChild(c);
    const ic = el('use', {href:'#i-'+t.i, x:p.x-6, y:p.y+13, width:12, height:12, class:'ntype'});
    g.appendChild(ic);
    const lt = el('text', {class:'nlabel', x:p.x, y:p.y+36, 'text-anchor':'middle'});
    lt.textContent = trunc(n.hostname || n.ip, 13);
    g.appendChild(lt);
    c.addEventListener('mouseenter', ()=>{ c.setAttribute('r', 12); highlightLinks(n.id); showTip(n); });
    c.addEventListener('mousemove', e=>moveTip(e));
    c.addEventListener('mouseleave', ()=>{ c.setAttribute('r', 9); highlightLinks(null); tip.style.display='none'; });
    c.addEventListener('click', ()=>{ if (n.id) location.href = '/devices/' + n.id; });
    svg.appendChild(g);
  }));

  applySearch();
}

// highlightLinks выделяет рёбра, которыми узел связан с другими.
function highlightLinks(id){
  document.querySelectorAll('#netmap .edge').forEach(e=>{
    e.classList.toggle('hot', id != null && (e.dataset.a == id || e.dataset.b == id));
  });
}

// linkInfo — строки подсказки о связях узла: вверх (куда подключён) и вниз.
function linkInfo(n){
  const byId = new Map(allNodes.map(x=>[x.id, x]));
  const name = id => { const x = byId.get(id); return x ? esc(x.hostname || x.ip || '—') : '—'; };
  const out = [];
  allLinks.filter(l=>l.to===n.id).forEach(l=>{
    out.push('подключено к ' + name(l.from) + (l.port ? ', порт ' + esc(l.port) : ''));
  });
  const kids = allLinks.filter(l=>l.from===n.id);
  if (kids.length) out.push('к нему подключено: ' + kids.length);
  return out.length ? '<br>' + out.join('<br>') : '';
}

function showTip(n){
  const tip = document.getElementById('map-tip');
  const t = TYPE[n.type] || TYPE.other;
  tip.innerHTML =
    `<b>${tico(n.type)} ${esc(n.hostname||'—')}</b>${n.critical?' ★':''}<br>${esc(n.ip||'IP —')}` +
    (n.mac?`<br>MAC: ${esc(n.mac)}`:'') + (n.vendor?`<br>${esc(n.vendor)}`:'') +
    `<br>тип: ${t.l}` + linkInfo(n) +
    `<br>статус: <span class="st" style="background:${STC[n.status]}22;color:${STC[n.status]}">${STL[n.status]}</span>` +
    (n.last_seen?`<br>онлайн: ${esc(n.last_seen)}`:'');
  tip.style.display='block';
}
function moveTip(e){
  const tip = document.getElementById('map-tip');
  const wrap = document.getElementById('netmap').closest('.map-wrap').getBoundingClientRect();
  tip.style.left = Math.min(e.clientX - wrap.left + 14, wrap.width - 295) + 'px';
  tip.style.top  = (e.clientY - wrap.top + 14) + 'px';
}

function applySearch(){
  const q = (document.getElementById('map-search').value||'').trim().toLowerCase();
  document.querySelectorAll('#netmap .node').forEach(c=>{
    const match = !q || (c.dataset.key||'').includes(q);
    // гасим весь узел целиком: кружок, значок типа и подпись
    c.parentNode.style.opacity = match ? 1 : 0.12;
  });
}

function buildChips(){
  const box = document.getElementById('map-filters');
  box.innerHTML = '';
  // статусы
  ['online','stale','offline','unknown'].forEach(s=>{
    const cnt = allNodes.filter(n=>n.status===s).length; if(!cnt) return;
    const b = document.createElement('button'); b.className='on';
    b.innerHTML = `<span class="cdot" style="background:${STC[s]}"></span>${STL[s]} ${cnt}`;
    b.onclick = ()=>{ b.classList.toggle('on'); b.classList.contains('on')?statusOn.add(s):statusOn.delete(s); render(); };
    box.appendChild(b);
  });
  // типы (только присутствующие)
  const present = [...new Set(allNodes.map(n=>n.type))];
  ['pc','server','phone','camera','ap','printer','network','other'].filter(t=>present.includes(t)).forEach(t=>{
    typeOn.add(t);
    const cnt = allNodes.filter(n=>n.type===t).length;
    const b = document.createElement('button'); b.className='on';
    b.innerHTML = `${tico(t)} ${TYPE[t].l} ${cnt}`;
    b.onclick = ()=>{ b.classList.toggle('on'); b.classList.contains('on')?typeOn.add(t):typeOn.delete(t); render(); };
    box.appendChild(b);
  });
}

function buildPanel(){
  const list = document.getElementById('pp-list');
  const probs = allNodes.filter(n => n.status==='offline' || n.status==='stale' || (n.critical && n.status!=='online'))
    .sort((a,b)=>{
      const w = n => (n.critical?0:2) + (n.status==='offline'?0:1);
      return w(a)-w(b);
    });
  document.getElementById('pp-count').textContent = probs.length;
  if (!probs.length){ list.innerHTML = '<div class="pp-empty">Проблемных устройств нет</div>'; return; }
  list.innerHTML = '';
  probs.forEach(n=>{
    const t = TYPE[n.type] || TYPE.other;
    const d = document.createElement('div'); d.className='pp-item';
    d.innerHTML = `<div class="nm"><span class="cdot" style="display:inline-block;width:8px;height:8px;border-radius:50%;background:${STC[n.status]}"></span>${tico(n.type)} ${esc(n.hostname||n.ip||'—')}${n.critical?' ★':''}</div>`+
      `<div class="meta">${esc(n.ip||'')} · ${STL[n.status]}${n.last_seen?' · '+esc(n.last_seen):''}</div>`;
    d.onclick = ()=>{ document.getElementById('map-search').value = n.hostname || n.ip || ''; applySearch(); };
    list.appendChild(d);
  });
}

async function load(){
  let data; try { data = await (await fetch('/api/network-map')).json(); } catch(e){ return; }
  allNodes = data.nodes || []; allLinks = data.links || [];
  buildChips(); buildPanel(); render();
}
document.getElementById('map-search').addEventListener('input', applySearch);
document.getElementById('map-group').addEventListener('change', e=>{ groupBy = e.target.value; render(); });
load();
