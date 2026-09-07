// Скрипт целиком в функции: объявления внутри блоков всплывают в общую
// область, а её делят layout.js, search.js и скрипт страницы. Наружу
// отдаётся только то, что явно положено в window.
(function () {
  const COLORS = { cpu:'#2f6bed', ram:'#18a058', disk:'#f08c00' };
  let state = { hours:24, metric:'cpu' }, lastPoints = [];

  document.getElementById('range').addEventListener('click', e=>{
    const b = e.target.closest('button[data-h]'); if(!b) return;
    state.hours = +b.dataset.h;
    document.querySelectorAll('#range button').forEach(x=>x.classList.toggle('on', x===b));
    loadCharts();
  });
  document.getElementById('tabs').addEventListener('click', e=>{
    const b = e.target.closest('button[data-m]'); if(!b) return;
    state.metric = b.dataset.m;
    document.querySelectorAll('#tabs button').forEach(x=>x.classList.toggle('on', x===b));
    drawTrends(document.getElementById('trends'), lastPoints, state.metric);
  });

  function fmtTs(ts){ return (ts||'').slice(5,16); }

  async function loadCharts(){
    try{
      const m = await (await fetch(`/api/metrics/fleet?hours=${state.hours}`)).json();
      lastPoints = m.points||[];
      drawTrends(document.getElementById('trends'), lastPoints, state.metric);
    }catch(e){}
  }

  function drawTrends(canvas, points, primary){
    const empty = document.getElementById('trends-empty');
    if(!points.length){ canvas.style.display='none'; empty.style.display='block'; return; }
    canvas.style.display='block'; empty.style.display='none';
    const dpr = window.devicePixelRatio||1, w = canvas.clientWidth, h = canvas.clientHeight;
    canvas.width=w*dpr; canvas.height=h*dpr;
    const ctx = canvas.getContext('2d'); ctx.setTransform(dpr,0,0,dpr,0,0); ctx.clearRect(0,0,w,h);
    const padL=34,padR=10,padT=10,padB=22, plotW=w-padL-padR, plotH=h-padT-padB;
    const yOf=v=>padT+plotH*(1-v/100), xOf=i=>padL+(points.length===1?plotW/2:plotW*i/(points.length-1));
    const css=getComputedStyle(document.documentElement);
    ctx.strokeStyle=css.getPropertyValue('--border').trim(); ctx.fillStyle=css.getPropertyValue('--muted').trim();
    ctx.font='11px sans-serif'; ctx.lineWidth=1; ctx.textAlign='right'; ctx.textBaseline='middle';
    for(let v=0;v<=100;v+=25){const y=yOf(v);ctx.beginPath();ctx.moveTo(padL,y);ctx.lineTo(w-padR,y);ctx.stroke();ctx.fillText(v+'%',padL-6,y);}
    ctx.textBaseline='top'; ctx.textAlign='left'; ctx.fillText(fmtTs(points[0].ts),padL,h-padB+5);
    if(points.length>1){ctx.textAlign='right';ctx.fillText(fmtTs(points[points.length-1].ts),w-padR,h-padB+5);}
    const order = ['cpu','ram','disk'].sort((a,b)=> a===primary?1:(b===primary?-1:0)); // primary last (on top)
    for(const k of order){
      const isP = k===primary;
      if(isP){ // заливка под основной линией
        ctx.beginPath(); let st=false;
        points.forEach((p,i)=>{const v=p[k]; if(v==null){return;} const x=xOf(i),y=yOf(v); st?ctx.lineTo(x,y):(ctx.moveTo(x,y),st=true);});
        ctx.lineTo(xOf(points.length-1), yOf(0)); ctx.lineTo(xOf(0), yOf(0)); ctx.closePath();
        ctx.fillStyle = COLORS[k]+'1f'; ctx.fill();
      }
      ctx.strokeStyle=COLORS[k]; ctx.globalAlpha = isP?1:0.45; ctx.lineWidth = isP?2.2:1.2; ctx.beginPath();
      let st=false;
      points.forEach((p,i)=>{const v=p[k]; if(v==null){st=false;return;} const x=xOf(i),y=yOf(v); st?ctx.lineTo(x,y):(ctx.moveTo(x,y),st=true);});
      ctx.stroke(); ctx.globalAlpha=1;
    }
  }
  loadCharts();

  // ── авто-обновление статусов парка (без перезагрузки) ──
  function dPct(part, total){ return total ? Math.round(part*100/total) : 0; }
  async function refreshDashboard(){
    if(document.hidden) return;
    let d;
    try{ d = await (await fetch('/api/devices/status')).json(); }catch(e){ return; }
    const s = d.summary || {}; const set = (id,v)=>{ const el=document.getElementById(id); if(el) el.textContent=v; };
    const total=s.total||0, online=s.online||0, offline=s.offline||0, unknown=s.unknown||0;
    set('d-online', online); set('d-total', total); set('d-offline', offline);
    set('d-alerts', s.alerts||0);
    const onPct=dPct(online,total);
    set('d-onpct', onPct+'%'); set('d-donut-pct', onPct+'%');
    set('d-lg-on', online);   set('d-lg-on-pct', onPct+'%');
    set('d-lg-off', offline); set('d-lg-off-pct', dPct(offline,total)+'%');
    set('d-lg-unk', unknown); set('d-lg-unk-pct', dPct(unknown,total)+'%');
    const donut = document.getElementById('d-donut');
    if(donut && total){
      const on=online/total*100, off=on+offline/total*100;
      donut.style.background = `conic-gradient(#18a058 0 ${on.toFixed(1)}%, #e5484d ${on.toFixed(1)}% ${off.toFixed(1)}%, #cdd6e4 ${off.toFixed(1)}% 100%)`;
    }
  }
  setInterval(refreshDashboard, 20000);
})();
