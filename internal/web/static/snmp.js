async function pollNow(id, btn){
  const old = btn.textContent; btn.disabled=true; btn.textContent='Опрос…';
  try{
    const d = await (await fetch(`/snmp/${id}/poll`,{method:'POST',headers:{'X-CSRF-Token':window.csrfToken}})).json();
    if(d.ok){ toast(d.status==='up'?'Устройство в сети':'Устройство недоступно', d.status==='up'?'ok':'err'); setTimeout(()=>location.reload(),700); }
    else { toast(d.error||'Ошибка', 'err'); btn.disabled=false; btn.textContent=old; }
  }catch(e){ toast('Ошибка опроса','err'); btn.disabled=false; btn.textContent=old; }
}

// Регистрация действий разметки (диспетчер — в layout.js).
window.actions = window.actions || {};
window.actions.poll = function (el) { pollNow(Number(el.dataset.id), el); };
