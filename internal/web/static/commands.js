const sel = document.getElementById('cmd-select');
if(sel){
  sel.addEventListener('change', function(){
    const o = sel.options[sel.selectedIndex];
    document.getElementById('cmd-desc').textContent = o ? (o.dataset.desc||'') : '';
  });
}
function confirmRun(){
  const o = sel.options[sel.selectedIndex];
  if(o && o.dataset.danger==='1'){
    return confirm('Эта команда прервёт работу пользователя. Выполнить?');
  }
  return true;
}

// Регистрация действий разметки (диспетчер — в layout.js).
// Отправка формы отменяется, если подтверждение не получено.
window.actions = window.actions || {};
window.actions.confirmRun = function (form, e) { if (!confirmRun()) e.preventDefault(); };
