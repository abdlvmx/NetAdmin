const EMPLOYEES = JSON.parse(document.getElementById("emp-data").dataset.json || "[]");
const EFIELDS = ["full_name","position","email","phone","department_id","notes"];
function openEditEmp(id){
  const e = EMPLOYEES.find(x=>x.id===id); if(!e) return;
  const form = document.getElementById('edit-form');
  form.action = `/employees/${id}/update`;
  EFIELDS.forEach(n=>{ const el=form.elements[n]; if(el) el.value = n==="department_id" ? (e.department_id||"") : (e[n]||""); });
  openModal('modal-edit');
}

// Регистрация действий разметки (диспетчер — в layout.js).
window.actions = window.actions || {};
window.actions.editEmp = function (el) { openEditEmp(Number(el.dataset.id)); };
