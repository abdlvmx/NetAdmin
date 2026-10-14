(function () {
  'use strict';
  const root = document.getElementById('job-center');
  if (!root) return;
  const id = root.dataset.jobId;
  let busy = false;
  function value(name, text) { const el = document.getElementById(name); if (el) el.textContent = text; }
  value('job-updated', 'Автоматическое обновление каждые 5 секунд');
  function updateRetrySelection() {
    const choices = document.getElementById('job-retry-choices'); if (!choices) return;
    const count = choices.querySelectorAll('[name=task]:checked').length;
    const button = choices.closest('form').querySelector('button[type=submit]');
    if (button) button.disabled = count === 0;
  }
  const retryChoices = document.getElementById('job-retry-choices');
  if (retryChoices) retryChoices.addEventListener('change', () => {
    retryChoices.closest('form').querySelector('[name=confirm]').checked = false;
    updateRetrySelection();
  });
  updateRetrySelection();
  async function refresh() {
    if (busy || document.hidden) return;
    busy = true;
    try {
      const response = await fetch('/api/jobs/' + encodeURIComponent(id), {credentials: 'same-origin', cache: 'no-store'});
      if (response.redirected) { location.assign('/login'); return; }
      if (response.status === 403 || response.status === 404) { location.assign('/jobs'); return; }
      if (!response.ok) throw new Error('unavailable');
      const data = await response.json(), job = data.job;
      if (data.tasks.some(task => !root.querySelector('[data-job-task="' + task.ID + '"]'))) {
        location.replace('/jobs/' + encodeURIComponent(id)); return;
      }
      value('job-state', job.State); document.getElementById('job-state').className = 'badge ' + job.Badge;
      ['Total','Done','Failed','Pending','Cancelled','Percent'].forEach(key => value('job-' + key.toLowerCase(), job[key]));
      value('job-active', job.Sent + ' / ' + job.Running);
      value('job-extra', 'Ожидают подключения ПК: ' + job.Waiting + ' · Запрошена отмена: ' + job.CancelRequested + (job.Deleted ? ' · Удалено ПК: ' + job.Deleted : ''));
      document.getElementById('job-progress').value = job.Percent;
      const cancel = document.getElementById('job-cancel-panel'), retry = document.getElementById('job-retry-panel'), choices = document.getElementById('job-retry-choices');
      if (cancel) cancel.hidden = !job.CanCancel;
      if (retry) retry.hidden = !job.CanRetry;
      // Do not move focus or clear a selection while the user reviews a form.
      const wanted = data.tasks.filter(task => task.CanRetry).map(task => String(task.ID));
      const existing = choices ? [...choices.querySelectorAll('[name=task]')].map(input => input.value) : [];
      if (choices && wanted.join(',') !== existing.join(',')) {
        choices.querySelectorAll('[name=task]').forEach(input => { if (!wanted.includes(input.value)) input.closest('label').remove(); });
        data.tasks.filter(task => task.CanRetry).forEach(task => {
          if (choices.querySelector('[name=task][value="' + task.ID + '"]')) return;
          const label = document.createElement('label'), input = document.createElement('input'), text = document.createElement('span');
          label.className = 'job-check'; input.type = 'checkbox'; input.name = 'task'; input.value = String(task.ID);
          input.checked = false;
          text.textContent = task.Hostname + ' · ' + task.State; label.append(input, text); choices.append(label);
        });
        choices.closest('form').querySelector('[name=confirm]').checked = false;
        updateRetrySelection();
      }
      const visible = new Set(data.tasks.map(task => String(task.ID)));
      root.querySelectorAll('[data-job-task]').forEach(row => { if (!visible.has(row.dataset.jobTask)) row.remove(); });
      data.tasks.forEach(task => {
        const row = root.querySelector('[data-job-task="' + task.ID + '"]'); if (!row) return;
        const state = row.querySelector('[data-task-state]'); state.textContent = task.State; state.className = 'badge ' + task.Badge;
        row.querySelector('[data-task-code]').textContent = ['done','failed','cancelled'].includes(task.Status) ? task.ExitCode : '—';
        row.querySelector('[data-task-preview]').textContent = task.Preview;
        const retryCell = row.querySelector('[data-task-retry]');
        if (task.RetryJobID && retryCell.dataset.retryId !== String(task.RetryJobID)) {
          const link = document.createElement('a'); link.href = '/jobs/' + task.RetryJobID; link.textContent = 'Повтор #' + task.RetryJobID;
          retryCell.replaceChildren(link); retryCell.dataset.retryId = String(task.RetryJobID);
        }
      });
      value('job-updated', 'Обновлено: ' + new Date().toLocaleTimeString('ru-RU'));
    } catch (_) { value('job-updated', 'Не удалось обновить данные. Можно обновить страницу вручную.'); }
    finally { busy = false; }
  }
  setInterval(refresh, 5000);
  document.addEventListener('visibilitychange', () => { if (!document.hidden) refresh(); });
})();
