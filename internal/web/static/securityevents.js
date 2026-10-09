(function () {
  'use strict';
  function openRuleTarget() {
    var id;
    try { id = decodeURIComponent(window.location.hash.slice(1)); } catch (_) { return; }
    var page = document.querySelector('[data-events-tab]');
    if (!page) return;
    var tab = '';
    if (id === 'events-rules' || id === 'events-exceptions' || id.indexOf('rule-') === 0) tab = 'rules';
    else if (id === 'events-backups' || id === 'events-backup-list' || id === 'events-restore') tab = 'backups';
    else if (id === 'events-delivery' || id === 'events-devices' || id.indexOf('events-device-') === 0) tab = 'collection';
    else if (id === 'events-recent') tab = 'logs';
    else if (id === 'events-findings') tab = 'findings';
    // Old fragment links cannot tell the server which section to render. Replace
    // that initial entry with a regular URL, keeping filters and Back behavior.
    if (tab && tab !== page.dataset.eventsTab) {
      var next = new URL(window.location.href);
      next.searchParams.set('tab', tab);
      window.location.replace(next.href);
      return;
    }
    var target = document.getElementById(id);
    if (!target) return;
    if (id === 'events-rules') {
      var settings = target.querySelector('details');
      if (settings) settings.open = true;
    }
    var parent = target.parentElement;
    while (parent) {
      if (parent.tagName === 'DETAILS') parent.open = true;
      parent = parent.parentElement;
    }
  }
  openRuleTarget();
  window.addEventListener('hashchange', openRuleTarget);
})();
