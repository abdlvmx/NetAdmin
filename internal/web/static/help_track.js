(function () {
  var m = document.cookie.match('(^|;)\\s*csrf\\s*=\\s*([^;]+)');
  var tok = m ? m.pop() : '';
  document.querySelectorAll('input[name=csrf_token]').forEach(function (i) { i.value = tok; });
})();
