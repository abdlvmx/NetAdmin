// Тема применяется до первой отрисовки, иначе светлая страница мигает перед
// переключением на тёмную. Поэтому файл подключается в <head> без defer.
(function () {
  try {
    var t = localStorage.getItem('theme');
    if (t === 'dark' || (!t && window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
      document.documentElement.setAttribute('data-theme', 'dark');
    }
  } catch (e) {}
})();
