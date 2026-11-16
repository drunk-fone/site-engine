// Dunkelmodus: folgt dem System, Wahl wird im Browser gemerkt.
(function () {
  var t = null;
  try { t = localStorage.getItem('admin-theme'); } catch (e) {}
  if (!t) t = window.matchMedia && matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  document.documentElement.setAttribute('data-theme', t);

  document.addEventListener('DOMContentLoaded', function () {
    var btn = document.getElementById('theme-toggle');
    if (!btn) return;
    function label() {
      btn.textContent = document.documentElement.getAttribute('data-theme') === 'dark' ? '☀️ Hell' : '🌙 Dunkel';
    }
    btn.addEventListener('click', function () {
      var next = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', next);
      try { localStorage.setItem('admin-theme', next); } catch (e) {}
      label();
    });
    label();
  });
})();
