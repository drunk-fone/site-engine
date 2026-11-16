// Login (Google / Notfall-Code) und Notfall-Link. Kein Inline-JS (CSP).
(function () {
  function $(id) { return document.getElementById(id); }
  function post(url, body) {
    return fetch(url, {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
    }).then(function (r) { return r.json().catch(function () { return { ok: false, error: 'Serverfehler (' + r.status + ')' }; }); });
  }
  function showError(msg) { var e = $('error'); e.textContent = msg; e.hidden = !msg; }
  function done(res) {
    if (res.ok) { location.replace('/admin'); return; }
    showError(res.error || 'Anmeldung fehlgeschlagen');
  }

  var page = document.body.getAttribute('data-page');

  if (page === 'login') {
    var info = null, gisReady = false;
    function initGoogle() {
      if (!info || !gisReady || !info.client_id) return;
      google.accounts.id.initialize({
        client_id: info.client_id,
        nonce: info.nonce,
        ux_mode: 'popup',
        auto_select: false,
        context: 'signin',
        callback: function (resp) { showError(''); post('/admin/google', { credential: resp.credential }).then(done); }
      });
      var dark = document.documentElement.getAttribute('data-theme') === 'dark';
      google.accounts.id.renderButton($('google-btn'), {
        type: 'standard', theme: dark ? 'filled_black' : 'outline', size: 'large',
        text: 'signin_with', shape: 'pill', locale: 'de'
      });
    }
    // Von Googles Skript aufgerufen, sobald es geladen ist.
    window.onGoogleLibraryLoad = function () { gisReady = true; initGoogle(); };
    fetch('/admin/login-info', { credentials: 'same-origin' }).then(function (r) { return r.json(); }).then(function (d) {
      info = d;
      var ready = d.client_id && d.erlaubt;
      $('not-configured').hidden = !!ready;
      $('google-area').hidden = !ready;
      if (!ready && d.notfall) $('notfall').open = true;
      if (window.google && google.accounts && google.accounts.id) gisReady = true;
      initGoogle();
    });
    $('notfall-form').addEventListener('submit', function (ev) {
      ev.preventDefault();
      showError('');
      $('notfall-submit').disabled = true;
      post('/admin/notfall', { code: $('code').value }).then(function (res) {
        $('notfall-submit').disabled = false;
        $('code').value = '';
        done(res);
      });
    });
  }

  if (page === 'setup') {
    // Das Token steht im #-Fragment: es wird nie an Server, Proxy oder Logs übertragen.
    var token = location.hash.length > 1 ? decodeURIComponent(location.hash.slice(1)) : '';
    if (token) { try { history.replaceState(null, '', location.pathname); } catch (e) {} }
    $('token-row').hidden = !!token;
    $('setup-form').addEventListener('submit', function (ev) {
      ev.preventDefault();
      showError('');
      $('submit').disabled = true;
      post('/admin/setup', { token: token || $('token').value.trim() }).then(function (res) {
        $('submit').disabled = false;
        done(res);
      });
    });
  }
})();
