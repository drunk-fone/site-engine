// Login- und Einrichtungsseite. Kein Inline-JS (Admin-CSP erlaubt nur 'self').
(function () {
  function $(id) { return document.getElementById(id); }
  function post(url, body) {
    return fetch(url, {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
    }).then(function (r) { return r.json().catch(function () { return { ok: false, error: 'Serverfehler (' + r.status + ')' }; }); });
  }
  function showError(msg) { var e = $('error'); e.textContent = msg; e.hidden = !msg; }

  var page = document.body.getAttribute('data-page');

  if (page === 'login') {
    fetch('/admin/login-info', { credentials: 'same-origin' }).then(function (r) { return r.json(); }).then(function (info) {
      if (info.setup) { $('setup-needed').hidden = false; $('login-form').hidden = true; return; }
      $('code-row').hidden = !info.totp;
      $('passwort').focus();
    });
    $('login-form').addEventListener('submit', function (ev) {
      ev.preventDefault();
      showError('');
      $('submit').disabled = true;
      post('/admin/login', { passwort: $('passwort').value, code: $('code').value }).then(function (res) {
        $('submit').disabled = false;
        if (res.ok) { location.replace('/admin'); return; }
        if (res.setup) { $('setup-needed').hidden = false; $('login-form').hidden = true; return; }
        $('passwort').value = ''; $('code').value = '';
        showError(res.error || 'Anmeldung fehlgeschlagen');
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
      var pw = $('pw1').value;
      if (pw !== $('pw2').value) return showError('Die Passwörter stimmen nicht überein.');
      if (pw.length < 12) return showError('Das Passwort muss mindestens 12 Zeichen lang sein.');
      $('submit').disabled = true;
      post('/admin/setup', { token: token || $('token').value.trim(), passwort: pw }).then(function (res) {
        $('submit').disabled = false;
        if (res.ok) { location.replace('/admin'); return; }
        showError(res.error || 'Fehler');
      });
    });
  }
})();
