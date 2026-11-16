// Admin-Cockpit. Wird nur mit gültiger Sitzung ausgeliefert; alle Schreibzugriffe
// tragen das CSRF-Token aus <meta name="csrf-token">.
(function () {
  'use strict';
  var CSRF = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
  var STATE = {};
  var $ = function (id) { return document.getElementById(id); };

  function toast(msg, type) {
    var t = $('toast');
    t.textContent = msg;
    t.className = 'toast ' + (type || 'ok');
    t.hidden = false;
    clearTimeout(toast._t);
    toast._t = setTimeout(function () { t.hidden = true; }, 3800);
  }

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  function handle(r) {
    if (r.status === 401) { location.replace('/admin/login'); return new Promise(function () {}); }
    return r.json().catch(function () { return { ok: false, error: 'Serverfehler (' + r.status + ')' }; });
  }
  function postJSON(url, body) {
    return fetch(url, {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': CSRF },
      body: JSON.stringify(body || {})
    }).then(handle);
  }
  function postRaw(url, blob) {
    return fetch(url, {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/octet-stream', 'X-CSRF-Token': CSRF }, body: blob
    }).then(handle);
  }
  function done(msg, after) {
    return function (res) {
      if (res.ok) { toast(msg); if (after) after(res); } else toast(res.error || 'Fehler', 'err');
      return res;
    };
  }

  // ------------------------------------------------------------- Tabs & Features
  function showTab(name) {
    document.querySelectorAll('.tab').forEach(function (b) { b.classList.toggle('active', b.dataset.tab === name); });
    document.querySelectorAll('.tab-pane').forEach(function (p) { p.hidden = p.id !== 'tab-' + name; });
    try { sessionStorage.setItem('admin-tab', name); } catch (e) {}
  }
  document.querySelectorAll('.tab').forEach(function (btn) {
    btn.addEventListener('click', function () { showTab(btn.dataset.tab); });
  });

  function applyFeatures(f) {
    f = f || {};
    document.querySelectorAll('[data-feature]').forEach(function (el) {
      el.hidden = !el.dataset.feature.split(' ').some(function (k) { return f[k]; });
    });
    ['shop', 'kontakt', 'seo', 'wartung'].forEach(function (k) { $('f-' + k).checked = !!f[k]; });
    syncSubs();
    $('maint-banner').hidden = !f.wartung;
    var active = document.querySelector('.tab.active');
    if (!active || active.hidden) {
      var saved = null;
      try { saved = sessionStorage.getItem('admin-tab'); } catch (e) {}
      var btn = saved && document.querySelector('.tab[data-tab="' + saved + '"]');
      showTab(btn && !btn.hidden ? saved : (f.shop ? 'katalog' : 'bilder'));
    }
  }
  function syncSubs() {
    ['seo', 'wartung'].forEach(function (k) {
      document.querySelectorAll('[data-sub="' + k + '"]').forEach(function (el) { el.hidden = !$('f-' + k).checked; });
    });
  }
  ['f-seo', 'f-wartung'].forEach(function (id) { $(id).addEventListener('change', syncSubs); });

  $('logout').addEventListener('click', function () {
    postJSON('/admin/logout', {}).then(function () { location.replace('/admin/login'); });
  });

  // ------------------------------------------------------------------- Katalog
  function renderCatalog() {
    var cat = STATE.catalog || {};
    $('prod-rows').innerHTML = (cat.produkte || []).map(function (p, idx) {
      var price = p.preis != null ? p.preis : (p.price || 0);
      return '<tr data-idx="' + idx + '">' +
        '<td><input type="text" data-f="id" value="' + esc(p.id) + '"></td>' +
        '<td><input type="text" data-f="name" value="' + esc(p.name) + '"></td>' +
        '<td><input type="text" data-f="groesse" value="' + esc(p.groesse || '') + '"></td>' +
        '<td><input type="number" step="0.5" data-f="preis" value="' + esc(price) + '"></td>' +
        '<td><input type="number" min="0" max="10" data-f="motive" value="' + esc(p.motive || 0) + '"></td>' +
        '<td><input type="checkbox" data-f="set"' + (p.set ? ' checked' : '') + '></td>' +
        '<td><button type="button" class="btn danger" data-del-prod="' + idx + '">✕</button></td></tr>';
    }).join('');
    var v = cat.versand || { preis: 9, gratis_ab_betrag: 60 };
    $('v-preis').value = v.preis != null ? v.preis : 9;
    $('v-gratis').value = v.gratis_ab_betrag != null ? v.gratis_ab_betrag : 60;
    $('motive-list').value = (cat.motive || []).join('\n');
  }
  function collectCatalog() {
    var produkte = [];
    document.querySelectorAll('#prod-rows tr').forEach(function (r) {
      var id = r.querySelector('[data-f="id"]').value.trim();
      var name = r.querySelector('[data-f="name"]').value.trim();
      if (!id || !name) return;
      var item = {
        id: id, name: name,
        groesse: r.querySelector('[data-f="groesse"]').value.trim(),
        preis: parseFloat(r.querySelector('[data-f="preis"]').value) || 0,
        motive: parseInt(r.querySelector('[data-f="motive"]').value, 10) || 0
      };
      if (r.querySelector('[data-f="set"]').checked) item.set = true;
      produkte.push(item);
    });
    return {
      versand: { preis: parseFloat($('v-preis').value) || 0, gratis_ab_betrag: parseFloat($('v-gratis').value) || 0 },
      motive: $('motive-list').value.split('\n').map(function (s) { return s.trim(); }).filter(Boolean),
      produkte: produkte
    };
  }
  $('add-prod').addEventListener('click', function () {
    STATE.catalog = collectCatalog();
    STATE.catalog.produkte.push({ id: 'neues-produkt', name: 'Neues Produkt', groesse: '', preis: 15, motive: 1 });
    renderCatalog();
  });
  $('prod-rows').addEventListener('click', function (e) {
    var b = e.target.closest('[data-del-prod]');
    if (!b) return;
    STATE.catalog = collectCatalog();
    STATE.catalog.produkte.splice(parseInt(b.dataset.delProd, 10), 1);
    renderCatalog();
  });
  $('save-catalog').addEventListener('click', function () {
    postJSON('/api/admin/catalog', collectCatalog()).then(done('Katalog & Preise gespeichert!', loadState));
  });

  // -------------------------------------------------------------------- Bilder
  function kb(n) { return n > 1048576 ? (n / 1048576).toFixed(1) + ' MB' : Math.ceil(n / 1024) + ' KB'; }
  function ratioWarn(img, fmt) {
    if (!fmt || !img.w || !img.h) return '';
    var p = fmt.split(':'), want = p[0] / p[1], have = img.w / img.h;
    return Math.abs(have - want) / want > 0.05 ? ' <span class="badge warn" title="Empfohlen: ' + esc(fmt) + '">Format ≠ ' + esc(fmt) + '</span>' : '';
  }

  function renderBilder() {
    var B = STATE.bilder || { bereiche: [], seiten: [] };
    var all = [];
    B.bereiche.forEach(function (s) { s.bilder.forEach(function (i) { all.push(i.path); }); });
    $('all-imgs').innerHTML = all.map(function (p) { return '<option value="' + esc(p) + '">'; }).join('');
    $('bilder-empty').hidden = all.length > 0 || B.bereiche.length > 0;
    $('new-folder-card').hidden = !!B.nur_bereiche;

    $('bilder-sections').innerHTML = B.bereiche.map(function (s, si) {
      var count = s.bilder.length;
      var full = s.max && count >= s.max;
      var meta = [
        '<code>img/' + esc(s.ordner ? s.ordner + '/' : '') + '</code>',
        count + (s.max ? ' / ' + s.max : '') + ' Bilder',
        s.format ? 'Format ' + esc(s.format) : ''
      ].filter(Boolean).join(' · ');
      var cards = s.bilder.map(function (img, ii) {
        var used = (img.verwendet || []).map(function (u) { return '<span class="badge ok">' + esc(u) + '</span>'; }).join(' ');
        return '<div class="img-card" data-path="' + esc(img.path) + '">' +
          '<img src="/' + esc(img.path) + '?v=' + img.bytes + '" loading="lazy" alt="">' +
          '<code>' + esc(img.path.split('/').pop()) + '</code>' +
          '<div>' + (img.w ? img.w + '×' + img.h + ' · ' : '') + kb(img.bytes) + ratioWarn(img, s.format) + '</div>' +
          (used ? '<div>' + used + '</div>' : '') +
          (s.beschriftung ? '<input type="text" data-k="text" placeholder="Beschriftung" value="' + esc(img.text) + '">' : '') +
          '<input type="text" data-k="alt" placeholder="Alternativtext (Barrierefreiheit)" value="' + esc(img.alt) + '">' +
          '<div class="tools">' +
            '<span><button type="button" class="btn small" data-move="-1" data-s="' + si + '" data-i="' + ii + '"' + (ii === 0 ? ' disabled' : '') + ' title="Nach vorne">↑</button> ' +
            '<button type="button" class="btn small" data-move="1" data-s="' + si + '" data-i="' + ii + '"' + (ii === count - 1 ? ' disabled' : '') + ' title="Nach hinten">↓</button></span>' +
            '<button type="button" class="btn small danger" data-del-img="' + esc(img.path) + '">Löschen</button>' +
          '</div></div>';
      }).join('');
      return '<div class="card" data-section="' + si + '">' +
        '<div class="row" style="justify-content:space-between"><h2 style="margin:0">' + esc(s.titel) + '</h2><span class="sub">' + meta + '</span></div>' +
        (s.beschreibung ? '<p class="sub" style="margin-top:6px">' + esc(s.beschreibung) + '</p>' : '') +
        '<div class="dropzone" data-drop="' + si + '" style="margin-top:12px">' +
          (full ? '<b>Maximum erreicht.</b> Lösche ein Bild oder lade eines mit gleichem Namen hoch, um es zu ersetzen.<br>' : 'Bilder hierher ziehen oder ') +
          '<input type="file" multiple accept=".png,.jpg,.jpeg,.webp,.gif,.svg" data-upload="' + si + '"></div>' +
        (count ? '<div class="img-grid">' + cards + '</div>' : '<p class="sub" style="margin-top:12px">Noch keine Bilder in diesem Bereich.</p>') +
        '<div class="row" style="margin-top:14px">' +
          (count ? '<button class="btn primary" type="button" data-save-section="' + si + '">Beschriftungen & Reihenfolge speichern</button>' : '') +
          (!count && !s.manifest && s.ordner ? '<button class="btn danger" type="button" data-del-folder="' + esc(s.ordner) + '">Leeren Bereich entfernen</button>' : '') +
        '</div></div>';
    }).join('');

    var pages = B.seiten || [];
    $('page-imgs-card').hidden = !pages.length;
    $('page-imgs').innerHTML = pages.map(function (p) {
      return '<h3>' + esc(p.titel) + ' <a class="badge" href="' + esc(p.seite) + '" target="_blank" rel="noopener">öffnen ↗</a></h3><div class="thumbs">' +
        p.bilder.map(function (b) {
          var badge = b.status === 'fehlt' ? '<span class="badge err">fehlt</span>' : b.status === 'extern' ? '<span class="badge">extern</span>' : '';
          var pic = b.status === 'ok' ? '<img src="/' + esc(b.path) + '" loading="lazy" alt="">' : '<div class="ph">' + (b.status === 'extern' ? '🌐' : '⚠️') + '</div>';
          return '<div class="thumb">' + pic + '<code>' + esc(b.path || b.ref) + '</code>' + badge + '</div>';
        }).join('') + '</div>';
    }).join('');
  }

  function sectionItems(si) {
    var card = document.querySelector('[data-section="' + si + '"]');
    return Array.prototype.map.call(card.querySelectorAll('.img-card'), function (c) {
      var t = c.querySelector('[data-k="text"]');
      return { path: c.dataset.path, text: t ? t.value : '', alt: c.querySelector('[data-k="alt"]').value };
    });
  }
  function saveSection(si, items) {
    var s = STATE.bilder.bereiche[si];
    return postJSON('/api/admin/bilder-save', { ordner: s.ordner, bilder: items });
  }
  function uploadFiles(si, files) {
    var s = STATE.bilder.bereiche[si];
    files = Array.prototype.slice.call(files || []);
    if (!files.length) return;
    var chain = Promise.resolve(), ok = 0, errors = [];
    files.forEach(function (file) {
      chain = chain.then(function () {
        return postRaw('/api/admin/bilder-upload?ordner=' + encodeURIComponent(s.ordner) + '&name=' + encodeURIComponent(file.name), file)
          .then(function (res) { if (res.ok) ok++; else errors.push(file.name + ': ' + (res.error || 'Fehler')); });
      });
    });
    toast(files.length + ' Bild(er) werden hochgeladen …');
    chain.then(function () {
      if (errors.length) toast(errors.join(' · '), 'err'); else toast(ok + ' Bild(er) hochgeladen');
      loadState();
    });
  }

  var sec = $('bilder-sections');
  sec.addEventListener('change', function (e) {
    var u = e.target.closest('[data-upload]');
    if (u) uploadFiles(+u.dataset.upload, u.files);
  });
  sec.addEventListener('dragover', function (e) {
    var z = e.target.closest('[data-drop]');
    if (z) { e.preventDefault(); z.classList.add('over'); }
  });
  sec.addEventListener('dragleave', function (e) {
    var z = e.target.closest('[data-drop]');
    if (z) z.classList.remove('over');
  });
  sec.addEventListener('drop', function (e) {
    var z = e.target.closest('[data-drop]');
    if (!z) return;
    e.preventDefault();
    z.classList.remove('over');
    uploadFiles(+z.dataset.drop, e.dataTransfer.files);
  });
  sec.addEventListener('click', function (e) {
    var b;
    if ((b = e.target.closest('[data-save-section]'))) {
      saveSection(+b.dataset.saveSection, sectionItems(+b.dataset.saveSection)).then(done('Bereich gespeichert', loadState));
    } else if ((b = e.target.closest('[data-move]'))) {
      var si = +b.dataset.s, i = +b.dataset.i, d = +b.dataset.move;
      var items = sectionItems(si);
      var x = items.splice(i, 1)[0];
      items.splice(i + d, 0, x);
      saveSection(si, items).then(done('Reihenfolge gespeichert', loadState));
    } else if ((b = e.target.closest('[data-del-img]'))) {
      if (!confirm(b.dataset.delImg + ' wirklich löschen?')) return;
      postJSON('/api/admin/bilder-delete', { path: b.dataset.delImg }).then(done('Bild gelöscht', loadState));
    } else if ((b = e.target.closest('[data-del-folder]'))) {
      postJSON('/api/admin/bilder-ordner-delete', { ordner: b.dataset.delFolder }).then(done('Bereich entfernt', loadState));
    }
  });
  $('new-folder-btn').addEventListener('click', function () {
    var name = $('new-folder').value.trim().toLowerCase();
    if (!name) return toast('Bitte einen Namen angeben.', 'err');
    postJSON('/api/admin/bilder-ordner', { ordner: name }).then(done('Bereich angelegt', function () { $('new-folder').value = ''; loadState(); }));
  });

  // ------------------------------------------------------------- Import & HTML
  function importZip(file) {
    if (!file) return;
    toast('ZIP wird importiert …');
    postRaw('/api/admin/upload-zip', file).then(function (res) {
      $('zip-input').value = '';
      if (res.ok) { toast('ZIP importiert (' + res.files + ' Dateien)'); loadState(); }
      else toast(res.error || 'Import fehlgeschlagen', 'err');
    });
  }
  $('zip-input').addEventListener('change', function (e) { importZip(e.target.files[0]); });
  var zd = $('zip-drop');
  zd.addEventListener('dragover', function (e) { e.preventDefault(); zd.classList.add('over'); });
  zd.addEventListener('dragleave', function () { zd.classList.remove('over'); });
  zd.addEventListener('drop', function (e) { e.preventDefault(); zd.classList.remove('over'); importZip(e.dataTransfer.files[0]); });
  $('save-html').addEventListener('click', function () {
    postJSON('/api/admin/html', { html: $('html-editor').value }).then(done('index.html gespeichert!', loadState));
  });

  // --------------------------------------------------------------- Unterseiten
  function renderPages(pages) {
    $('page-rows').innerHTML = (pages || []).map(function (p) {
      return '<tr><td><a href="/' + esc(p.slug) + '" target="_blank" rel="noopener">/' + esc(p.slug) + '</a></td>' +
        '<td>' + Math.ceil(p.size / 1024) + ' KB</td>' +
        '<td style="text-align:right;white-space:nowrap">' +
        '<button class="btn" type="button" data-edit-page="' + esc(p.slug) + '">Bearbeiten</button> ' +
        '<button class="btn danger" type="button" data-del-page="' + esc(p.slug) + '">Löschen</button></td></tr>';
    }).join('');
    $('page-empty').hidden = !!(pages && pages.length);
  }
  $('page-rows').addEventListener('click', function (e) {
    var ed = e.target.closest('[data-edit-page]');
    var del = e.target.closest('[data-del-page]');
    if (ed) {
      fetch('/api/admin/page?slug=' + encodeURIComponent(ed.dataset.editPage), { credentials: 'same-origin' }).then(handle).then(function (d) {
        if (d.error) return toast(d.error, 'err');
        $('page-slug').value = d.slug;
        $('page-html').value = d.html;
        $('page-form-title').textContent = 'Seite bearbeiten: /' + d.slug;
      });
    } else if (del && confirm('Seite /' + del.dataset.delPage + ' wirklich löschen?')) {
      postJSON('/api/admin/page-delete', { slug: del.dataset.delPage }).then(done('Seite gelöscht', loadState));
    }
  });
  $('page-save').addEventListener('click', function () {
    postJSON('/api/admin/page', { slug: $('page-slug').value.trim().toLowerCase(), html: $('page-html').value })
      .then(done('Seite gespeichert', loadState));
  });
  $('page-new').addEventListener('click', function () {
    $('page-slug').value = '';
    $('page-html').value = '';
    $('page-form-title').textContent = 'Neue Seite';
  });

  // ------------------------------------------------------------- Nachrichten
  function renderMessages(list) {
    $('msg-list').innerHTML = (list || []).length ? list.map(function (m) {
      return '<div class="msg"><div class="row" style="justify-content:space-between">' +
        '<div><b>' + esc(m.betreff || '(ohne Betreff)') + '</b><br><small>' + esc(m.datum) + ' · ' + esc(m.name) +
        ' · <a href="mailto:' + encodeURIComponent(m.email).replace(/%40/g, '@') + '">' + esc(m.email) + '</a>' +
        (m.telefon ? ' · ' + esc(m.telefon) : '') + '</small></div>' +
        '<button class="btn small danger" type="button" data-del-msg="' + esc(m.id) + '">Löschen</button></div>' +
        '<pre>' + esc(m.nachricht) + '</pre></div>';
    }).join('') : '<p class="sub">Noch keine Nachrichten.</p>';
  }
  $('msg-list').addEventListener('click', function (e) {
    var b = e.target.closest('[data-del-msg]');
    if (b && confirm('Nachricht löschen?')) postJSON('/api/admin/nachricht-delete', { id: b.dataset.delMsg }).then(done('Nachricht gelöscht', loadState));
  });

  // -------------------------------------------------------------- Bestellungen
  function renderOrders(orders) {
    var tbody = $('order-rows');
    if (!orders || !orders.length) {
      tbody.innerHTML = '<tr><td colspan="7" style="color:var(--muted)">Noch keine Bestellungen vorhanden.</td></tr>';
      return;
    }
    tbody.innerHTML = orders.map(function (o) {
      var k = o.kunde || {};
      var pos = (o.positionen || []).map(function (p) {
        var m = p.motive && p.motive.length ? ' (' + p.motive.join(', ') + ')' : '';
        return p.qty + '× ' + p.name + m;
      }).join(', ');
      return '<tr><td><b>' + esc(o.bestellnummer) + '</b></td><td>' + esc(o.datum) + '</td>' +
        '<td>' + esc(k.name) + '<br><small>' + esc(k.email) + '</small></td>' +
        '<td>' + esc(k.adresse) + '<br>' + esc(k.plz_ort) + '</td><td>' + esc(pos) + '</td>' +
        '<td>' + esc(o.zahlung || 'Rechnung') + '</td>' +
        '<td><b>CHF ' + esc(Number(o.total || 0).toFixed(2)) + '</b></td></tr>';
    }).join('');
  }

  // -------------------------------------------------------------- Einstellungen
  function renderSettings(s) {
    s = s || {};
    $('s-shop-name').value = s.shop_name || '';
    $('s-shop-url').value = s.shop_url || '';
    $('s-shop-address').value = s.shop_address || '';
    $('s-order-prefix').value = s.order_prefix || '';
    $('s-mail-to').value = s.mail_to || '';
    $('s-smtp-host').value = s.smtp_host || 'smtp.gmail.com';
    $('s-smtp-port').value = s.smtp_port || 465;
    $('s-smtp-user').value = s.smtp_user || '';
    $('s-smtp-pass').value = '';
    $('s-pw-status').textContent = s.smtp_pass_set ? '(✓ hinterlegt)' : '(noch nicht hinterlegt)';
    $('s-live-mail').checked = !s.testmodus;
    $('s-seo-titel').value = s.seo_titel || '';
    $('s-seo-beschreibung').value = s.seo_beschreibung || '';
    $('s-seo-bild').value = s.seo_bild || '';
    $('s-wartung-titel').value = s.wartung_titel || '';
    $('s-wartung-text').value = s.wartung_text || '';
  }
  $('save-features').addEventListener('click', function () {
    postJSON('/api/admin/settings', {
      features: { shop: $('f-shop').checked, kontakt: $('f-kontakt').checked, seo: $('f-seo').checked, wartung: $('f-wartung').checked },
      seo_titel: $('s-seo-titel').value.trim(),
      seo_beschreibung: $('s-seo-beschreibung').value.trim(),
      seo_bild: $('s-seo-bild').value.trim(),
      wartung_titel: $('s-wartung-titel').value.trim(),
      wartung_text: $('s-wartung-text').value.trim()
    }).then(done('Funktionen gespeichert', loadState));
  });
  $('save-settings').addEventListener('click', function () {
    postJSON('/api/admin/settings', {
      shop_name: $('s-shop-name').value.trim(),
      shop_url: $('s-shop-url').value.trim(),
      shop_address: $('s-shop-address').value.trim(),
      order_prefix: $('s-order-prefix').value.trim(),
      mail_to: $('s-mail-to').value.trim(),
      smtp_host: $('s-smtp-host').value.trim(),
      smtp_port: parseInt($('s-smtp-port').value, 10) || 465,
      smtp_user: $('s-smtp-user').value.trim(),
      smtp_pass: $('s-smtp-pass').value,
      testmodus: !$('s-live-mail').checked
    }).then(done('Einstellungen gespeichert!', loadState));
  });
  $('send-test-mail').addEventListener('click', function () {
    toast('Test-E-Mail wird gesendet …');
    postJSON('/api/admin/test-email', {}).then(done('Test-E-Mail erfolgreich gesendet!'));
  });

  // Anmeldung: Google-Konten & Notfall-Codes
  function renderAuth(a) {
    a = a || {};
    $('auth-me').textContent = a.ich === 'notfall-code' ? 'Notfall-Code' : a.ich === 'notfall-link' ? 'Notfall-Link' : (a.ich || '?');
    $('auth-cid').value = a.client_id || '';
    $('auth-cid').readOnly = !!a.client_id_env;
    $('cid-label').textContent = a.client_id_env ? 'OAuth-Client-ID (aus der ConfigMap: GOOGLE_CLIENT_ID)' : 'OAuth-Client-ID (öffentlich, kein Geheimnis)';
    $('auth-env-emails').innerHTML = (a.emails_env || []).map(function (e) {
      return '<span class="badge ok" title="aus ADMIN_EMAILS (ConfigMap)">' + esc(e) + ' · ConfigMap</span>';
    }).join(' ');
    $('auth-emails').value = (a.emails || []).filter(function (e) { return (a.emails_env || []).indexOf(e) < 0; }).join('\n');
    var n = a.notfall_codes || 0;
    $('codes-status').textContent = n ? n + ' von 10 Notfall-Codes übrig.' : 'Noch keine Notfall-Codes – empfohlen, damit du auch ohne Google reinkommst.';
    $('codes-status').className = 'notice' + (n ? '' : ' err');
  }
  $('save-access').addEventListener('click', function () {
    var body = { emails: $('auth-emails').value.split(/[\s,;]+/).filter(Boolean) };
    if (!$('auth-cid').readOnly) body.client_id = $('auth-cid').value.trim();
    postJSON('/api/admin/access', body).then(done('Zugang gespeichert', loadState));
  });
  $('new-codes').addEventListener('click', function () {
    if (STATE.auth && STATE.auth.notfall_codes && !confirm('Neue Codes erzeugen? Alle bisherigen Codes werden ungültig.')) return;
    postJSON('/api/admin/notfall-codes', {}).then(done('Neue Notfall-Codes erzeugt', function (res) {
      $('codes-text').value = res.codes.join('\n');
      $('codes-box').hidden = false;
      loadState();
    }));
  });
  $('codes-copy').addEventListener('click', function () {
    var t = $('codes-text');
    t.select();
    (navigator.clipboard ? navigator.clipboard.writeText(t.value) : Promise.reject()).then(function () { toast('Kopiert'); },
      function () { try { document.execCommand('copy'); toast('Kopiert'); } catch (e) { toast('Bitte manuell kopieren', 'err'); } });
  });

  // -------------------------------------------------------------------- Laden
  function loadState() {
    return fetch('/api/admin/state', { credentials: 'same-origin' }).then(handle).then(function (data) {
      STATE = data;
      applyFeatures(data.features);
      renderPages(data.pages);
      renderCatalog();
      renderBilder();
      renderSettings(data.settings);
      renderAuth(data.auth);
      $('html-editor').value = data.html || '';
      renderOrders(data.orders);
      renderMessages(data.nachrichten);
    });
  }
  loadState();
})();
