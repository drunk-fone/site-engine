# 🚀 Site-Engine

Schlanke, gehärtete Webshop- und Website-Engine für Kubernetes & Docker.

* **Zero Dependencies:** Reines Python 3.14 (Standardbibliothek), kein Framework-Ballast.
* **Minimaler Footprint:** ~30–50 MB RAM, Image ~85 MB (distroless, ohne Shell und Paketmanager).
* **Produktions-Härtung:** Non-Root (UID 10001), Read-Only Root Filesystem, keine Geheimnisse im Image oder Repo.
* **Entkoppelte Konfiguration:** Shop-Daten, Produkte und Branding in `app/config/site.json`, Bild-Bereiche über `bilder.json`.

---

## 📁 Repository-Struktur

```
site-engine/
├── .github/workflows/image.yml   # Tests, Image-Scan (Trivy), Multi-Arch Build -> ghcr.io
├── app/
│   ├── admin/                    # Admin-Oberfläche (nur über /admin, nie als statische Datei)
│   ├── config/
│   │   ├── site.json             # Aktive Konfiguration (Preise, Produkte, Brand)
│   │   ├── site.example.json     # Vorlage für neue Webseiten
│   │   └── bilder.example.json   # Vorlage für Bild-Bereiche im Admin
│   ├── public/                   # Standard-Webseite (Vorlage) inkl. Platzhalter-Bildern
│   └── server.py                 # Server-Engine
├── tests/test_engine.py
├── Dockerfile
└── renovate.json                 # hält Base-Images, Trivy und Actions (per Digest) aktuell
```

---

## 🔐 Admin-Zugang

Es gibt **keinen Benutzernamen** und **kein Passwort im Repo, Image oder in Umgebungsvariablen**.
Das Passwort liegt nur als Hash (PBKDF2-SHA256, 600 000 Runden) in `/data/site/config/auth.json` (0600) auf dem
persistenten Volume – **Neustarts und Updates ändern daran nichts**.

**Neue Webseite:** Beim ersten Start schreibt der Server einen **Einrichtungs-Link** (24 h gültig) ins Log:

```
WARNING ADMIN-EINRICHTUNG: noch kein Passwort gesetzt – Einmal-Link (gültig 24 h):
WARNING   https://shop.example.ch/admin/setup#…
```

In Argo CD: *App öffnen → Pod → Logs*, Link anklicken, Passwort setzen – fertig. Ist der Link abgelaufen, erzeugt
der Button **«Neuen Einrichtungs-Link erzeugen»** auf `/admin/login` einen neuen (wieder im Log).
Damit der Link die richtige Domain hat, `SHOP_URL` in der ConfigMap setzen (sonst steht `<deine-domain>` im Link).

**Passwort vergessen:** Button **«Passwort vergessen?»** auf der Anmeldeseite.
* Ist unter *Einstellungen → Anmeldung* eine **Wiederherstellungs-E-Mail** hinterlegt (oder `ADMIN_EMAIL` in der ConfigMap)
  und SMTP sowie die Webseiten-URL eingerichtet, kommt ein Einmal-Link per E-Mail (30 Min. gültig).
* Zusätzlich steht **immer** ein Link im Server-Log.
* Ist 2FA aktiv, verlangt der **E-Mail-Link** zusätzlich den 2FA-Code – wer nur das Postfach kontrolliert, kommt nicht rein.
  Der **Log-Link** (setzt Zugriff auf Argo CD/Cluster voraus) setzt 2FA zurück, falls das Handy weg ist.
* Notfall ohne UI: `kubectl exec deploy/<name> -n <ns> -- python /app/server.py reset-admin`.

Schutzmassnahmen:
* Der Code steht hinter dem `#` des Links und gelangt nie an Server, Proxy oder Access-Logs; gespeichert wird nur sein Hash.
  Jeder Link funktioniert genau einmal; nach dem Setzen sind alle Links und Sitzungen ungültig.
* Die Domain im E-Mail-Link stammt nur aus der Konfiguration, nie aus dem `Host`-Header (kein Host-Header-Poisoning).
* Link-Anforderungen sind begrenzt (3 pro 15 Min.); bestehende Links werden nie überschrieben, sodass niemand per
  Knopfdruck einen gültigen Link entwerten kann.
* Login-Formular mit Sitzungs-Cookie (`__Host-…`, `HttpOnly`, `Secure`, `SameSite=Strict`), Ablauf nach 2 h Inaktivität bzw. 12 h.
* CSRF-Token und `Origin`-Prüfung für alle Änderungen.
* Sperre nach 5 Fehlversuchen pro IP (15 Min.) und globale Obergrenze von 50 Fehlversuchen / 15 Min. gegen IP-Rotation.
* Optionale **Zwei-Faktor-Anmeldung (TOTP)** mit jeder Authenticator-App, lokal ohne externen Dienst, mit Replay-Schutz.
* Admin-Seiten erlauben kein Inline-JavaScript (CSP `script-src 'self'`).
* Passwortänderung und Änderung der Wiederherstellungs-E-Mail erfordern das aktuelle Passwort.

Lokal ohne HTTPS (z. B. `http://192.168.…`) braucht es `COOKIE_SECURE=0`; für `http://localhost` nicht.

**Upgrade von 1.x:** `ADMIN_USER`, `ADMIN_PASSWORD` und `ADMIN_PASSWORD_HASH` werden ignoriert (Warnung im Log) und können
aus ConfigMaps/Secrets entfernt werden. Ein früher im Admin gesetztes Passwort (in `settings.json` auf dem Volume) wird
automatisch übernommen und beim nächsten Login neu gehasht. Sonst einmal den Link aus dem Log verwenden.

---

## 🖼️ Bilder

*Admin → Bilder* zeigt nur die Bilder der Kunden-Webseite (`/data/site/public/img/`), nie die Platzhalter des Images.

* **Jeder Ordner unter `img/` ist ein Bereich** (z. B. `img/galerie/`, `img/team/`). Bilder direkt in `img/` erscheinen unter «Allgemein».
* Optional legt eine **`bilder.json`** im ZIP (Wurzel, `public/` oder `config/`) Titel, Beschreibung, Maximalanzahl,
  empfohlenes Format und Beschriftungen fest – siehe `app/config/bilder.example.json`. Mit `"nur_bereiche": true` können im
  Admin keine weiteren Bereiche angelegt werden.
* Pro Bild: Vorschau, Pixelgrösse (Warnung bei falschem Format), Beschriftung, Alternativtext, Reihenfolge, Ersetzen (gleicher Name), Löschen.
* **«Bilder auf den Seiten»** listet, welche Bilder Startseite und Unterseiten verwenden, inkl. fehlender Dateien. Bilder zeigen
  zudem als Badge, auf welchen Seiten sie vorkommen.
* Uploads werden geprüft (Endung, Magic Bytes, Dateiname bereinigt); SVGs werden ohne Skriptausführung ausgeliefert.
* Die Webseite kann alles über **`GET /api/bilder`** laden:

```js
fetch('/api/bilder').then(r => r.json()).then(({ bereiche }) => {
  const galerie = bereiche.find(b => b.ordner === 'galerie');
  galerie.bilder.forEach(b => { /* b.src, b.text, b.alt, b.breite, b.hoehe */ });
});
```

---

## 🧩 Funktionen (Admin → Einstellungen → Funktionen)

| Funktion | Standard | Env-Default | Beschreibung |
|---|---|---|---|
| Webshop | an | `FEATURE_SHOP` | Produkte, Warenkorb, Bestellungen, Bestätigungs-E-Mails |
| Kontaktformular | aus | `FEATURE_KONTAKT` | `POST /api/kontakt` (JSON oder HTML-Formular), Honigtopf, Rate-Limit, Nachrichten im Admin + E-Mail an Betreiber |
| SEO | aus | `FEATURE_SEO` | `sitemap.xml`, `robots.txt`, ergänzt fehlende `description`/OpenGraph/Canonical-Tags |
| Wartungsmodus | aus | `FEATURE_WARTUNG` | Besucher sehen eine Wartungsseite (503), angemeldete Admins die normale Seite |

Deaktivierte Funktionen antworten mit 404. Das Kontaktformular verschickt bewusst **keine** automatische Antwort an den
Absender (sonst könnte man darüber Dritten E-Mails schicken). Beispiel ohne JavaScript:

```html
<form method="post" action="/api/kontakt">
  <input name="name" required> <input name="email" type="email" required>
  <input name="betreff"> <textarea name="nachricht" required></textarea>
  <input name="website" style="display:none" tabindex="-1" autocomplete="off">  <!-- Honigtopf -->
  <input type="hidden" name="weiter" value="/kontakt">                          <!-- danach /kontakt?kontakt=ok -->
  <button>Senden</button>
</form>
```

Weitere Bereiche: **Unterseiten** (`/<name>`, gespeichert in `/data/site/pages/`), **ZIP-Import & HTML-Editor**,
**Backup-ZIP** (ohne Passwort-Hash und SMTP-Passwort) und **Dunkelmodus**.

---

## 🐳 Docker Image

Mehrstufiger Build: Der offizielle `python:3.14-slim`-Build wird entschlackt (kein pip, keine Test-/GUI-/Datenbankmodule)
und auf `gcr.io/distroless/base-debian13` kopiert – ohne Shell, Paketmanager und Coreutils. Beide Base-Images sind per
Digest gepinnt.

Die CI führt die Tests zusätzlich **im fertigen Image** (read-only, UID 10001, ohne Capabilities) aus und bricht bei
behebbaren HIGH/CRITICAL-Schwachstellen ab (Trivy). Veröffentlicht wird nur bei Versions-Tags:

```bash
git tag v2.0.0 && git push origin --tags
# -> ghcr.io/drunk-fone/site-engine:2.0.0 und :latest (amd64 + arm64)
git tag v2.0.0-rc.1 && git push origin v2.0.0-rc.1
# -> nur :2.0.0-rc.1 (Vorabversion zum Testen, :latest bleibt unverändert)
```

Da es keine Shell gibt, funktioniert `kubectl exec … -- sh` nicht; `kubectl exec … -- python /app/server.py reset-admin` schon.

---

## 💻 Lokal testen

```bash
mkdir -p data
DATA_DIR=data SHOP_URL=http://localhost:8080 python3 app/server.py   # Einrichtungs-Link steht im Log
# -> Link öffnen, Passwort setzen, dann http://localhost:8080/admin
python3 -m unittest discover tests
```
