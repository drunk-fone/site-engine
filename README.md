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
Das Passwort liegt nur als Hash (PBKDF2-SHA256, 600 000 Runden) in `/data/site/config/auth.json` (Dateirechte 0600).

**Erstes Passwort setzen oder Passwort vergessen:**

```bash
kubectl exec -it deploy/<name> -n <namespace> -- python /app/server.py reset-admin
# lokal: DATA_DIR=../data python3 app/server.py reset-admin
```

Das gibt einen **Einmal-Link** aus (`https://<domain>/admin/setup#…`, 15 Minuten gültig). Der Code steht hinter dem `#` und wird
daher nie an Server, Proxy oder Logs übertragen. Nach dem Setzen werden alle Sitzungen beendet und eine aktive 2FA wird
zurückgesetzt. Wer `kubectl exec` darf, kann das Passwort zurücksetzen – mehr Vertrauen braucht es nicht.

Weitere Schutzmassnahmen:
* Login-Formular mit Sitzungs-Cookie (`__Host-…`, `HttpOnly`, `Secure`, `SameSite=Strict`), Ablauf nach 2 h Inaktivität bzw. 12 h.
* CSRF-Token und `Origin`-Prüfung für alle Änderungen.
* Sperre nach 5 Fehlversuchen pro IP (15 Min.) und globale Obergrenze von 50 Fehlversuchen / 15 Min. gegen IP-Rotation.
  Neustart des Pods hebt die Sperre auf.
* Optionale **Zwei-Faktor-Anmeldung (TOTP)** mit jeder Authenticator-App, lokal ohne externen Dienst, mit Replay-Schutz.
* Admin-Seiten erlauben kein Inline-JavaScript (CSP `script-src 'self'`).
* Passwortänderung erfordert das aktuelle Passwort und meldet alle anderen Sitzungen ab.

Lokal ohne HTTPS (z. B. `http://192.168.…`) braucht es `COOKIE_SECURE=0`; für `http://localhost` nicht.

**Upgrade von 1.x:** `ADMIN_USER`, `ADMIN_PASSWORD` und `ADMIN_PASSWORD_HASH` werden ignoriert (Warnung im Log) und können
aus ConfigMaps/Secrets entfernt werden. Ein früher im Admin gesetztes Passwort (in `settings.json` auf dem Volume) wird
automatisch übernommen und beim nächsten Login neu gehasht. Sonst einmal `reset-admin` ausführen.

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
```

Da es keine Shell gibt: `kubectl exec … -- python /app/server.py reset-admin` funktioniert, `kubectl exec … -- sh` nicht.

---

## 💻 Lokal testen

```bash
mkdir -p data
DATA_DIR=data python3 app/server.py reset-admin   # Einmal-Link ausgeben
DATA_DIR=data python3 app/server.py               # http://localhost:8080/admin
python3 -m unittest discover tests
```
