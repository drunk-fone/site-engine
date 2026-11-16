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

## 🔐 Admin-Zugang: Anmeldung mit Google

Das Admin wird mit **«Sign in with Google»** geschützt. Es gibt keine Passwörter und **kein Secret**: Der Browser bekommt
von Google ein signiertes ID-Token, der Server prüft es mit Googles öffentlichen Schlüsseln (Signatur RS256, Aussteller,
Client ID, Ablauf, Nonce, bestätigte E-Mail) und vergleicht die E-Mail mit der Liste erlaubter Konten. Die zweite
Absicherung (2FA) übernimmt Google.

### Neue Webseite einrichten

1. **Einmalig für alle Seiten** in der [Google Cloud Console](https://console.cloud.google.com/apis/credentials):
   OAuth-Zustimmungsbildschirm (Typ «Extern», nur die Standardbereiche `openid`, `email`, `profile`) und eine
   **OAuth-Client-ID vom Typ «Webanwendung»** anlegen. Eine Client-ID reicht für alle Seiten.
   Solange die App im Status «Testen» ist, dürfen sich nur eingetragene Testnutzer anmelden – die erlaubten Konten dort
   eintragen oder die App veröffentlichen (für die Standardbereiche ist keine Prüfung durch Google nötig).
2. **Pro Seite** bei dieser Client-ID unter **«Autorisierte JavaScript-Quellen»** die Domain eintragen
   (z. B. `https://shop.example.ch`). Weiterleitungs-URIs braucht es nicht.
3. **Pro Seite** in der ConfigMap:

```yaml
GOOGLE_CLIENT_ID: "1234567890-abc….apps.googleusercontent.com"   # öffentlich, kein Geheimnis
ADMIN_EMAILS: "ich@gmail.com, kunde@gmail.com"                     # erlaubte Google-Konten
```

Nach dem Sync von Argo CD kann man sich sofort unter `/admin` anmelden – kein Log, kein Link, kein `kubectl`.
Alternativ lassen sich Client ID und weitere Konten auch im Admin unter *Einstellungen → Anmeldung* pflegen
(Werte aus der ConfigMap sind dort schreibgeschützt).

### Notfall

* **Notfall-Codes:** Nach dem ersten Login unter *Einstellungen → Anmeldung* «Neue Notfall-Codes erzeugen» und die
  10 Einmal-Codes z. B. in Vaultwarden ablegen. Auf der Login-Seite: «Google funktioniert nicht? Notfall-Code verwenden».
* **Letzter Ausweg:** `kubectl exec deploy/<name> -n <ns> -- python /app/server.py notfall-link` gibt einen einmaligen,
  15 Minuten gültigen Link aus, der direkt eine Sitzung öffnet. Kann sich niemand anmelden (keine Client ID, keine
  Konten, keine Codes), steht ein solcher Link beim Start auch im Pod-Log.

### Schutzmassnahmen

* Nonce pro Anmeldung (an ein HttpOnly-Cookie gebunden): ein abgefangenes Token funktioniert in keinem anderen Browser
  und jedes Token nur ein einziges Mal.
* RSA-Signaturprüfung vergleicht die vollständige PKCS#1-Kodierung (keine Padding-Tricks), nur Schlüssel ≥ 2048 Bit.
  Googles Schlüssel werden gemäss `Cache-Control` gecacht.
* Sitzungs-Cookie `__Host-…`, `HttpOnly`, `Secure`, `SameSite=Strict`; Ablauf nach 2 h Inaktivität bzw. 12 h.
* CSRF-Token und `Origin`-Prüfung für alle Änderungen; Sperre nach 5 Fehlversuchen pro IP und globale Obergrenze.
* Auf der Login-Seite ist ausser eigenem Code nur `https://accounts.google.com/gsi/client` erlaubt (CSP); alle anderen
  Admin-Seiten erlauben nur eigenes JavaScript.
* Notfall-Codes und -Links werden nur als SHA-256-Hash gespeichert und sind einmalig.
* Selbstaussperr-Schutz: Man kann das eigene Konto nicht entfernen und nicht alle Zugänge gleichzeitig.

Lokal ohne HTTPS (z. B. `http://192.168.…`) braucht es `COOKIE_SECURE=0`. Für lokale Tests mit Google muss
`http://localhost:8080` als JavaScript-Quelle der Client-ID eingetragen sein.

**Upgrade:** `ADMIN_USER`, `ADMIN_PASSWORD`, `ADMIN_PASSWORD_HASH` und `ADMIN_EMAIL` werden ignoriert (Warnung im Log);
alte Passwort-Hashes auf dem Volume werden beim Start entfernt.

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

Da es keine Shell gibt, funktioniert `kubectl exec … -- sh` nicht; `kubectl exec … -- python /app/server.py notfall-link` schon.

---

## 💻 Lokal testen

```bash
mkdir -p data
DATA_DIR=data GOOGLE_CLIENT_ID=… ADMIN_EMAILS=ich@gmail.com python3 app/server.py
# -> http://localhost:8080/admin  (ohne Google: Notfall-Link steht im Log)
python3 -m unittest discover tests
```
