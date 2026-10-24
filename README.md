# 🚀 Site-Engine

Schlanke, gehärtete Webshop- und Website-Engine für Kubernetes & Docker.

Entwickelt für maximale Performance, Sicherheit und minimale Ressourcen:
* **Zero Dependencies:** Reines Python 3.12 (Standardbibliothek), kein Framework-Ballast.
* **Minimaler Footprint:** ~30–50 MB RAM, extrem sparsam.
* **Produktions-Härtung:** Non-Root User (UID 10001), Read-Only Root Filesystem, NetworkPolicy-kompatibel.
* **Entkoppelte Konfiguration:** Shop-Daten, Produkte und Branding liegen in `app/config/site.json`.

---

## 📁 Repository-Struktur

```
site-engine/
├── .github/workflows/
│   └── image.yml               # Multi-Arch Docker Build (amd64, arm64) -> ghcr.io
├── app/
│   ├── config/
│   │   ├── site.json           # Aktive Konfiguration (Preise, Produkte, Brand)
│   │   └── site.example.json   # Vorlage für neue Webseiten
│   ├── public/
│   │   ├── index.html          # Storefront-Template
│   │   └── img/                # Produktbilder und Logos
│   └── server.py               # Reusable HTTP/Shop Server Engine
├── Dockerfile                  # Gehärtetes Container-Image
└── .dockerignore
```

---

## ⚙️ Wie Kunden-Anpassungen funktionieren

Für jede neue Kundenwebseite muss kein Code neu geschrieben werden:
1. Kopiere `app/config/site.example.json` nach `app/config/site.json`.
2. Trage Name, Adresse, Farben, Produkte und Versandregeln ein.
3. Platziere die Produktbilder in `app/public/img/`.
4. Der Server übernimmt automatisch Preise, Validierung, Warenkorbberechnung und E-Mail-Vorlagen.

---

## 🐳 Docker Image bauen

### Automatisch via GitHub Actions
Bei jedem Push auf `main` oder Taggen einer Version (`v1.0.0`):
```bash
git tag v1.0.0
git push origin --tags
```
GitHub Actions baut das Image für `linux/amd64` und `linux/arm64` und pusht es nach:
`ghcr.io/drunk-fone/site-engine:latest` und `ghcr.io/drunk-fone/site-engine:1.0.0`.

---

## 💻 Lokal testen (ohne Docker / Kubernetes)

```bash
cd app
mkdir -p ../data
DATA_DIR=../data python3 server.py
# Öffne http://localhost:8080
```
Bestellungen landen direkt in `../data/bestellungen.csv` und `../data/bestellungen.jsonl`.
