# Umbralyn

Umbralyn est un outil d'audit réseau en Python : il lance un scan Nmap, repère les services
à risque, croise avec les CVE connues, calcule un score de risque par hôte,
compare avec les scans précédents, et génère un rapport HTML/PDF.

## Fonctionnalités

- Scan Nmap (rapide ou complet) avec détection de version des services (`-sV`)
- Scripts NSE de détection de vulnérabilités (`--script vuln`) en option
- Détection heuristique des services à risque connus (Telnet, SMB exposé, RDP, bases de données non protégées...)
- Correspondance CVE via l'API NVD, avec cache local et repli hors-ligne si l'API est injoignable
- Score de risque par hôte (0-100) et score global, avec jauges visuelles dans le rapport
- Historique des scans en SQLite + comparaison entre deux scans (nouveaux ports, hôtes, services modifiés)
- Mode surveillance planifiée (`schedule`) avec alerte email en cas de changement
- Rapport HTML au design soigné, exportable en PDF
- Dockerfile prêt à l'emploi (aucune dépendance à installer sur la machine hôte)
- Configuration YAML et surcharges par variables d'environnement
- Exports JSON portables, commandes `compare`, `history` et `report`
- Tests unitaires pour le score et la comparaison

## Documentation

- [Guide d’utilisation](USER_GUIDE.md) : installation, configuration, scans, rapports, historique, planification et Docker.
- [Documentation technique](TECHNICAL_DOCUMENTATION.md) : architecture, modèles, flux de données, scoring, sécurité et évolutions.

## ⚠️ Avertissement

**Ne scanne que des cibles pour lesquelles tu as une autorisation explicite**
(ton propre lab, une VM à toi, ou un accord écrit du propriétaire du réseau).
Scanner un réseau sans autorisation est illégal dans la plupart des pays
(en France : article 323-1 du Code pénal). Pour une démo en entretien,
utilise ton propre lab (VMs VirtualBox/VMware/vSphere) ou des cibles
prévues pour ça comme `scanme.nmap.org`.

## Installation

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Nmap doit être installé sur le système :
```bash
sudo apt install nmap      # Debian/Ubuntu
brew install nmap          # macOS
```

## Usage

### Scan ponctuel

```bash
# Scan rapide (top 100 ports) avec détection de service
python -m umbralyn scan 192.168.1.0/24

# Scan complet + scripts de vulnérabilités + CVE + export PDF
python -m umbralyn scan 10.0.0.5 --full --vuln-scripts --cve --pdf

# Sauvegarder dans l'historique et comparer avec le scan précédent de la même cible
python -m umbralyn scan 192.168.1.0/24 --compare

# Choisir le chemin de sortie
python -m umbralyn scan scanme.nmap.org --out reports/scanme.html

# Exporter, puis comparer deux scans sans relancer Nmap
python -m umbralyn scan 192.168.1.0/24 --json-out scans/scan-01.json
python -m umbralyn compare scans/scan-01.json scans/scan-02.json

# Générer un rapport depuis un export existant
python -m umbralyn report scans/scan-02.json --out reports/audit.html
```

Le rapport HTML est généré dans `reports/` par défaut. Ajoute `--pdf` pour
avoir aussi une version PDF (utile pour l'envoyer par mail).

`--cve` interroge l'API NVD (≈1 requête toutes les 6s pour respecter le
rate-limit sans clé API) ; en cas d'échec ou d'absence de réseau, l'outil
bascule automatiquement sur une petite base de CVE notoires en local.

### Surveillance planifiée

```bash
# Scanne la cible toutes les heures, alerte par email si changement
export UMBRALYN_SMTP_USER="toncompte@gmail.com"
export UMBRALYN_SMTP_PASS="un_mot_de_passe_d_application"
python -m umbralyn schedule 192.168.1.0/24 --interval 3600 \
    --email-to alerte@exemple.com --smtp-host smtp.gmail.com
```

Chaque scan est comparé au précédent (stockés dans `umbralyn_history.db`) ;
un email n'est envoyé que si un changement est détecté.

### Avec Docker

```bash
docker build -t umbralyn .
docker run --rm -v $(pwd)/reports:/app/reports --network host \
    umbralyn scan 192.168.1.0/24 --pdf
```

`--network host` est nécessaire pour que Nmap scanne le réseau local depuis
le conteneur (sinon il ne verra que le réseau interne Docker).

## Structure du projet

```
umbralyn/
├── umbralyn/
│   ├── __main__.py       # CLI (argparse) : sous-commandes scan / schedule
│   ├── scanner.py        # Appel nmap + parsing XML (+ scripts NSE)
│   ├── risk_analysis.py  # Détection de ports/services à risque
│   ├── cve_lookup.py     # Correspondance CVE (API NVD + cache + repli hors-ligne)
│   ├── scoring.py        # Score de risque par hôte / global
│   ├── history.py        # Historique SQLite + comparaison entre scans
│   ├── scheduler.py       # Boucle de surveillance planifiée + alerte email
│   └── report.py          # Génération du rapport HTML/PDF (Jinja2 + WeasyPrint)
├── templates/
│   └── report.html       # Template du rapport (jauges, CVE, diff)
├── reports/               # Rapports générés (gitignored idéalement)
├── tests/                 # Tests unitaires sans scan réel
├── config.example.yaml    # Configuration de référence
├── .env.example           # Variables sensibles documentées, sans secrets
├── Dockerfile
└── requirements.txt
```

## Pistes d'évolution restantes

- Tests unitaires sur le parsing XML (fichiers d'exemple Nmap en fixtures)
- Authentification à l'API NVD (clé API) pour lever la limite de 6s/requête
- Interface web légère (Flask) au-dessus de l'historique SQLite existant
- Export des findings au format SARIF pour intégration CI/CD

## Licence

Usage personnel / pédagogique. Adapte librement.
