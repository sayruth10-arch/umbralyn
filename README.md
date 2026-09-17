# Umbralyn

Umbralyn est un outil d'audit réseau défensif développé en Python. Il s'appuie sur Nmap pour découvrir les hôtes, ports et services exposés, réalise une première analyse heuristique des services à risque, corrèle les versions détectées avec les CVE disponibles via l'API NVD, calcule un score de risque explicable et génère des rapports d'audit.

L'outil permet également de conserver un historique SQLite, de comparer plusieurs scans, d'effectuer une surveillance planifiée et d'envoyer des alertes par email en cas de changement détecté.

## Fonctionnalités

* Scan Nmap rapide ou complet avec détection des versions des services (`-sV`)
* Détection optionnelle des systèmes d'exploitation (`-O`)
* Scripts NSE de détection de vulnérabilités (`--script vuln`) en option
* Analyse heuristique des services et ports exposés présentant un risque connu
* Corrélation des services et versions avec l'API NVD
* Cache local des résultats CVE pour limiter les requêtes répétées
* Mode dégradé avec une petite base locale de CVE lorsque l'API NVD est indisponible
* Score de risque par hôte de 0 à 100 et score global du scan
* Calcul du score explicable à partir de la sévérité des findings et des CVE détectées
* Historique des scans dans SQLite
* Comparaison entre scans : nouveaux ports, ports fermés, nouveaux hôtes, hôtes indisponibles et changements de services
* Surveillance planifiée avec la commande `schedule`
* Alertes email lors de changements détectés
* Rapports HTML et PDF
* Exports JSON portables
* Configuration YAML avec surcharge possible par variables d'environnement
* Dockerfile prêt à l'emploi
* Tests unitaires pour les principales fonctions métier

> **Important :** la détection heuristique d'un port ou service à risque ne constitue pas, à elle seule, une preuve de vulnérabilité. Les CVE obtenues par recherche de mots-clés doivent également être considérées comme des candidates nécessitant une vérification du produit, de la version et du contexte. Les résultats NSE doivent être interprétés dans leur contexte.

## Documentation

* [Guide d'utilisation](USER_GUIDE.md) : installation, configuration, scans, rapports, historique, planification et Docker.
* [Documentation technique](TECHNICAL_DOCUMENTATION.md) : architecture, modèles de données, flux, scoring, sécurité et évolutions.

## ⚠️ Avertissement

**Ne scanne que des cibles pour lesquelles tu as une autorisation explicite**
(ton propre lab, une VM à toi, ou un accord écrit du propriétaire du réseau).

Scanner un réseau sans autorisation peut être illégal. Pour une démonstration ou un entretien, utilise ton propre environnement de laboratoire ou des cibles explicitement prévues pour les tests, comme `scanme.nmap.org`.

## Installation

### Installation classique

Créer un environnement virtuel :

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Nmap doit être installé sur le système :

```bash
sudo apt install nmap      # Debian / Ubuntu
brew install nmap          # macOS
```

Vérifier l'installation :

```bash
nmap --version
python -m umbralyn --help
```

### Configuration

Un fichier de configuration peut être créé à partir de l'exemple :

```bash
cp config.example.yaml config.yaml
```

`config.yaml` est ignoré par Git afin d'éviter de versionner une configuration locale.

La configuration peut également être surchargée par des variables d'environnement, notamment :

```text
UMBRALYN_CONFIG
UMBRALYN_TARGET
UMBRALYN_TIMEOUT
UMBRALYN_DATABASE_PATH
UMBRALYN_REPORTS_DIR
UMBRALYN_ALERT_THRESHOLD
UMBRALYN_SERVICE_DETECTION
UMBRALYN_OS_DETECTION
UMBRALYN_NSE
UMBRALYN_NVD_API_KEY
UMBRALYN_SMTP_USER
UMBRALYN_SMTP_PASS
```

Afficher la configuration effectivement chargée :

```bash
python -m umbralyn config
```

## Usage

### Scan ponctuel

Scan rapide des 100 ports les plus courants avec détection des services :

```bash
python -m umbralyn scan 192.168.1.0/24
```

Scan complet avec détection des versions, scripts NSE et recherche CVE :

```bash
python -m umbralyn scan 10.0.0.5 --full --vuln-scripts --cve
```

Activer la détection du système d'exploitation :

```bash
python -m umbralyn scan 10.0.0.5 --os-detection
```

Générer également un rapport PDF :

```bash
python -m umbralyn scan 10.0.0.5 --full --cve --pdf
```

Désactiver la détection de version des services :

```bash
python -m umbralyn scan 10.0.0.5 --no-service-detection
```

### Historique et comparaison

Sauvegarder un scan dans l'historique SQLite :

```bash
python -m umbralyn scan 192.168.1.0/24 --save-history
```

Sauvegarder puis comparer avec le scan précédent :

```bash
python -m umbralyn scan 192.168.1.0/24 --compare
```

Afficher l'historique :

```bash
python -m umbralyn history
```

Filtrer l'historique sur une cible :

```bash
python -m umbralyn history --target 192.168.1.0/24
```

La base SQLite est stockée par défaut dans :

```text
data/umbralyn.db
```

### Export JSON

Exporter un scan complet au format JSON :

```bash
python -m umbralyn scan 192.168.1.0/24 \
    --json-out scans/scan-01.json
```

Comparer deux exports JSON sans relancer Nmap :

```bash
python -m umbralyn compare \
    scans/scan-01.json \
    scans/scan-02.json
```

Générer un rapport HTML depuis un export existant :

```bash
python -m umbralyn report \
    scans/scan-02.json \
    --out reports/audit.html
```

### Recherche CVE

L'option `--cve` utilise l'API NVD afin de rechercher des CVE correspondant aux produits et versions détectés.

Sans clé API, l'application espace les requêtes afin de respecter les limites de l'API NVD et utilise un cache local.

Une clé API peut être fournie avec :

```text
UMBRALYN_NVD_API_KEY
```

En cas d'indisponibilité de l'API, Umbralyn utilise une petite base locale de CVE connues afin de conserver un fonctionnement en mode dégradé.

**Attention :** une correspondance NVD basée sur le produit et la version constitue une piste de vulnérabilité. Elle ne remplace pas une vérification précise du produit, de la version affectée, de la configuration et des conditions d'exploitation.

### Surveillance planifiée

Exécuter un scan toutes les heures :

```bash
python -m umbralyn schedule \
    192.168.1.0/24 \
    --interval 3600
```

Avec une alerte email :

```bash
export UMBRALYN_SMTP_USER="toncompte@gmail.com"
export UMBRALYN_SMTP_PASS="un_mot_de_passe_d_application"

python -m umbralyn schedule \
    192.168.1.0/24 \
    --interval 3600 \
    --email-to alerte@exemple.com \
    --smtp-host smtp.gmail.com
```

Le scheduler :

1. lance le scan ;
2. sauvegarde le résultat dans SQLite ;
3. récupère le scan précédent ;
4. compare les deux résultats ;
5. affiche les changements détectés ;
6. envoie une alerte email si nécessaire.

Les changements suivis comprennent notamment :

* nouveaux hôtes ;
* hôtes devenus indisponibles ;
* nouveaux ports ouverts ;
* ports précédemment ouverts désormais fermés ;
* changements de service ou de bannière.

## Docker

Construire l'image :

```bash
docker build -t umbralyn .
```

Lancer un scan :

```bash
docker run --rm \
    --network host \
    -v "$(pwd)/reports:/app/reports" \
    -v "$(pwd)/data:/app/data" \
    umbralyn scan 192.168.1.0/24 --pdf
```

Le montage de `data/` permet de conserver l'historique SQLite entre deux conteneurs.

Le montage de `reports/` permet de récupérer les rapports générés sur la machine hôte.

`--network host` est généralement nécessaire pour permettre à Nmap d'accéder directement au réseau local depuis le conteneur.

## Structure du projet

```text
umbralyn/
├── umbralyn/
│   ├── __init__.py
│   ├── __main__.py       # CLI argparse et sous-commandes
│   ├── config.py         # Configuration YAML + variables d'environnement
│   ├── scanner.py        # Exécution Nmap + parsing XML
│   ├── risk_analysis.py  # Analyse heuristique des services à risque
│   ├── cve_lookup.py     # Corrélation CVE avec l'API NVD + cache
│   ├── scoring.py        # Score de risque par hôte et global
│   ├── history.py        # Historique SQLite + comparaison
│   ├── scheduler.py      # Surveillance planifiée + alertes email
│   └── report.py          # Génération HTML/PDF
├── templates/
│   └── report.html       # Template du rapport
├── web/
│   ├── index.html        # Interface web de démonstration
│   └── styles.css        # Styles de l'interface
├── tests/
│   ├── test_history.py
│   └── test_scoring.py
├── config.example.yaml   # Configuration de référence
├── .env.example          # Exemple de variables d'environnement
├── Dockerfile
├── pyproject.toml
├── requirements.txt
├── USER_GUIDE.md
└── TECHNICAL_DOCUMENTATION.md
```

Les répertoires suivants sont destinés aux données générées localement et ne sont pas versionnés :

```text
data/
reports/
scans/
```

## Tests

Les tests utilisent `pytest` :

```bash
pip install pytest
pytest
```

Les tests actuels couvrent notamment :

* la sérialisation et désérialisation des scans ;
* la conservation des résultats NSE ;
* la détection des nouveaux ports lors d'une comparaison ;
* le plafonnement du score à 100 ;
* la génération du détail explicatif du score.

Des tests supplémentaires peuvent être ajoutés pour le parsing XML, la configuration, la corrélation CVE et le scheduler.

## Pistes d'évolution

* Ajouter des fixtures XML Nmap pour tester davantage le parsing sans effectuer de scan réel
* Améliorer la corrélation CVE avec les CPE afin de réduire les correspondances trop larges
* Utiliser une clé API NVD pour augmenter les capacités de requêtage
* Ajouter davantage de tests automatisés pour la configuration et le scheduler
* Ajouter une interface web légère au-dessus de l'historique SQLite
* Ajouter un export SARIF pour faciliter l'intégration CI/CD
* Ajouter éventuellement PostgreSQL pour les déploiements multi-utilisateurs
* Ajouter une intégration optionnelle avec Wazuh pour enrichir la supervision de sécurité

## Licence

Usage personnel et pédagogique. Adaptable librement selon les besoins du projet.

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
