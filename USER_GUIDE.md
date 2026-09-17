# Umbralyn — Guide d’utilisation

Umbralyn est un outil d’audit réseau défensif. Il découvre les hôtes et services d’une cible autorisée, identifie les points d’attention, calcule un score de risque et génère des rapports.

> **Cadre d’utilisation :** n’utilisez Umbralyn que sur vos systèmes, votre laboratoire, ou une infrastructure pour laquelle vous disposez d’une autorisation explicite. Le logiciel ne réalise ni exploitation, ni brute force, ni action corrective intrusive.

## 1. Pré-requis

- Python 3.10 ou supérieur ;
- Nmap installé et disponible dans le `PATH` ;
- accès réseau à la cible autorisée ;
- optionnel : Docker pour une exécution isolée ;
- optionnel : une clé API NVD pour accélérer les recherches CVE.

Sous macOS :

```bash
brew install nmap
```

Sous Debian/Ubuntu :

```bash
sudo apt update
sudo apt install nmap python3-venv
```

## 2. Installation locale

Placez-vous dans le dossier du projet, créez un environnement virtuel puis installez les dépendances.

```bash
cd umbralyn
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Vérifiez que la CLI est disponible :

```bash
python -m umbralyn --help
```

Pour utiliser la commande courte `umbralyn`, vous pouvez également installer le projet localement :

```bash
pip install -e .
umbralyn --help
```

## 3. Configuration

Copiez la configuration exemple. Le fichier réel `config.yaml` est ignoré par Git afin de ne pas partager des cibles internes.

```bash
cp config.example.yaml config.yaml
```

Exemple minimal :

```yaml
target:
  network: "192.168.1.0/24"
scan:
  service_detection: true
  os_detection: false
  nse: false
  timeout_seconds: 600
database:
  path: "./data/umbralyn.db"
report:
  directory: "./reports"
risk:
  alert_threshold: 70
```

Vous pouvez surcharger ces valeurs avec des variables d’environnement :

```bash
export UMBRALYN_CONFIG=config.yaml
export UMBRALYN_DATABASE_PATH=./data/umbralyn.db
export UMBRALYN_REPORTS_DIR=./reports
export UMBRALYN_NVD_API_KEY="votre-cle-api"
```

Pour afficher la configuration effectivement lue :

```bash
python -m umbralyn config --config config.yaml
```

## 4. Lancer un scan

### Scan rapide

Scanne les ports les plus courants, avec détection de services et de versions.

```bash
python -m umbralyn scan 192.168.1.10
```

Le rapport HTML est généré dans `reports/` par défaut.

### Scanner un réseau de laboratoire

```bash
python -m umbralyn scan 192.168.1.0/24 --config config.yaml
```

### Scan étendu

`--full` examine tous les ports TCP. Cette opération peut être longue sur une plage réseau ; utilisez-la seulement sur une cible validée.

```bash
python -m umbralyn scan 192.168.1.10 --full
```

### Détection de l’OS

```bash
python -m umbralyn scan 192.168.1.10 --os-detection
```

Selon le système, Nmap peut demander des privilèges élevés pour obtenir un résultat fiable. Ne lancez cette option que si cela respecte vos procédures de sécurité.

### Scripts NSE de vulnérabilité

```bash
python -m umbralyn scan 192.168.1.10 --vuln-scripts
```

Cette option active les scripts NSE `vuln` de Nmap. Ils sont normalisés en findings dans le rapport. Prévoyez davantage de temps et validez toujours leur autorisation dans le périmètre d’audit.

### Recherche CVE

```bash
python -m umbralyn scan 192.168.1.10 --cve
```

Umbralyn recherche les CVE candidates dans la NVD à partir du produit et de la version détectés. Une correspondance reste une **indication**, pas une preuve : une version peut être patchée par un fournisseur ou être mal détectée. Sans accès API, Umbralyn utilise un petit jeu de données de démonstration hors ligne.

### Toutes les sorties

```bash
python -m umbralyn scan 192.168.1.10 \
  --full --os-detection --vuln-scripts --cve \
  --save-history --compare \
  --json-out scans/audit-2026-09-17.json \
  --out reports/audit-2026-09-17.html --pdf
```

Options importantes :

| Option | Effet |
| --- | --- |
| `--full` | Scanne tous les ports au lieu des ports usuels. |
| `--no-service-detection` | Désactive `-sV` pour un inventaire plus rapide. |
| `--os-detection` | Active `-O` de Nmap. |
| `--vuln-scripts` | Active les scripts NSE `vuln`. |
| `--cve` | Recherche les CVE candidates auprès de NVD. |
| `--out` | Définit le chemin du rapport HTML. |
| `--pdf` | Produit un PDF en plus du rapport HTML. |
| `--json-out` | Exporte le résultat brut en JSON portable. |
| `--save-history` | Enregistre le résultat dans SQLite. |
| `--compare` | Compare le résultat au scan précédent enregistré. |

## 5. Lire le rapport

Un rapport est organisé en quatre niveaux :

1. **Synthèse exécutive** : hôtes actifs, ports ouverts et nombre de findings.
2. **Score de risque** : score global et score par hôte sur 100.
3. **Points d’attention** : services, expositions ou résultats NSE nécessitant une vérification.
4. **Détails techniques** : ports, services, versions, CVE candidates et recommandations par hôte.

Le score est explicable. Par exemple, une exposition Telnet ajoute un poids élevé et une CVE critique candidate ajoute un poids plus important. Le score est plafonné à 100 et ne remplace pas l’analyse humaine.

## 6. Historique et comparaison

Enregistrez le scan et comparez-le au précédent :

```bash
python -m umbralyn scan 192.168.1.10 --save-history --compare
```

Listez l’historique :

```bash
python -m umbralyn history
python -m umbralyn history --target 192.168.1.10
```

Comparez deux exports JSON :

```bash
python -m umbralyn compare scans/avant.json scans/apres.json
```

Les changements détectés sont : nouvel hôte, hôte absent, nouveau port, port fermé et bannière de service modifiée.

Pour régénérer un rapport sans contacter le réseau :

```bash
python -m umbralyn report scans/apres.json --out reports/apres.html
```

## 7. Surveillance planifiée

Le sous-programme `schedule` effectue un scan à intervalle fixe et compare automatiquement chaque résultat au précédent.

```bash
export UMBRALYN_SMTP_USER="alertes@example.com"
export UMBRALYN_SMTP_PASS="mot-de-passe-application"
python -m umbralyn schedule 192.168.1.10 --interval 3600 \
  --email-to secops@example.com --smtp-host smtp.example.com
```

- `--interval` est exprimé en secondes ; `3600` correspond à une heure.
- un e-mail n’est envoyé que lorsqu’un changement est détecté ;
- utilisez un mot de passe d’application ou un secret injecté par votre gestionnaire de secrets ;
- pour un usage durable, exécutez ce processus avec `systemd`, un conteneur supervisé ou un ordonnanceur de votre infrastructure.

## 8. Docker

Construisez l’image :

```bash
docker build -t umbralyn .
```

Exécutez un scan autorisé. Sous Linux, `--network host` permet à Nmap d’atteindre le réseau de l’hôte ; examinez les implications de cette option avant emploi.

```bash
docker run --rm --network host \
  -v "$(pwd)/reports:/app/reports" \
  umbralyn scan 192.168.1.10 --out /app/reports/audit.html
```

## 9. Dépannage

| Message / situation | Résolution |
| --- | --- |
| `nmap est introuvable` | Installez Nmap puis vérifiez `nmap --version`. |
| Aucun hôte actif | Vérifiez la cible, le VPN, le pare-feu et le périmètre autorisé. |
| Export PDF en erreur | Réinstallez les dépendances ; dans Docker, elles sont déjà présentes. |
| Recherche CVE lente | Utilisez une clé NVD via `UMBRALYN_NVD_API_KEY` ou désactivez `--cve`. |
| E-mail non envoyé | Vérifiez les identifiants SMTP, le port, TLS et les règles du fournisseur. |

## 10. Tests et mise à jour

Lancez les tests, sans scan réel :

```bash
pip install pytest
pytest -q
```

Avant toute mise à jour, conservez vos exports JSON, votre base SQLite et vos rapports. Ces dossiers sont volontairement ignorés par Git.
