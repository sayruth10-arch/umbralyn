# Umbralyn — Guide d’utilisation

Umbralyn est un outil d’audit réseau défensif. Il découvre les hôtes et services d’une cible autorisée, identifie les points d’attention, recherche des CVE candidates, calcule un score de risque explicable et génère des rapports.

> **Cadre d’utilisation :** n’utilisez Umbralyn que sur vos systèmes, votre laboratoire ou une infrastructure pour laquelle vous disposez d’une autorisation explicite. Le logiciel ne réalise ni exploitation, ni brute force, ni action corrective intrusive.

## 1. Pré-requis

* Python 3.10 ou supérieur ;
* Nmap installé et disponible dans le `PATH` ;
* accès réseau à la cible autorisée ;
* optionnel : Docker pour une exécution conteneurisée ;
* optionnel : une clé API NVD pour augmenter les capacités de requêtage.

Sous macOS :

```bash
brew install nmap
```

Sous Debian/Ubuntu :

```bash
sudo apt update
sudo apt install nmap python3-venv
```

Vérifiez l'installation :

```bash
nmap --version
python3 --version
```

## 2. Installation locale

Placez-vous dans le dossier du projet, créez un environnement virtuel puis installez les dépendances :

```bash
cd umbralyn
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Vérifiez que la CLI fonctionne :

```bash
python -m umbralyn --help
```

Pour installer également la commande courte `umbralyn` :

```bash
pip install -e .
umbralyn --help
```

## 3. Configuration

Copiez la configuration exemple :

```bash
cp config.example.yaml config.yaml
```

Le fichier réel `config.yaml` est ignoré par Git afin d'éviter de versionner une configuration locale.

Exemple :

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

### Variables d'environnement

Les paramètres peuvent être surchargés avec des variables `UMBRALYN_*`.

Principales variables disponibles :

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

Exemple :

```bash
export UMBRALYN_CONFIG=config.yaml
export UMBRALYN_DATABASE_PATH=./data/umbralyn.db
export UMBRALYN_REPORTS_DIR=./reports
export UMBRALYN_TIMEOUT=600
export UMBRALYN_NVD_API_KEY="votre-cle-api"
```

Les variables d'environnement spécifiques ont priorité sur les valeurs définies dans le fichier YAML.

Pour afficher la configuration effectivement chargée :

```bash
python -m umbralyn config --config config.yaml
```

Les valeurs booléennes acceptent notamment :

```text
true / false
yes / no
on / off
1 / 0
```

Le timeout doit être supérieur à `0` et le seuil de risque doit être compris entre `0` et `100`.

## 4. Lancer un scan

### Scan rapide

Par défaut, Umbralyn utilise le mode rapide de Nmap avec `-F`, qui cible les ports TCP les plus courants.

```bash
python -m umbralyn scan 192.168.1.10
```

La détection des services et versions (`-sV`) est activée par défaut.

Le rapport HTML est généré dans `reports/`.

### Scanner un réseau de laboratoire

```bash
python -m umbralyn scan 192.168.1.0/24 --config config.yaml
```

### Scan complet

L'option `--full` désactive le mode rapide `-F` et laisse Nmap utiliser son comportement normal pour l'analyse des ports.

Cette opération peut être nettement plus longue sur une plage réseau.

```bash
python -m umbralyn scan 192.168.1.10 --full
```

### Désactiver la détection de service

```bash
python -m umbralyn scan 192.168.1.10 \
    --no-service-detection
```

Cette option désactive `-sV`.

### Détection de l'OS

```bash
python -m umbralyn scan 192.168.1.10 \
    --os-detection
```

Nmap peut nécessiter des privilèges élevés pour obtenir un résultat fiable.

### Scripts NSE

```bash
python -m umbralyn scan 192.168.1.10 \
    --vuln-scripts
```

Cette option active :

```text
--script vuln
```

Les résultats sont intégrés aux findings du rapport lorsqu'un script signale une condition vulnérable.

Les scripts NSE peuvent générer davantage de trafic et nécessitent donc un périmètre d'utilisation clairement défini.

### Recherche CVE

```bash
python -m umbralyn scan 192.168.1.10 \
    --cve
```

Umbralyn recherche des CVE candidates dans la NVD à partir du produit et de la version détectés.

Une correspondance NVD ne constitue pas automatiquement une vulnérabilité confirmée. Il faut notamment vérifier :

* le produit exact ;
* la version exacte ;
* les versions affectées ;
* le niveau de correctifs ;
* la configuration ;
* les conditions d'exploitation.

En cas d'indisponibilité de la NVD, Umbralyn utilise un petit jeu de données local de démonstration.

### Toutes les options principales

Exemple de scan complet :

```bash
python -m umbralyn scan 192.168.1.10 \
    --full \
    --os-detection \
    --vuln-scripts \
    --cve \
    --save-history \
    --compare \
    --json-out scans/audit-2026-09-17.json \
    --out reports/audit-2026-09-17.html \
    --pdf
```

| Option                   | Effet                                                |
| ------------------------ | ---------------------------------------------------- |
| `--full`                 | Désactive `-F` et effectue un scan plus étendu.      |
| `--no-service-detection` | Désactive `-sV`.                                     |
| `--os-detection`         | Active `-O`.                                         |
| `--vuln-scripts`         | Active les scripts NSE `vuln`.                       |
| `--cve`                  | Recherche les CVE candidates dans la NVD.            |
| `--out`                  | Définit le chemin du rapport HTML.                   |
| `--pdf`                  | Produit également un PDF.                            |
| `--json-out`             | Exporte le résultat au format JSON.                  |
| `--save-history`         | Enregistre le scan dans SQLite.                      |
| `--compare`              | Compare avec le scan précédent de la même cible.     |
| `--config`               | Utilise un fichier YAML de configuration spécifique. |

## 5. Lire le rapport

Un rapport est organisé autour de plusieurs niveaux.

### 1. Synthèse

Présente notamment :

* nombre d'hôtes analysés ;
* nombre d'hôtes actifs ;
* nombre de ports ouverts ;
* nombre de findings ;
* score global.

### 2. Score de risque

Chaque hôte reçoit un score compris entre `0` et `100`.

Le score est calculé à partir des findings et des CVE candidates détectées.

Le calcul est volontairement simple et explicable.

Une exposition à risque, comme un service d'administration exposé, peut contribuer au score sans signifier qu'une vulnérabilité est confirmée.

### 3. Points d'attention

Les findings peuvent correspondre à :

* une exposition réseau à risque ;
* un service historiquement sensible ;
* un résultat de script NSE ;
* une autre condition nécessitant une vérification.

### 4. Détails techniques

Le rapport présente notamment :

* les hôtes ;
* les ports ;
* les protocoles ;
* les services ;
* les produits ;
* les versions ;
* les CVE candidates ;
* les changements entre scans.

## 6. Historique et comparaison

Enregistrer un scan :

```bash
python -m umbralyn scan 192.168.1.10 \
    --save-history
```

Enregistrer et comparer avec le scan précédent :

```bash
python -m umbralyn scan 192.168.1.10 \
    --save-history \
    --compare
```

La base SQLite est stockée par défaut dans :

```text
data/umbralyn.db
```

Afficher l'historique :

```bash
python -m umbralyn history
```

Filtrer sur une cible :

```bash
python -m umbralyn history \
    --target 192.168.1.10
```

Utiliser une configuration spécifique :

```bash
python -m umbralyn history \
    --config config.yaml
```

### Comparaison de deux exports JSON

```bash
python -m umbralyn compare \
    scans/avant.json \
    scans/apres.json
```

Les changements détectés peuvent être :

* nouvel hôte ;
* hôte devenu indisponible ;
* nouveau port ;
* port fermé ;
* service ou bannière modifié.

### Générer un rapport depuis un export

Cette opération ne nécessite pas de nouveau scan réseau :

```bash
python -m umbralyn report \
    scans/apres.json \
    --out reports/apres.html
```

## 7. Surveillance planifiée

Le sous-programme `schedule` effectue automatiquement des scans à intervalle fixe.

Exemple toutes les heures :

```bash
python -m umbralyn schedule \
    192.168.1.10 \
    --interval 3600
```

### Alertes email

Définissez les identifiants SMTP dans l'environnement :

```bash
export UMBRALYN_SMTP_USER="alertes@example.com"
export UMBRALYN_SMTP_PASS="mot-de-passe-application"
```

Puis :

```bash
python -m umbralyn schedule \
    192.168.1.10 \
    --interval 3600 \
    --email-to secops@example.com \
    --smtp-host smtp.example.com
```

Le scheduler :

1. effectue un scan ;
2. l'enregistre dans SQLite ;
3. récupère les deux derniers scans ;
4. compare les résultats ;
5. affiche les changements ;
6. envoie un email si un changement est détecté.

`--interval` est exprimé en secondes :

```text
3600 = 1 heure
1800 = 30 minutes
900  = 15 minutes
```

Pour une utilisation durable, le processus peut être exécuté via `systemd`, un conteneur supervisé ou un ordonnanceur de l'infrastructure.

## 8. Docker

Construire l'image :

```bash
docker build -t umbralyn .
```

Exécuter un scan :

```bash
docker run --rm \
    --network host \
    -v "$(pwd)/data:/app/data" \
    -v "$(pwd)/reports:/app/reports" \
    umbralyn scan 192.168.1.10 --pdf
```

Le montage de :

```text
/app/data
```

permet de conserver la base SQLite entre les conteneurs.

Le montage de :

```text
/app/reports
```

permet de récupérer les rapports générés.

Sous Linux, `--network host` permet à Nmap d'utiliser le réseau de l'hôte.

Cette option modifie l'isolation réseau du conteneur et doit donc être utilisée uniquement dans un environnement maîtrisé.

## 9. Dépannage

| Message / situation        | Résolution                                                                                    |
| -------------------------- | --------------------------------------------------------------------------------------------- |
| `nmap est introuvable`     | Installez Nmap et vérifiez `nmap --version`.                                                  |
| Aucun hôte actif           | Vérifiez la cible, le routage, le VPN, le pare-feu et le périmètre autorisé.                  |
| Le scan dépasse le délai   | Augmentez `UMBRALYN_TIMEOUT` ou `scan.timeout_seconds`.                                       |
| Recherche CVE lente        | Utilisez une clé NVD via `UMBRALYN_NVD_API_KEY`.                                              |
| Recherche CVE indisponible | Vérifiez l'accès Internet ; Umbralyn peut utiliser son repli local.                           |
| Export PDF en erreur       | Vérifiez les dépendances WeasyPrint ou utilisez l'image Docker.                               |
| Base SQLite introuvable    | Vérifiez `UMBRALYN_DATABASE_PATH` et les permissions du répertoire `data/`.                   |
| E-mail non envoyé          | Vérifiez les identifiants SMTP, le port, TLS et les règles du fournisseur.                    |
| Configuration invalide     | Utilisez `python -m umbralyn config --config config.yaml` pour vérifier les valeurs chargées. |

## 10. Tests et mise à jour

Les tests peuvent être exécutés sans effectuer de scan réseau :

```bash
pip install pytest
pytest -q
```

Pour vérifier la compilation Python :

```bash
python -m compileall umbralyn tests
```

Si Ruff est installé :

```bash
ruff check .
```

Avant une mise à jour, conservez vos :

* exports JSON ;
* base SQLite ;
* rapports HTML/PDF.

Les répertoires de données générées sont volontairement ignorés par Git.

## 11. Bonnes pratiques

* Utilisez uniquement des cibles autorisées.
* Testez d'abord Umbralyn dans un laboratoire.
* Ne stockez jamais de secrets dans Git.
* Utilisez `UMBRALYN_NVD_API_KEY` et les identifiants SMTP via des variables d'environnement ou un gestionnaire de secrets.
* Traitez les CVE retournées par recherche de mots-clés comme des candidates.
* Vérifiez les versions et les correctifs avant de conclure à une vulnérabilité.
* Conservez les rapports contenant des informations d'infrastructure dans un emplacement sécurisé.
* Limitez les privilèges du conteneur et les accès réseau lorsque Docker est utilisé.
