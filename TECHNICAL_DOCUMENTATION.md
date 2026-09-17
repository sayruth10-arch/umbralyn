# Umbralyn — Documentation technique

## 1. Vue d’ensemble

Umbralyn est une application Python en ligne de commande dédiée à l’audit réseau défensif. Elle orchestre Nmap, transforme sa sortie XML en modèle interne, analyse les expositions, recherche des CVE candidates, calcule des scores, conserve l’historique et produit des rapports HTML/PDF.

```text
CLI
 │
 ├── Configuration ─────────────────────────────┐
 │                                               │
 ├── Scanner Nmap ──> Parser XML ──> ScanResult │
 │                                  │            │
 ├── Risk analysis <────────────────┤            │
 ├── CVE lookup (NVD/cache) <───────┤            │
 ├── Scoring <──────────────────────┤            │
 ├── SQLite history / comparison <──┤            │
 └── HTML / PDF / JSON reporting <──┘            │
                                                 │
                 YAML + variables UMBRALYN_* <──┘
```

Le projet se concentre sur l’identification et la priorisation. Il ne comprend ni exploitation de vulnérabilité, ni brute force, ni mécanisme de propagation.

Les résultats produits par l’analyse sont des indicateurs destinés à faciliter la priorisation. Ils nécessitent une validation dans le contexte réel avant de considérer une vulnérabilité comme confirmée.

## 2. Arborescence

```text
Umbralyn/
├── umbralyn/
│   ├── __init__.py
│   ├── __main__.py        # CLI et orchestration des commandes
│   ├── config.py          # Chargement YAML / variables d’environnement
│   ├── scanner.py         # Nmap, parsing XML et modèles ScanResult/Host/Port
│   ├── risk_analysis.py   # Findings heuristiques et résultats NSE
│   ├── cve_lookup.py      # NVD, cache local et repli hors ligne
│   ├── scoring.py         # Score transparent par hôte et global
│   ├── history.py         # SQLite, JSON et comparaison de scans
│   ├── report.py          # Rendu Jinja2 et export PDF
│   └── scheduler.py       # Surveillance à intervalle et e-mail SMTP
├── templates/
│   └── report.html        # Présentation du rapport
├── web/
│   ├── index.html         # Interface web de démonstration
│   └── styles.css         # Styles de l'interface
├── tests/                 # Tests sans appel réseau
├── config.example.yaml    # Exemple de configuration
├── .env.example           # Variables d’environnement documentées
├── Dockerfile             # Exécution conteneurisée
├── pyproject.toml         # Métadonnées et outils Python
├── requirements.txt       # Dépendances d’exécution
├── USER_GUIDE.md
└── TECHNICAL_DOCUMENTATION.md
```

## 3. Modèle de données

### `ScanResult`

Représente une exécution Nmap complète : cible, date, durée, arguments et liste des hôtes.

### `Host`

Contient l’adresse IP, le nom, l’état, une hypothèse d’OS et les ports observés. `hosts_up` filtre les hôtes dont l’état est `up`.

### `Port`

Stocke le numéro, le protocole, l’état, le service, le produit, la version et les éventuels résultats de scripts NSE.

La propriété `banner` produit une représentation courte sous la forme `produit version`. Si aucun produit ou aucune version n'est disponible, elle retourne `inconnu`.

### `Finding`

Un finding contient l’hôte, le port, la catégorie ou le service, une description et une sévérité (`high`, `medium`, `info`).

Un finding peut représenter une exposition heuristique à risque ou un résultat NSE signalant une vulnérabilité.

La présence d'un finding heuristique ne signifie donc pas automatiquement qu'une vulnérabilité est confirmée.

### `HostScore`

Le résultat du scoring d’un hôte : valeur entre 0 et 100, grade lisible et détail des contributions au score.

### `DiffEntry`

Décrit un changement entre deux scans :

* `new_host`
* `host_down`
* `new_port`
* `closed_port`
* `service_changed`

## 4. Cycle d’un scan

1. La CLI valide les options et charge la configuration.
2. `scanner.run_scan()` construit la commande Nmap avec une sortie XML standard (`-oX -`).
3. `_parse_nmap_xml()` transforme le XML en objets métier.
4. `risk_analysis.analyze()` génère les findings heuristiques et intègre les résultats NSE signalant une vulnérabilité.
5. Avec `--cve`, `cve_lookup.lookup_cves_for_scan()` interroge la NVD ou le cache local.
6. Avec `--save-history`, `history.save_scan()` persiste l’état dans SQLite.
7. Avec `--compare`, le résultat est comparé au scan historique précédent.
8. `report.save_html()` génère le rapport ; `save_pdf()` ajoute un PDF si demandé.
9. Avec `--json-out`, le résultat Nmap normalisé devient un export portable et réutilisable.
10. Avec `schedule`, le même cycle peut être répété automatiquement à intervalle régulier.

## 5. Scanner et Nmap

Le scanner utilise `subprocess.run()` avec une liste d’arguments et non une chaîne de shell. La cible n’est donc pas interprétée par un shell.

Nmap doit néanmoins être considéré comme un outil puissant ; l’autorisation de scan demeure nécessaire.

Arguments actuellement utilisés :

| Option Umbralyn      | Argument Nmap   | Usage                                         |
| -------------------- | --------------- | --------------------------------------------- |
| par défaut           | `-F`            | Ports courants, plus rapide.                  |
| détection de service | `-sV`           | Produit et version lorsque détectables.       |
| `--os-detection`     | `-O`            | Hypothèse d’OS. Peut requérir des privilèges. |
| `--vuln-scripts`     | `--script vuln` | Vérifications NSE défensives.                 |
| toujours             | `-oX -`         | XML envoyé sur la sortie standard.            |

Le délai maximal de Nmap est défini par `scan.timeout_seconds` dans la configuration et transmis au scanner sous la forme du paramètre `timeout`.

Une expiration est convertie en `ScanError` et affichée proprement par la CLI.

## 6. Analyse et score de risque

`risk_analysis.py` réalise une analyse heuristique des services exposés.

Certains ports sont considérés comme nécessitant une attention particulière, notamment :

* Telnet ;
* SMB ;
* RDP ;
* Redis ;
* VNC ;
* services de bases de données exposés ;
* certains protocoles historiquement non chiffrés.

Cette détection constitue une **indication d'exposition ou de configuration potentiellement risquée**, et non une preuve automatique de vulnérabilité.

Une sortie NSE contenant `VULNERABLE` produit un finding distinct de sévérité `high`. Le résultat doit néanmoins être vérifié dans le contexte du service et de sa configuration.

### Pondérations

`scoring.py` utilise des pondérations visibles :

| Élément                  | Poids |
| ------------------------ | ----: |
| Finding `high`           |   +30 |
| Finding `medium`         |   +15 |
| Finding `info`           |    +5 |
| CVE `critical` candidate |   +35 |
| CVE `high` candidate     |   +25 |
| CVE `medium` candidate   |   +12 |
| CVE `low` candidate      |    +4 |

Le score par hôte est plafonné à 100.

Les grades sont :

|  Score | Grade                |
| -----: | -------------------- |
|      0 | Aucun risque détecté |
|   1–19 | Faible               |
|  20–44 | Modéré               |
|  45–74 | Élevé                |
| 75–100 | Critique             |

Le score global est calculé avec :

* 70 % du score du pire hôte ;
* 30 % de la moyenne des scores des hôtes actifs.

Le résultat est ensuite arrondi.

Ce système est volontairement simple, explicable et modifiable directement dans `scoring.py`.

### Limites du scoring

Le score ne constitue pas une mesure absolue de la sécurité d'une infrastructure.

Plusieurs findings ou CVE peuvent rapidement faire progresser le score jusqu'au plafond de 100. Le score doit donc principalement être utilisé comme **indicateur de priorisation** et non comme mesure quantitative exacte du risque.

## 7. CVE, NVD et cache

`cve_lookup.py` applique cet ordre :

1. lecture du cache local `~/.umbralyn_cve_cache.json` ;
2. si aucune entrée valide n'est disponible, requête HTTPS vers la NVD ;
3. si NVD est indisponible, utilisation du petit repli local de démonstration.

Le cache est conservé pendant sept jours.

La recherche NVD utilise actuellement `keywordSearch` avec le produit et la version détectés par Nmap.

La variable `UMBRALYN_NVD_API_KEY` peut être utilisée pour fournir une clé API NVD via l'en-tête `apiKey`.

Sans clé API, Umbralyn espace les requêtes afin de respecter les limites de l'API.

### Limite de corrélation

La recherche actuelle par mots-clés peut produire des correspondances trop larges.

Une CVE retournée par cette recherche doit donc être considérée comme **candidate** tant qu'une vérification plus précise n'a pas confirmé :

* le produit exact ;
* la version exacte ;
* les versions affectées ;
* les conditions d'exploitation ;
* le contexte de configuration.

Une évolution importante du projet consiste à utiliser les CPE afin d'améliorer cette corrélation.

Aucune clé API ne doit être écrite dans le dépôt Git ou dans un rapport.

## 8. Persistance et format JSON

SQLite contient actuellement une table `scans` comprenant :

* un identifiant ;
* la cible ;
* la date de début ;
* la durée ;
* le document JSON complet du scan.

Le chemin par défaut est :

```text
data/umbralyn.db
```

Il peut être modifié avec `database.path` dans la configuration ou avec :

```text
UMBRALYN_DATABASE_PATH
```

Le format JSON contient les données normalisées :

* cible ;
* date ;
* durée ;
* arguments Nmap ;
* hôtes ;
* ports ;
* résultats NSE.

Les fonctions principales sont :

* `scan_to_dict(scan)` / `scan_from_dict(data)` ;
* `save_scan_json(scan, path)` / `load_scan_json(path)` ;
* `save_scan(scan, db_path)` ;
* `get_scan(scan_id, db_path)` ;
* `list_scans(target, db_path)` ;
* `compare_scans(old, new)`.

La comparaison distingue le numéro **et le protocole** du port. Ainsi, `80/tcp` et `80/udp` sont considérés comme deux services différents.

Les exports JSON peuvent être utilisés pour l'archivage, la comparaison ou la génération de rapports hors ligne.

## 9. Rapports

`report.py` utilise Jinja2 avec auto-échappement HTML.

Le template reçoit notamment :

* les résultats du scan ;
* les findings ;
* les CVE candidates ;
* les scores ;
* le résumé ;
* les différences entre scans.

Le PDF est généré par WeasyPrint à partir du HTML.

Le rapport privilégie une synthèse comprenant :

* le volume d'actifs ;
* les ports exposés ;
* les findings ;
* les CVE candidates ;
* le score global ;
* les changements détectés.

Les détails techniques restent disponibles au niveau de chaque hôte.

## 10. Planification et alertes

`scheduler.run_loop()` appelle régulièrement `run_once()`.

Chaque itération :

1. effectue un scan ;
2. l'enregistre dans SQLite ;
3. récupère les deux derniers scans de la cible ;
4. compare les deux résultats ;
5. affiche les changements détectés ;
6. envoie un e-mail texte si un changement existe et qu'une configuration SMTP est fournie.

Les secrets SMTP sont lus depuis :

```text
UMBRALYN_SMTP_USER
UMBRALYN_SMTP_PASS
```

Le scheduler peut également reprendre les paramètres de scan définis dans la configuration :

* détection de service ;
* détection d'OS ;
* scripts NSE ;
* timeout ;
* chemin de la base SQLite.

Pour une utilisation durable, l'exécution peut être confiée à systemd, cron ou une plateforme de conteneurs.

## 11. Configuration et précédence

La configuration est chargée par `config.load_config()`.

Les valeurs sont évaluées dans cet ordre :

1. valeurs par défaut définies dans `config.py` ;
2. fichier YAML (`config.yaml` ou chemin fourni par `UMBRALYN_CONFIG`) ;
3. variables d'environnement spécifiques.

Les variables spécifiques disponibles comprennent notamment :

```text
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

Les valeurs booléennes sont validées explicitement. Les valeurs acceptées sont notamment :

```text
true / false
yes / no
on / off
1 / 0
```

Le timeout doit être strictement positif.

Le seuil d'alerte doit être compris entre 0 et 100.

Ne commitez jamais de secrets dans `config.yaml`, `.env` ou le dépôt Git.

## 12. Docker

L'image dérive de `python:3.12-slim`.

Elle installe :

* Nmap ;
* Python et les dépendances Umbralyn ;
* les bibliothèques nécessaires à WeasyPrint.

Le point d'entrée du conteneur est :

```text
python -m umbralyn
```

Les données persistantes doivent être montées depuis l'hôte, notamment :

```text
/app/data
/app/reports
```

Exemple :

```bash
docker run --rm \
    --network host \
    -v "$(pwd)/data:/app/data" \
    -v "$(pwd)/reports:/app/reports" \
    umbralyn scan 192.168.1.0/24 --pdf
```

`--network host` donne au conteneur une visibilité réseau correspondant à celle de l'hôte sous Linux.

Le conteneurisation n'est pas une frontière de sécurité complète. Le périmètre réseau et les privilèges accordés au conteneur doivent rester maîtrisés.

## 13. Tests et qualité

Les tests actuels couvrent notamment :

* l'aller-retour de la sérialisation JSON ;
* la conservation des résultats NSE ;
* la détection d'un nouveau port ;
* le plafonnement du score à 100 ;
* la génération du détail explicatif du score.

Exécution :

```bash
pip install pytest
pytest -q
```

Les vérifications recommandées avant une contribution sont :

```bash
python -m compileall umbralyn tests
ruff check .
pytest -q
```

Les tests ne nécessitent pas de scan réseau réel.

Les prochaines extensions de tests devraient notamment couvrir :

* le parsing XML Nmap ;
* la validation de la configuration ;
* le comportement du cache CVE ;
* le scheduler ;
* la distinction TCP/UDP lors des comparaisons.

## 14. Évolutions recommandées

Les principales évolutions techniques envisagées sont :

1. ajouter des fixtures XML Nmap pour tester le parsing sans effectuer de scan réel ;
2. améliorer la corrélation CVE avec les CPE et un niveau de confiance ;
3. ajouter davantage de tests automatisés pour la configuration et le scheduler ;
4. persister les findings et CVE dans des tables SQLite normalisées ;
5. ajouter une abstraction de dépôt afin de préparer une éventuelle migration vers PostgreSQL ;
6. ajouter une interface web pour consulter l'historique et les rapports ;
7. ajouter des canaux d'alerte supplémentaires comme les webhooks ;
8. ajouter un export SARIF pour faciliter l'intégration CI/CD ;
9. créer un environnement Docker Compose dédié au laboratoire ;
10. étudier une intégration optionnelle avec Wazuh pour enrichir la supervision.

## 15. Sécurité de développement

* Ne mettez ni clés NVD, ni identifiants SMTP, ni exports d'infrastructure dans Git.
* Utilisez des cibles de laboratoire ou disposez d'une autorisation explicite avant tout scan.
* N'interprétez pas un résultat de bannière ou une CVE candidate comme une vulnérabilité automatiquement confirmée.
* Vérifiez le produit, la version, le niveau de correctifs et la configuration avant toute conclusion.
* Maintenez Nmap, les dépendances Python et l'image Docker à jour.
* Limitez les privilèges accordés aux conteneurs et aux comptes utilisés pour les scans.
* Conservez les rapports et exports contenant des informations d'infrastructure dans des emplacements appropriés.
