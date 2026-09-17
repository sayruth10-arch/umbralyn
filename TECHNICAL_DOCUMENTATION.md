# Umbralyn — Documentation technique

## 1. Vue d’ensemble

Umbralyn est une application Python en ligne de commande dédiée à l’audit réseau défensif. Elle orchestre Nmap, transforme sa sortie XML en modèle interne, analyse les expositions, recherche des CVE candidates, calcule des scores, conserve l’historique et produit des rapports HTML/PDF.

```text
CLI
 │
 ├── Scanner Nmap ──> Parser XML ──> ScanResult
 │                                  │
 ├── Risk analysis <────────────────┤
 ├── CVE lookup (NVD/cache) <───────┤
 ├── Scoring <──────────────────────┤
 ├── SQLite history / comparison <──┤
 └── HTML / PDF / JSON reporting <──┘
```

Le projet se concentre sur l’identification et la priorisation. Il ne comprend ni exploitation de vulnérabilité, ni brute force, ni mécanisme de propagation.

## 2. Arborescence

```text
Umbralyn/
├── umbralyn/
│   ├── __main__.py        # CLI et orchestration des commandes
│   ├── config.py          # Chargement YAML / variables d’environnement
│   ├── scanner.py         # Nmap, parsing XML et modèles ScanResult/Host/Port
│   ├── risk_analysis.py   # Findings heuristiques et résultats NSE
│   ├── cve_lookup.py      # NVD, cache local et repli hors ligne
│   ├── scoring.py         # Score transparent par hôte et global
│   ├── history.py         # SQLite, JSON et comparaison de scans
│   ├── report.py          # Rendu Jinja2 et export PDF
│   └── scheduler.py       # Surveillance à intervalle et e-mail SMTP
├── templates/report.html  # Présentation du rapport
├── tests/                 # Tests sans appel réseau
├── config.example.yaml    # Exemple de configuration
├── .env.example           # Variables sensibles documentées
├── Dockerfile             # Exécution conteneurisée
├── pyproject.toml         # Métadonnées et outils Python
└── requirements.txt       # Dépendances d’exécution
```

## 3. Modèle de données

### `ScanResult`

Représente une exécution Nmap complète : cible, date, durée, arguments et liste des hôtes.

### `Host`

Contient l’adresse IP, le nom, l’état, une hypothèse d’OS et les ports observés. `hosts_up` filtre les hôtes dont l’état est `up`.

### `Port`

Stocke numéro, protocole, état, service, produit, version et éventuels résultats de scripts NSE. La propriété `banner` produit une représentation courte `produit version`.

### `Finding`

Un finding contient l’hôte, le port, la catégorie/service, une description et une sévérité (`high`, `medium`, `info`). Il est la base du score et du rapport.

### `HostScore`

Le résultat du scoring d’un hôte : valeur entre 0 et 100, grade lisible et détail des contributions.

### `DiffEntry`

Décrit un changement entre deux scans : `new_host`, `host_down`, `new_port`, `closed_port` ou `service_changed`.

## 4. Cycle d’un scan

1. La CLI valide les options et charge la configuration.
2. `scanner.run_scan()` construit la commande Nmap avec une sortie XML standard (`-oX -`).
3. `_parse_nmap_xml()` transforme le XML en objets métier.
4. `risk_analysis.analyze()` génère des findings heuristiques et intègre les résultats NSE marqués vulnérables.
5. Avec `--cve`, `cve_lookup.lookup_cves_for_scan()` interroge la NVD ou le cache local.
6. Avec `--save-history`, `history.save_scan()` persiste l’état dans SQLite.
7. Avec `--compare`, le résultat est comparé au scan historique précédent.
8. `report.save_html()` génère le rapport ; `save_pdf()` ajoute un PDF si demandé.
9. Avec `--json-out`, le résultat Nmap normalisé devient un export portable et rejouable.

## 5. Scanner et Nmap

Le scanner utilise `subprocess.run()` avec une liste d’arguments, et non une chaîne de shell : la cible n’est donc pas interprétée par un shell. Nmap doit néanmoins être considéré comme un outil puissant ; l’autorisation de scan demeure nécessaire.

Arguments actuellement utilisés :

| Option Umbralyn | Argument Nmap | Usage |
| --- | --- | --- |
| par défaut | `-F` | Ports courants, plus rapide. |
| détection de service | `-sV` | Produit et version lorsque détectables. |
| `--os-detection` | `-O` | Hypothèse d’OS. Peut requérir des privilèges. |
| `--vuln-scripts` | `--script vuln` | Vérifications NSE défensives. |
| toujours | `-oX -` | XML envoyé sur la sortie standard. |

Le délai maximal de Nmap provient de `scan.timeout_seconds`. Une expiration devient une `ScanError` proprement affichée par la CLI.

## 6. Analyse et score de risque

`risk_analysis.py` n’affirme pas automatiquement qu’un service est vulnérable. Il repère des services qui méritent une vérification : Telnet, SMB, RDP, Redis, bases de données exposées, etc. Une sortie NSE contenant `VULNERABLE` produit un finding distinct.

`scoring.py` utilise des pondérations visibles :

| Élément | Poids |
| --- | ---: |
| Finding `high` | +30 |
| Finding `medium` | +15 |
| Finding `info` | +5 |
| CVE `critical` candidate | +35 |
| CVE `high` candidate | +25 |
| CVE `medium` candidate | +12 |
| CVE `low` candidate | +4 |

Le score par hôte est plafonné à 100. Le score global est `70 %` du pire score plus `30 %` de la moyenne, puis arrondi. C’est volontairement simple, explicable et modifiable dans `scoring.py`.

Limite importante : la correspondance CVE par mot-clé produit/version est probabiliste. Les rapports doivent être traités comme une liste de priorités à valider, par exemple à l’aide du CPE exact, de l’état de correctif et du contexte d’exposition.

## 7. CVE, NVD et cache

`cve_lookup.py` applique cet ordre :

1. lecture du cache `~/.umbralyn_cve_cache.json`, valable sept jours ;
2. requête HTTPS NVD avec `keywordSearch` ;
3. petit repli local de démonstration si NVD est indisponible.

La variable `UMBRALYN_NVD_API_KEY` est transmise dans l’en-tête `apiKey` et accélère les requêtes. Sans clé, l’outil attend entre les appels pour respecter les limites NVD. Aucune clé ne doit être écrite dans YAML, Git ou un rapport.

## 8. Persistance et format JSON

SQLite contient une table `scans` : identifiant, cible, date de départ, durée et document JSON complet. Le chemin se configure avec `database.path` ou `UMBRALYN_DATABASE_PATH`.

Le format JSON contient les données normalisées : cible, date, durée, arguments, hôtes, ports et résultats NSE. Les fonctions publiques sont :

- `scan_to_dict(scan)` / `scan_from_dict(data)` ;
- `save_scan_json(scan, path)` / `load_scan_json(path)` ;
- `save_scan(scan, db_path)` ;
- `compare_scans(old, new)`.

Les exports JSON sont adaptés aux pipelines CI, à l’archivage et à la génération de rapports hors ligne.

## 9. Rapports

`report.py` utilise Jinja2 avec auto-échappement HTML. Le template reçoit les résultats brut, les findings, les CVE, les scores, le résumé et les différences. Le PDF est généré par WeasyPrint à partir du HTML.

Le template privilégie une synthèse exécutive : volume d’actifs, expositions, score global et changements. Chaque hôte conserve ensuite ses détails techniques.

## 10. Planification et alertes

`scheduler.run_loop()` appelle régulièrement `run_once()`. Chaque itération :

1. effectue un scan ;
2. l’enregistre dans SQLite ;
3. charge les deux derniers états ;
4. les compare ;
5. envoie un e-mail texte si un diff existe et qu’une configuration SMTP est fournie.

Les secrets SMTP sont lus uniquement depuis `UMBRALYN_SMTP_USER` et `UMBRALYN_SMTP_PASS`. Pour la production, il est recommandé de déléguer l’exécution à systemd, un ordonnanceur ou une plateforme de conteneurs et d’injecter les secrets via son gestionnaire dédié.

## 11. Configuration et précédence

Les sources sont évaluées dans cet ordre, la dernière valeur gagnant :

1. valeurs par défaut dans `config.py` ;
2. `config.yaml` ou chemin précisé par `UMBRALYN_CONFIG` ;
3. variables spécifiques telles que `UMBRALYN_DATABASE_PATH`, `UMBRALYN_REPORTS_DIR`, `UMBRALYN_TIMEOUT` et `UMBRALYN_ALERT_THRESHOLD`.

Ne commitez jamais `config.yaml` s’il contient une cible interne ou une adresse e-mail.

## 12. Docker

L’image dérive de `python:3.12-slim`, installe Nmap et les bibliothèques nécessaires à WeasyPrint, puis lance `python -m umbralyn` comme point d’entrée.

Le conteneur est une facilité de packaging, pas une frontière de sécurité complète. `--network host` donne à Nmap la visibilité réseau de l’hôte sous Linux ; limitez-le à des environnements contrôlés et documentez le périmètre.

## 13. Tests et qualité

Les tests actuels couvrent :

- aller-retour de la sérialisation JSON ;
- conservation des résultats NSE ;
- détection d’un nouveau port ;
- plafond et explication du score.

Exécution :

```bash
pip install pytest
pytest -q
```

Les vérifications recommandées avant une contribution :

```bash
python -m compileall umbralyn tests
ruff check .
pytest -q
```

## 14. Évolutions recommandées

Les priorités techniques suivantes renforceraient le produit :

1. ajouter des fixtures XML Nmap et des tests de parsing ;
2. remplacer le rapprochement CVE par mots-clés par une résolution CPE avec score de confiance ;
3. persister findings et CVE dans des tables normalisées pour des requêtes historiques plus fines ;
4. extraire une abstraction de dépôt pour préparer PostgreSQL ;
5. ajouter des canaux d’alerte webhook, Teams et Slack derrière une interface commune ;
6. ajouter une authentification/API ou une interface web légère pour visualiser l’historique ;
7. créer un fichier `docker-compose.yml` de laboratoire, sans inclure de cible réelle ni de secret.

## 15. Sécurité de développement

- Ne mettez ni clés NVD, ni identifiants SMTP, ni exports d’infrastructure dans Git.
- Utilisez des cibles de laboratoire et conservez la preuve d’autorisation pour les environnements clients.
- N’interprétez pas un résultat de bannière ou une CVE candidate comme une vulnérabilité prouvée.
- Vérifiez les faux positifs, le niveau de patch et l’exposition effective avant toute escalade.
- Maintenez les dépendances, Nmap et l’image Docker à jour.
