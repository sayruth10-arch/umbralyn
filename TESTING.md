# Rapport de tests et de validation — UMBRALYN

**Projet :** UMBRALYN — Automated Network Security Auditing
**Version :** 0.2.0
**Environnement de test :** macOS 26.2 — Apple Silicon
**Date des tests :** 17 septembre 2026
**Dépôt :** GitHub — `sayruth10-arch/umbralyn`
**Branche :** `main`

---

# 1. Objectif du rapport

Ce document présente l'ensemble des tests réalisés sur le projet **UMBRALYN** après les corrections du code.

L'objectif était de vérifier que l'application pouvait :

* être installée dans un environnement Python isolé ;
* charger correctement ses dépendances ;
* être installée comme package Python ;
* exécuter sa CLI ;
* lancer un scan Nmap réel ;
* détecter les services et versions ;
* exécuter des scripts NSE ;
* rechercher des CVE ;
* intégrer les CVE au calcul de risque ;
* générer des rapports HTML ;
* exporter les résultats en JSON ;
* sauvegarder les scans dans SQLite ;
* comparer plusieurs scans ;
* charger correctement sa configuration ;
* exécuter sa suite de tests automatisés ;
* fonctionner correctement avec Git/GitHub.

Les tests ont également permis de vérifier les corrections effectuées après l'audit initial du projet.

---

# 2. Environnement utilisé

## 2.1 Système

Le projet a été testé sur :

* **macOS 26.2 (Tahoe)**
* Apple Silicon
* Homebrew installé
* Nmap installé via Homebrew
* Python 3.12 utilisé pour le projet
* `uv` utilisé pour la gestion de l'environnement Python

Le Python système macOS était en version 3.9.6.

Les versions Homebrew disponibles comprenaient notamment Python 3.12 et Python 3.13.

---

# 3. Problème rencontré avec Python macOS

Lors de la création classique d'un environnement virtuel avec Python Homebrew, un problème spécifique à l'environnement Python/macOS a été rencontré.

La commande classique :

```bash
python3.12 -m venv .venv
```

ne fonctionnait pas correctement.

Le problème était lié à `platform.mac_ver()`, qui retournait une information macOS vide :

```python
platform.mac_ver()
```

avec un résultat de type :

```text
('', ('', '', ''), '')
```

Cela provoquait notamment des erreurs de type :

```text
ValueError: invalid literal for int() with base 10: ''
```

Le problème apparaissait également lors de certaines opérations `pip`/`ensurepip`.

---

# 4. Création de l'environnement virtuel

Une première tentative avec le chemin direct vers le Python Homebrew a également rencontré ce problème.

La solution retenue a été d'utiliser `uv` avec la version Python demandée :

```bash
uv venv --python 3.12 .venv
```

Cette commande a fonctionné.

L'environnement virtuel a ensuite été activé :

```bash
source .venv/bin/activate
```

Le terminal affichait alors :

```text
(.venv)
```

confirmant que l'environnement virtuel était actif.

---

# 5. Installation des dépendances

Le projet utilise notamment :

* Jinja2
* WeasyPrint
* Requests
* PyYAML

Les dépendances ont été installées avec :

```bash
uv pip install -r requirements.txt
```

Les outils de test ont ensuite été installés :

```bash
uv pip install pytest
```

La commande :

```bash
uv pip list
```

a permis de vérifier la présence des dépendances nécessaires.

---

# 6. Installation du projet comme package

Une première tentative avec :

```bash
uv pip install -e .
```

a rencontré un problème de découverte des packages Python.

Setuptools détectait plusieurs répertoires de premier niveau, notamment :

```text
web
reports
umbralyn
templates
```

alors que le package Python principal est :

```text
umbralyn/
```

La configuration suivante a donc été ajoutée dans `pyproject.toml` :

```toml
[tool.setuptools.packages.find]
include = ["umbralyn*"]
```

Après cette correction, la commande :

```bash
uv pip install -e .
```

a fonctionné.

Résultat :

```text
Built umbralyn @ file:///Users/.../umbralyn
Installed 1 package
+ umbralyn==0.2.0
```

Le package UMBRALYN est donc correctement installable dans l'environnement virtuel.

---

# 7. Suite de tests automatisés

La suite de tests a été exécutée avec :

```bash
pytest -q
```

Résultat final :

```text
7 passed
```

Les tests couvrent notamment :

* la configuration ;
* les variables d'environnement ;
* la validation des paramètres ;
* la sérialisation des scans ;
* la conservation des résultats NSE ;
* la comparaison de scans ;
* le plafonnement du score de risque.

---

# 8. Tests de configuration

Un fichier de test supplémentaire a été créé :

```text
tests/test_config.py
```

Il contient notamment quatre tests.

## 8.1 Configuration par défaut

Le test vérifie notamment :

```text
target_network = None
timeout = 600
service_detection = True
os_detection = False
nse = False
alert_threshold = 70
database = data/umbralyn.db
reports = reports
```

Le test est passé.

---

## 8.2 Variables d'environnement

Les variables suivantes ont été testées :

```text
UMBRALYN_TARGET
UMBRALYN_TIMEOUT
UMBRALYN_NSE
UMBRALYN_OS_DETECTION
UMBRALYN_ALERT_THRESHOLD
```

Exemple :

```text
UMBRALYN_TARGET=192.168.1.0/24
UMBRALYN_TIMEOUT=300
UMBRALYN_NSE=true
UMBRALYN_OS_DETECTION=true
UMBRALYN_ALERT_THRESHOLD=80
```

Le chargement et la surcharge de configuration fonctionnent correctement.

---

## 8.3 Validation du timeout

Une valeur invalide :

```text
UMBRALYN_TIMEOUT=0
```

a correctement provoqué une `ValueError`.

Le système refuse donc un timeout inférieur ou égal à zéro.

---

## 8.4 Validation des booléens

Une valeur invalide :

```text
UMBRALYN_NSE=maybe
```

a correctement provoqué une `ValueError`.

Les valeurs booléennes sont donc validées.

---

# 9. Test de la CLI

La commande :

```bash
python -m umbralyn --help
```

a fonctionné.

Les commandes principales disponibles sont :

```text
scan
compare
history
report
config
schedule
```

Cela confirme que l'interface en ligne de commande est correctement accessible.

---

# 10. Test de la commande `config`

La commande :

```bash
python -m umbralyn config
```

a retourné :

```text
Base de données : data/umbralyn.db
Rapports : reports
Cible : non définie
Détection de service : True
Détection d'OS : False
Scripts NSE : False
Timeout : 600s
Seuil d'alerte : 70
```

Ce test confirme que :

* la configuration est correctement chargée ;
* les valeurs par défaut sont correctes ;
* le chemin SQLite est cohérent ;
* les paramètres Nmap sont correctement exposés.

---

# 11. Vérification de Nmap

La présence de Nmap a été vérifiée avec :

```bash
nmap --version
```

Résultat :

```text
Nmap version 7.991
Platform: arm-apple-darwin25.6.0
```

Nmap est donc correctement installé et accessible depuis le système.

---

# 12. Test de scan réel

Un premier scan réel a été effectué contre :

```text
127.0.0.1
```

Commande :

```bash
python -m umbralyn scan 127.0.0.1
```

Résultat :

```text
[*] Lancement du scan sur 127.0.0.1 ...
[*] 1/1 hôte(s) actif(s), 1 port(s) ouvert(s)
[*] 0 alerte(s) critique(s), 0 alerte(s) moyenne(s)
[+] Rapport HTML : reports/127.0.0.1.html
```

Ce test valide simultanément :

* le lancement de Nmap ;
* l'exécution du scanner ;
* le parsing XML ;
* la détection de l'hôte ;
* la détection des ports ;
* l'analyse des résultats ;
* la génération du rapport HTML.

---

# 13. Test de détection des services

Un scan avec détection de version a été réalisé :

```bash
python -m umbralyn scan 127.0.0.1 --json-out reports/services.json
```

Les arguments Nmap enregistrés dans le JSON étaient :

```text
nmap -oX - -F -sV 127.0.0.1
```

Le paramètre :

```text
-sV
```

confirme que la détection de services/version est bien activée.

Le port détecté était notamment :

```text
5000/tcp
```

avec un service identifié comme :

```text
rtsp
```

Dans ce cas précis, Nmap n'a pas fourni de produit/version précis.

Cela ne constitue pas un bug UMBRALYN : Nmap ne peut pas toujours identifier précisément le produit et sa version lorsqu'un service ne fournit pas suffisamment d'informations.

---

# 14. Test de l'export JSON

La commande :

```bash
python -m umbralyn scan 127.0.0.1 --json-out reports/test.json
```

a fonctionné.

Le fichier JSON a été généré correctement.

La structure conserve notamment :

* la cible ;
* la date du scan ;
* la durée ;
* les hôtes ;
* les ports ;
* les services ;
* les informations NSE ;
* les arguments Nmap.

---

# 15. Test de comparaison de scans

Deux fichiers JSON identiques ont été comparés :

```bash
python -m umbralyn compare reports/test.json reports/test2.json
```

Résultat :

```text
Aucun changement détecté.
```

Ce comportement est attendu lorsqu'aucune modification n'existe entre deux scans.

---

# 16. Test de comparaison avec nouveau port

La suite de tests contient également :

```python
test_compare_detects_new_port()
```

Le test compare :

```text
80
```

avec :

```text
80, 443
```

et vérifie qu'un événement :

```text
new_port
```

est détecté.

Le test est passé.

La comparaison des ports prend désormais en compte :

```text
(number, protocol)
```

et non simplement le numéro du port.

Cela permet notamment de distinguer correctement :

```text
53/tcp
53/udp
```

---

# 17. Test de l'historique SQLite

Un scan a été sauvegardé avec :

```bash
python -m umbralyn scan 127.0.0.1 --save-history
```

Résultat :

```text
[+] Scan sauvegardé dans l'historique.
```

La commande :

```bash
python -m umbralyn history
```

a ensuite retourné notamment :

```text
#1  2026-09-17T15:43:04.720812  127.0.0.1
```

Le système d'historique SQLite fonctionne donc correctement.

Le fichier utilisé est :

```text
data/umbralyn.db
```

Il s'agit d'une base SQLite et non d'un programme exécutable.

---

# 18. Test de `--compare` avec l'historique

La commande :

```bash
python -m umbralyn scan 127.0.0.1 --compare
```

a fonctionné.

Résultat :

```text
[+] Scan sauvegardé dans l'historique.
[*] 0 changement(s) depuis le scan précédent.
```

Ce test confirme l'intégration entre :

* scanner ;
* historique SQLite ;
* comparaison des scans.

---

# 19. Test des scripts NSE

Un scan avec les scripts de vulnérabilité Nmap a été réalisé :

```bash
python -m umbralyn scan 127.0.0.1 --vuln-scripts --json-out reports/nse.json
```

Les arguments Nmap étaient :

```text
nmap -oX - -F -sV --script vuln 127.0.0.1
```

Les résultats NSE ont été correctement récupérés dans :

```text
script_findings
```

Le test a notamment fait apparaître une information de fingerprint AirTunes.

Important : une sortie NSE ou un fingerprint ne signifie pas automatiquement qu'une machine est vulnérable.

UMBRALYN présente ces résultats comme des éléments nécessitant une vérification, et non comme une preuve absolue de compromission ou de vulnérabilité.

---

# 20. Test du système CVE

La fonctionnalité CVE est accessible avec :

```bash
python -m umbralyn scan 127.0.0.1 --cve
```

Le système utilise l'API NVD lorsqu'elle est disponible.

Une clé API peut être fournie via :

```text
UMBRALYN_NVD_API_KEY
```

La fonctionnalité comprend également :

* un cache local ;
* un TTL de 7 jours ;
* un délai entre les requêtes sans clé API ;
* un fallback offline.

---

# 21. Test CVE sur un service réel sans version identifiable

La commande :

```bash
python -m umbralyn scan 127.0.0.1 --cve --json-out reports/cve.json
```

a fonctionné.

Aucune CVE n'a été retournée dans ce cas.

La raison est que le service identifié ne fournissait pas suffisamment d'informations produit/version pour permettre une corrélation utile.

Ce comportement est cohérent avec le fonctionnement actuel du moteur CVE.

---

# 22. Test du moteur CVE offline

Afin de tester réellement la logique CVE sans dépendre de l'API NVD, un hôte synthétique a été créé avec :

```text
Produit : apache
Version : 2.4.49
Port : 80/tcp
```

Le lookup offline a retourné :

```text
CVE-2021-41773
Severity : critical
```

avec un résumé concernant une vulnérabilité de traversée de répertoire.

Ce test confirme que le moteur offline fonctionne.

---

# 23. Validation du lien CVE → scoring

Le même scénario Apache 2.4.49 a ensuite été envoyé au moteur de scoring.

Résultat :

```text
CVEs:
CVE-2021-41773 (critical)

Score:
35

Grade:
Modéré
```

Le breakdown indiquait :

```text
CVE-2021-41773 (critical) sur 192.0.2.10:80 : +35
```

Cela confirme que les candidats CVE sont bien intégrés au calcul du score.

---

# 24. Système de scoring

Le système de scoring utilise notamment :

```text
high finding = +30
medium finding = +15
info finding = +5
```

Pour les CVE :

```text
critical = +35
high = +25
medium = +12
low = +4
```

Le score est plafonné à :

```text
100
```

Un test a été réalisé avec quatre findings `high` sur le port Telnet.

Le résultat était :

```text
Score = 100
```

Le breakdown contenait quatre éléments.

Le plafonnement fonctionne donc correctement.

---

# 25. Interprétation du score global

Le score global UMBRALYN utilise :

```text
70 % du pire hôte
30 % de la moyenne des hôtes
```

Par exemple, pour :

```text
20
45
80
30
```

le pire hôte vaut :

```text
80
```

et la moyenne :

```text
43,75
```

Le score global serait :

```text
69,125
```

Cette formule constitue une **méthode interne à UMBRALYN** et ne doit pas être présentée comme une norme universelle de cybersécurité.

Le score est un indicateur permettant de prioriser les éléments à examiner.

---

# 26. Test de génération du rapport HTML

La génération HTML a été testée sur un scan réel :

```text
reports/127.0.0.1.html
```

Le rapport contient notamment :

* cible ;
* date ;
* nombre d'hôtes ;
* nombre de ports ;
* services ;
* résultats d'analyse ;
* score ;
* grade ;
* informations CVE lorsqu'elles sont disponibles.

La génération fonctionne correctement.

---

# 27. Test d'affichage des CVE dans le rapport

Un scénario synthétique Apache 2.4.49 a été utilisé pour produire :

```text
reports/cve-test.html
```

Le rapport affichait :

```text
CVE-2021-41773
```

ainsi que :

```text
Apache 2.4.49
```

et le score :

```text
35/100
```

Le grade affiché était :

```text
Modéré
```

La présence des CVE dans les détails de l'hôte a donc été validée.

---

# 28. Correction du message du rapport

Lors du test du rapport CVE, un problème de présentation a été identifié.

Lorsque :

```text
findings = []
```

mais que des CVE étaient présentes, le rapport affichait auparavant :

```text
Aucun service à risque connu détecté sur les ports scannés.
```

Cette formulation pouvait laisser penser qu'aucun problème n'était présent alors que des CVE étaient affichées plus bas.

Le template :

```text
templates/report.html
```

a été corrigé.

Le comportement est maintenant :

### Avec CVE

```text
Aucun service à risque connu détecté sur les ports scannés.
Des CVE associées aux services identifiés sont détaillées ci-dessous.
```

### Sans findings ni CVE

```text
Aucun service à risque connu ni aucune CVE associée détectée sur les ports scannés.
```

---

# 29. Validation de la correction du rapport

Après modification du template, le rapport a été régénéré.

Commande de vérification :

```bash
grep -n "Des CVE associées" reports/cve-test.html
```

Résultat :

```text
131:<p class="no-findings">Aucun service à risque connu détecté sur les ports scannés. Des CVE associées aux services identifiés sont détaillées ci-dessous.</p>
```

La correction est donc validée.

---

# 30. Tests de sérialisation

Le fichier :

```text
tests/test_history.py
```

teste la conversion :

```text
ScanResult
    ↓
dict
    ↓
ScanResult
```

Le test vérifie notamment que les résultats NSE sont conservés.

Exemple :

```text
http-test: safe result
```

Le résultat est correctement conservé après sérialisation/désérialisation.

---

# 31. Test de conservation des résultats NSE

Le test :

```python
test_scan_round_trip_preserves_ports_and_scripts()
```

confirme que :

```text
script_findings
```

est conservé après conversion JSON/dictionnaire puis reconstruction du scan.

Le test est passé.

---

# 32. Vérification du package et de la CLI après installation

Après installation editable :

```bash
uv pip install -e .
```

la commande :

```bash
python -m umbralyn --help
```

fonctionne.

Cela confirme que la structure du package et les imports sont cohérents.

---

# 33. Vérification des options de scan

La commande :

```bash
python -m umbralyn scan --help
```

a permis de vérifier les options disponibles.

Notamment :

```text
--full
--no-service-detection
--vuln-scripts
--cve
--out
--pdf
--save-history
--compare
--os-detection
--json-out
--config
```

La CLI expose donc les principales fonctionnalités du moteur.

---

# 34. Configuration YAML

Le fichier :

```text
config.example.yaml
```

est cohérent avec le modèle de configuration actuel.

Exemple :

```yaml
target:
  network: "192.168.1.0/24"

scan:
  service_detection: true
  os_detection: false
  nse: false
  timeout_seconds: 600

risk:
  alert_threshold: 70

database:
  path: "./data/umbralyn.db"

report:
  directory: "reports"
```

---

# 35. Configuration environnement

Le fichier :

```text
.env.example
```

contient les variables principales :

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

Les secrets ne sont pas destinés à être commités.

---

# 36. Vérification Git avant commit

Après les tests locaux, la commande :

```bash
git status
```

a montré trois éléments :

```text
templates/report.html
get-pip.py
tests/test_config.py
```

La décision a été prise de :

### Conserver dans le commit

```text
templates/report.html
tests/test_config.py
```

### Ne pas mettre dans Git

```text
get-pip.py
```

`get-pip.py` était un script utilisé lors des manipulations liées à Python/pip et n'est pas une dépendance du projet UMBRALYN.

---

# 37. Vérification du diff

La commande :

```bash
git diff -- templates/report.html
```

a confirmé que la correction du template était limitée au comportement du message affiché lorsqu'il n'y a pas de findings.

Le changement concernait uniquement la prise en compte de la présence éventuelle de CVE.

---

# 38. Ajout des fichiers au commit

Les deux fichiers pertinents ont été ajoutés :

```bash
git add templates/report.html
git add tests/test_config.py
```

`get-pip.py` est resté non suivi et n'a donc pas été inclus.

---

# 39. Commit Git

Le commit a été créé avec :

```bash
git commit -m "Fix CVE report messaging and add config tests"
```

Commit obtenu :

```text
c1f140b
```

Message :

```text
Fix CVE report messaging and add config tests
```

Git a indiqué :

```text
2 files changed
53 insertions
2 deletions
```

et :

```text
create mode 100644 tests/test_config.py
```

---

# 40. Push GitHub

Le commit a ensuite été envoyé avec :

```bash
git push
```

Résultat :

```text
868384c..c1f140b
main -> main
```

Le dépôt GitHub est donc à jour.

---

# 41. État final du dépôt

La version distante contient maintenant :

```text
c1f140b
```

avec :

```text
Fix CVE report messaging and add config tests
```

Les deux changements sont présents sur GitHub :

```text
templates/report.html
tests/test_config.py
```

Le fichier :

```text
get-pip.py
```

n'a pas été envoyé.

---

# 42. Bilan global des tests

| Fonctionnalité               | Résultat       |
| ---------------------------- | -------------- |
| Création `.venv`             | VALIDÉ         |
| Python 3.12                  | VALIDÉ         |
| Installation dépendances     | VALIDÉ         |
| Installation editable        | VALIDÉ         |
| Setuptools package discovery | CORRIGÉ        |
| pytest                       | 7 tests passés |
| CLI                          | VALIDÉ         |
| Configuration YAML           | VALIDÉ         |
| Variables environnement      | VALIDÉ         |
| Validation paramètres        | VALIDÉ         |
| Nmap                         | VALIDÉ         |
| Scan réel                    | VALIDÉ         |
| Détection services           | VALIDÉ         |
| Détection versions           | VALIDÉ         |
| Export JSON                  | VALIDÉ         |
| Comparaison JSON             | VALIDÉ         |
| Historique SQLite            | VALIDÉ         |
| Comparaison historique       | VALIDÉ         |
| NSE                          | VALIDÉ         |
| CVE offline                  | VALIDÉ         |
| CVE → scoring                | VALIDÉ         |
| Scoring /100                 | VALIDÉ         |
| Plafonnement score           | VALIDÉ         |
| Rapport HTML                 | VALIDÉ         |
| Affichage CVE                | VALIDÉ         |
| Correction message CVE       | VALIDÉ         |
| Sérialisation scans          | VALIDÉ         |
| Git commit                   | VALIDÉ         |
| Git push                     | VALIDÉ         |

---

# 43. Problèmes rencontrés et solutions

## Problème 1 — Python / macOS

**Symptôme :**

```text
ValueError: invalid literal for int() with base 10: ''
```

**Cause :**

Informations de version macOS incorrectement remontées par Python Homebrew.

**Solution :**

Utilisation de :

```bash
uv venv --python 3.12 .venv
```

---

## Problème 2 — setuptools détectait plusieurs packages

**Symptôme :**

Plusieurs répertoires de premier niveau étaient détectés comme packages.

**Solution :**

Ajout de :

```toml
[tool.setuptools.packages.find]
include = ["umbralyn*"]
```

---

## Problème 3 — Rapport CVE potentiellement ambigu

**Symptôme :**

Le rapport indiquait qu'aucun service à risque n'était détecté alors que des CVE étaient présentes.

**Solution :**

Modification de :

```text
templates/report.html
```

pour différencier :

* absence de findings avec CVE ;
* absence de findings et de CVE.

---

## Problème 4 — `get-pip.py`

**Symptôme :**

Le fichier apparaissait comme :

```text
?? get-pip.py
```

**Solution :**

Ne pas l'ajouter au dépôt.

Il est externe au fonctionnement d'UMBRALYN.

---

# 44. Limites identifiées pendant les tests

Les tests ont également permis d'identifier plusieurs limites normales du projet.

## Identification des versions

Nmap ne peut pas toujours déterminer le produit et la version d'un service.

Cela limite nécessairement la corrélation CVE.

---

## Corrélation CVE

Les résultats CVE doivent être considérés comme des **candidats à vérifier**, et non comme une preuve automatique qu'une vulnérabilité est exploitable sur la machine.

La corrélation actuelle repose notamment sur le produit et la version détectés.

---

## Scripts NSE

Une sortie d'un script NSE ne constitue pas systématiquement une preuve de vulnérabilité.

Une vérification manuelle peut être nécessaire.

---

## Score de risque

Le score UMBRALYN est un indicateur interne destiné à faciliter la priorisation.

Il ne constitue pas une mesure universelle ou une certification de sécurité.

---

# 45. Conclusion

La phase de validation locale d'UMBRALYN est terminée avec succès.

Le projet a été :

1. installé dans un environnement virtuel Python ;
2. configuré ;
3. installé comme package ;
4. testé avec pytest ;
5. exécuté via sa CLI ;
6. connecté à Nmap ;
7. utilisé pour effectuer un scan réel ;
8. testé avec détection de services ;
9. testé avec NSE ;
10. testé avec export JSON ;
11. testé avec historique SQLite ;
12. testé avec comparaison de scans ;
13. testé avec recherche CVE offline ;
14. testé avec intégration CVE → scoring ;
15. testé avec génération de rapports HTML ;
16. corrigé au niveau de l'affichage CVE ;
17. revalidé après correction ;
18. versionné avec Git ;
19. poussé sur GitHub.

Le dernier commit validé est :

```text
c1f140b — Fix CVE report messaging and add config tests
```

La branche :

```text
main
```

est synchronisée avec :

```text
origin/main
```

**État final : projet fonctionnel, tests automatisés passants, fonctionnalités principales validées et corrections poussées sur GitHub.**
