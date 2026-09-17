# Rapport des correctifs — UMBRALYN

**Projet :** UMBRALYN — Automated Network Security Auditing
**Version :** 0.2.0
**Date :** Septembre 2026

---

## 1. Objet du document

Ce document recense les principaux correctifs apportés à UMBRALYN à la suite de l'audit technique du projet.

L'objectif était de vérifier la cohérence du code, la fiabilité des fonctionnalités principales et la qualité des exports avant de poursuivre les tests fonctionnels sur des cibles de laboratoire.

Les corrections ont principalement concerné :

* la recherche de CVE ;
* la configuration ;
* l'historisation des scans ;
* le scoring de risque ;
* le scheduler ;
* l'export des résultats ;
* les tests automatisés ;
* le packaging Python ;
* la présentation des rapports.

---

# 2. Correctifs techniques

## 2.1 Recherche CVE — `cve_lookup.py`

### Problème

La fonction de recherche CVE utilisait une variable `api_key` qui n'était pas correctement définie dans son contexte d'utilisation.

### Correction

La récupération de la clé API NVD a été déplacée dans `lookup_cves_for_scan()` :

```python
api_key = os.environ.get("UMBRALYN_NVD_API_KEY")
```

La recherche prend désormais en charge :

* l'API NVD ;
* une mise en cache locale ;
* un délai entre les requêtes lorsque aucune clé API n'est utilisée ;
* un fallback hors ligne lorsque l'API n'est pas disponible.

### Amélioration de la documentation

Les résultats sont désormais présentés comme des **CVE candidates** et non comme des vulnérabilités confirmées.

Cette distinction est importante : une correspondance produit/version avec une CVE nécessite une vérification complémentaire avant de conclure qu'un système est effectivement vulnérable.

---

## 2.2 Historisation et comparaison — `history.py`

### Problème

La comparaison des ports utilisait uniquement leur numéro.

Cela pouvait provoquer une confusion entre :

```text
TCP/80
UDP/80
```

### Correction

La clé de comparaison utilise désormais :

```python
(port.number, port.protocol)
```

Les changements entre TCP et UDP sont donc correctement différenciés.

### Base SQLite

Le chemin par défaut a également été harmonisé :

```text
data/umbralyn.db
```

La création du répertoire parent est automatique lors de la connexion à la base.

---

# 3. Configuration — `config.py`

### Problèmes identifiés

Plusieurs valeurs de configuration nécessitaient une validation plus stricte.

### Corrections

La configuration valide désormais :

* les valeurs booléennes ;
* les valeurs entières positives ;
* le timeout ;
* le seuil d'alerte.

Le seuil de risque est limité à :

```text
0 — 100
```

Les variables d'environnement `UMBRALYN_*` ont également été intégrées comme priorité sur les valeurs définies dans le fichier YAML.

Les chemins par défaut ont été harmonisés :

```text
Base de données : data/umbralyn.db
Rapports        : reports/
```

---

# 4. Scheduler — `scheduler.py`

### Problèmes

Le scheduler ne partageait pas toujours les mêmes paramètres que le scanner principal.

Des incohérences pouvaient notamment apparaître concernant :

* le timeout ;
* les options de détection ;
* la base SQLite.

### Corrections

Le scheduler utilise désormais les mêmes paramètres de scan que la configuration principale.

Le timeout est également validé avant l'exécution.

L'historisation et la comparaison avec le scan précédent sont intégrées au processus planifié.

---

# 5. Scoring des risques — `scoring.py`

### Objectif

Rendre le calcul du score plus robuste et plus explicable.

### Corrections

Les poids utilisés sont explicitement définis :

```text
Finding :
    high   = 30
    medium = 15
    info   = 5

CVE :
    critical = 35
    high     = 25
    medium   = 12
    low      = 4
```

Le score est limité à :

```text
100 maximum
```

La gestion des données CVE a également été sécurisée afin d'éviter les erreurs lorsque certains champs sont absents.

### Méthode du score global

Le score global combine :

```text
70 % : score du pire hôte
30 % : moyenne des scores des hôtes
```

Cette méthode est spécifique à UMBRALYN et constitue un indicateur interne. Elle ne doit pas être considérée comme une norme universelle de mesure de sécurité.

---

# 6. Analyse des risques — `risk_analysis.py`

### Correction importante

La documentation et les messages générés ont été précisés afin d'éviter de présenter automatiquement un port à risque comme une vulnérabilité.

Par exemple :

```text
Port exposé ≠ vulnérabilité confirmée
```

Les résultats des scripts NSE nécessitent également une vérification manuelle lorsqu'ils signalent un problème potentiel.

---

# 7. Export JSON avec les CVE — `history.py`

## Problème identifié

Lorsqu'un scan était lancé avec :

```text
--cve
```

les CVE étaient correctement utilisées par le rapport HTML et le scoring, mais **elles n'étaient pas présentes dans l'export JSON**.

Le JSON contenait uniquement les informations issues de Nmap :

```text
target
hosts
ports
services
versions
```

Les résultats CVE étaient stockés séparément dans la variable `cves`.

### Correction

`save_scan_json()` accepte désormais les résultats CVE :

```python
def save_scan_json(
    scan: ScanResult,
    path: str | Path,
    cves: Optional[Dict[str, list]] = None,
) -> Path:
```

Les données CVE sont ajoutées au dictionnaire avant la sérialisation :

```python
data = scan_to_dict(scan)

if cves:
    data["cves"] = cves
```

`__main__.py` transmet désormais les CVE à la fonction :

```python
save_scan_json(
    scan,
    args.json_out,
    cves=cves,
)
```

### Validation

Un test d'export a été effectué sans effectuer de nouveau scan réseau.

Le JSON généré contenait correctement :

```json
"cves": {
  "45.33.32.156:80": [
    {
      "id": "CVE-TEST-0001",
      "severity": "high",
      "summary": "Test export JSON"
    }
  ]
}
```

Cette validation confirme que le mécanisme d'export fonctionne.

---

# 8. Rapports HTML

### Problème

Lorsqu'un scan possédait des CVE mais aucun `Finding`, le rapport pouvait afficher :

```text
Aucun service à risque connu détecté...
```

alors que des CVE étaient effectivement présentes plus bas dans le rapport.

### Correction

Le message a été adapté pour préciser que des CVE peuvent être associées aux services détectés.

Le rapport distingue désormais mieux :

* absence de finding ;
* présence de CVE candidates ;
* absence de finding et de CVE.

---

# 9. Tests automatisés

De nouveaux tests ont été ajoutés pour la configuration.

Les tests vérifient notamment :

* la configuration par défaut ;
* les variables d'environnement ;
* la validation du timeout ;
* la validation des booléens.

Tests réalisés :

```text
7 tests passés
0 échec
```

Les tests existants couvrent également :

* l'historisation ;
* la comparaison des scans ;
* la conservation des résultats NSE ;
* le scoring.

---

# 10. Packaging Python

### Problème

L'installation du projet avec :

```bash
uv pip install -e .
```

rencontrait une erreur de découverte de plusieurs packages Python de premier niveau.

### Cause

Setuptools détectait notamment plusieurs répertoires comme packages potentiels :

```text
web
reports
templates
umbralyn
```

### Correction

Le `pyproject.toml` limite désormais explicitement la découverte au package Python :

```toml
[tool.setuptools.packages.find]
include = ["umbralyn*"]
```

L'installation editable fonctionne désormais correctement.

---

# 11. Validation fonctionnelle

Une validation locale a été réalisée sur macOS avec :

* Python 3.12 ;
* Nmap 7.991 ;
* environnement virtuel `.venv` ;
* dépendances du projet ;
* pytest.

Fonctionnalités vérifiées :

```text
✓ Lancement du module UMBRALYN
✓ Affichage de l'aide CLI
✓ Lecture de la configuration
✓ Scan Nmap
✓ Détection des services
✓ Détection des versions
✓ Export JSON
✓ Rapport HTML
✓ Historisation SQLite
✓ Comparaison de scans
✓ Scripts NSE
✓ Recherche CVE
✓ Intégration CVE → scoring
✓ Export JSON avec CVE
✓ Tests pytest
```

---

# 12. Validation sur `scanme.nmap.org`

Une validation sur la cible de test officielle de Nmap a permis de confirmer la détection de services et versions.

Résultat obtenu :

```text
Hôte actif : 45.33.32.156

22/tcp
    OpenSSH
    6.6.1p1 Ubuntu 2ubuntu2.13

80/tcp
    Apache httpd
    2.4.7
```

UMBRALYN a également identifié une correspondance CVE lors de la recherche NVD :

```text
CVE-2021-44224
```

Cette information est traitée par UMBRALYN comme une **CVE candidate** issue de la corrélation produit/version et ne constitue pas, à elle seule, une preuve de vulnérabilité.

---

# 13. État après correction

À l'issue de cette phase :

```text
Code principal              ✓
Configuration               ✓
Historisation               ✓
Comparaison                 ✓
Scoring                     ✓
Recherche CVE               ✓
Rapports HTML               ✓
Export JSON                 ✓
Export JSON + CVE           ✓
NSE                         ✓
Tests automatisés           ✓
Packaging                   ✓
```

Le projet peut désormais poursuivre sa phase de validation sur des environnements de laboratoire contrôlés, notamment avec des machines volontairement vulnérables.

---

# 14. Conclusion

Cette phase de correction a permis de renforcer la fiabilité et la cohérence interne d'UMBRALYN.

Les principales améliorations concernent la gestion des CVE, la configuration, l'historisation, le scoring, les rapports et l'export des résultats.

Une attention particulière a été portée à la distinction entre :

```text
détection
    ↓
exposition potentielle
    ↓
CVE candidate
    ↓
vérification
    ↓
vulnérabilité confirmée
```

Cette distinction permet d'éviter de présenter les résultats automatisés comme des conclusions définitives.

La prochaine phase consiste à poursuivre les validations sur un laboratoire contrôlé et à enrichir progressivement la couverture fonctionnelle du projet.

