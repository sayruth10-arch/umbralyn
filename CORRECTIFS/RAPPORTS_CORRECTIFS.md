# Rapport des correctifs — UMBRALYN

**Projet :** UMBRALYN — Automated Network Security Auditing
**Version :** 0.2.0
**Date :** Septembre 2026

---

## 1. Objet du document

Ce document recense les principaux correctifs apportés à UMBRALYN à la suite de l'audit technique du projet.

L'objectif de cette phase était de vérifier la cohérence du code, la fiabilité des fonctionnalités principales, la gestion des erreurs et la cohérence des différents formats d'export avant de poursuivre les validations fonctionnelles sur des environnements de laboratoire contrôlés.

Les corrections ont principalement concerné :

* la recherche de CVE ;
* la configuration ;
* l'historisation des scans ;
* la comparaison des résultats ;
* le scoring de risque ;
* l'analyse des risques ;
* le scheduler ;
* l'export JSON ;
* les rapports HTML ;
* les tests automatisés ;
* le packaging Python.

---

# 2. Recherche CVE — `cve_lookup.py`

## 2.1 Problème identifié

La fonction de recherche CVE utilisait une variable `api_key` qui n'était pas correctement définie dans son contexte d'utilisation.

Cette situation pouvait provoquer une erreur lors de l'exécution de la recherche CVE.

## 2.2 Correction

La récupération de la clé API NVD a été déplacée directement dans la fonction `lookup_cves_for_scan()` :

```python
api_key = os.environ.get("UMBRALYN_NVD_API_KEY")
```

La recherche CVE prend désormais en charge :

* l'API NVD ;
* une clé API facultative ;
* une mise en cache locale ;
* un délai entre les requêtes lorsqu'aucune clé API n'est utilisée ;
* un fallback hors ligne lorsque l'API NVD n'est pas disponible.

## 2.3 Clarification du résultat

La documentation et les rapports utilisent désormais la notion de **CVE candidate**.

Une correspondance entre un produit/version détecté et une CVE ne constitue pas automatiquement une preuve que le système est vulnérable.

Le fonctionnement est donc considéré comme :

```text
Produit / version détecté
        ↓
Corrélation avec une CVE
        ↓
CVE candidate
        ↓
Vérification complémentaire
        ↓
Vulnérabilité éventuellement confirmée
```

Cette distinction permet d'éviter de présenter une corrélation automatisée comme une conclusion définitive.

---

# 3. Historisation et comparaison — `history.py`

## 3.1 Problème identifié

La comparaison des ports entre deux scans utilisait uniquement leur numéro.

Cela pouvait provoquer une confusion entre deux services utilisant le même numéro de port mais des protocoles différents :

```text
TCP/80
UDP/80
```

## 3.2 Correction

La clé utilisée pour comparer les ports prend désormais en compte :

```python
(port.number, port.protocol)
```

TCP et UDP sont donc correctement différenciés lors des comparaisons.

## 3.3 Base SQLite

Le chemin par défaut de la base de données a également été harmonisé :

```text
data/umbralyn.db
```

Le répertoire parent est automatiquement créé lors de la connexion à la base.

Cette modification permet d'éviter les erreurs lorsque le répertoire `data/` n'existe pas encore.

---

# 4. Configuration — `config.py`

## 4.1 Problèmes identifiés

Certaines valeurs de configuration nécessitaient une validation plus stricte afin d'éviter des paramètres incohérents ou invalides.

## 4.2 Corrections

La configuration valide notamment :

* les valeurs booléennes ;
* les valeurs entières positives ;
* le timeout ;
* le seuil d'alerte.

Le seuil de risque est limité à :

```text
0 — 100
```

Les variables d'environnement `UMBRALYN_*` peuvent également prendre la priorité sur les valeurs définies dans le fichier YAML.

## 4.3 Harmonisation des chemins

Les chemins par défaut ont été harmonisés :

```text
Base de données : data/umbralyn.db
Rapports        : reports/
```

Cette harmonisation permet d'utiliser les mêmes emplacements entre le scanner, l'historisation et le scheduler.

---

# 5. Scheduler — `scheduler.py`

## 5.1 Problèmes identifiés

Le scheduler ne partageait pas toujours les mêmes paramètres que le scanner principal.

Des incohérences pouvaient notamment apparaître concernant :

* le timeout ;
* les options de détection ;
* les scripts NSE ;
* la base SQLite.

## 5.2 Corrections

Le scheduler utilise désormais les mêmes paramètres de scan que la configuration principale.

Le timeout est validé avant l'exécution du scan.

L'historisation est également intégrée au processus planifié.

Lorsqu'un historique existe, le nouveau résultat peut être comparé au scan précédent afin d'identifier les changements.

Les alertes email peuvent également être déclenchées lorsque les conditions configurées sont remplies.

---

# 6. Scoring des risques — `scoring.py`

## 6.1 Objectif

Le système de scoring a été renforcé afin de rendre le calcul plus robuste et plus explicable.

Le score UMBRALYN constitue un **indicateur interne** et ne représente pas une norme universelle de sécurité.

## 6.2 Poids des findings

Les poids utilisés sont explicitement définis :

```text
Finding :

high   = 30
medium = 15
info   = 5
```

## 6.3 Poids des CVE candidates

Les CVE candidates utilisent les pondérations suivantes :

```text
critical = 35
high     = 25
medium   = 12
low      = 4
```

## 6.4 Limitation du score

Le score d'un hôte est limité à :

```text
100 maximum
```

Cette limitation évite qu'une accumulation de findings ou de CVE fasse dépasser la plage prévue.

## 6.5 Gestion des données CVE

La récupération des informations CVE a également été sécurisée afin d'éviter des erreurs lorsque certains champs sont absents ou incomplets.

## 6.6 Calcul du score global

Le score global UMBRALYN combine :

```text
70 % : score du pire hôte
30 % : moyenne des scores des hôtes
```

Cette méthode est spécifique à UMBRALYN.

Elle doit être considérée comme une méthode de synthèse interne permettant de représenter le niveau de risque détecté sur l'ensemble de la cible.

---

# 7. Analyse des risques — `risk_analysis.py`

## 7.1 Clarification des findings

La documentation et les messages générés ont été précisés afin d'éviter de présenter automatiquement un port identifié comme risqué comme une vulnérabilité confirmée.

La logique distingue désormais clairement :

```text
Port exposé
≠
Vulnérabilité confirmée
```

Un port identifié comme potentiellement risqué représente une exposition ou une surface d'attaque nécessitant éventuellement une analyse complémentaire.

## 7.2 Scripts NSE

Les résultats des scripts Nmap NSE sont également considérés comme des indications techniques.

Lorsqu'un script signale un problème potentiel, une vérification manuelle peut être nécessaire avant de conclure à la présence d'une vulnérabilité.

---

# 8. Export JSON avec les CVE — `history.py`

## 8.1 Problème identifié

Lorsqu'un scan était lancé avec :

```text
--cve
```

les CVE étaient correctement recherchées et utilisées par :

* le scoring ;
* le rapport HTML ;

mais elles n'étaient pas présentes dans l'export JSON.

Le fichier JSON contenait uniquement les informations issues du scan Nmap :

```text
target
hosts
ports
services
versions
```

Les résultats de corrélation CVE restaient dans la variable `cves` et n'étaient donc pas sauvegardés dans le fichier JSON.

## 8.2 Correction

La fonction `save_scan_json()` a été modifiée afin d'accepter les CVE en paramètre :

```python
def save_scan_json(
    scan: ScanResult,
    path: str | Path,
    cves: Optional[Dict[str, list]] = None,
) -> Path:
```

Les données du scan sont d'abord sérialisées normalement :

```python
data = scan_to_dict(scan)
```

Puis les CVE sont ajoutées lorsqu'elles sont disponibles :

```python
if cves:
    data["cves"] = cves
```

## 8.3 Modification de `__main__.py`

Le résultat CVE est désormais transmis à la fonction d'export :

```python
json_path = save_scan_json(
    scan,
    args.json_out,
    cves=cves,
)
```

Lorsqu'aucune recherche CVE n'est demandée, la variable reste vide et le fonctionnement normal de l'export est conservé.

## 8.4 Structure obtenue

Le fichier JSON peut désormais contenir une section dédiée :

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

Les résultats CVE sont ainsi conservés avec les données du scan.

---

# 9. Rapports HTML

## 9.1 Problème identifié

Lorsqu'un scan possédait des CVE candidates mais aucun `Finding`, le rapport pouvait afficher un message laissant penser qu'aucun élément de sécurité n'avait été identifié.

Cela pouvait être ambigu puisque les CVE étaient pourtant présentes dans le rapport.

## 9.2 Correction

Le template :

```text
templates/report.html
```

a été adapté afin de différencier plusieurs situations :

### Aucun finding et aucune CVE

```text
Aucun service à risque connu ni aucune CVE associée détectée sur les ports scannés.
```

### CVE présentes mais aucun finding

```text
Aucun service à risque connu détecté sur les ports scannés.
Des CVE associées aux services identifiés sont détaillées ci-dessous.
```

Le rapport présente ainsi plus clairement la différence entre findings et CVE candidates.

---

# 10. Tests automatisés

## 10.1 Objectif

Des tests automatisés ont été ajoutés et renforcés afin de vérifier le comportement des principales fonctionnalités et d'éviter les régressions.

Les tests couvrent notamment :

* la configuration ;
* l'historisation ;
* la comparaison des scans ;
* la conservation des résultats NSE ;
* l'export JSON ;
* l'export des CVE dans le JSON ;
* le scoring.

## 10.2 Test de l'export CVE

Un test spécifique a été ajouté dans :

```text
tests/test_history.py
```

Le test :

```python
def test_save_scan_json_preserves_cves(tmp_path) -> None:
```

effectue les opérations suivantes :

1. création d'un scan fictif ;
2. création d'une CVE de test ;
3. export du scan au format JSON ;
4. lecture du fichier JSON généré ;
5. vérification de la présence et de l'intégrité des données CVE.

Cette vérification confirme que les CVE sont réellement écrites dans le fichier JSON.

## 10.3 Résultat final

La suite de tests complète donne :

```text
........ [100%]

8 passed in 0.03s
```

Résultat :

```text
8 tests passés
0 échec
```

Le nouveau test d'export CVE est donc intégré à la suite automatisée.

---

# 11. Packaging Python

## 11.1 Problème identifié

L'installation du projet avec :

```bash
uv pip install -e .
```

rencontrait initialement une erreur liée à la découverte automatique des packages par Setuptools.

Plusieurs répertoires situés à la racine du projet pouvaient être interprétés comme des packages :

```text
web
reports
templates
umbralyn
```

## 11.2 Cause

Le projet contient plusieurs répertoires nécessaires au fonctionnement global de l'application, mais seul :

```text
umbralyn/
```

correspond au package Python.

## 11.3 Correction

La découverte des packages a été limitée explicitement au package UMBRALYN :

```toml
[tool.setuptools.packages.find]
include = ["umbralyn*"]
```

L'installation editable fonctionne désormais correctement.

---

# 12. Validation fonctionnelle

Une validation locale a été réalisée sur macOS avec :

* Python 3.12 ;
* Nmap 7.991 ;
* environnement virtuel `.venv` ;
* dépendances du projet ;
* pytest.

Les fonctionnalités suivantes ont été vérifiées :

```text
✓ Lancement du module UMBRALYN
✓ Affichage de l'aide CLI
✓ Lecture de la configuration
✓ Scan Nmap
✓ Détection des hôtes
✓ Détection des ports
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

# 13. Validation sur `scanme.nmap.org`

Une validation fonctionnelle a été réalisée avec la cible de test publique fournie par Nmap :

```text
scanme.nmap.org
```

Cette validation a permis de tester la détection des services et des versions sans utiliser le réseau personnel.

## 13.1 Résultat du scan

L'hôte détecté était :

```text
45.33.32.156
```

Les services détectés étaient :

```text
22/tcp
    OpenSSH
    6.6.1p1 Ubuntu 2ubuntu2.13

80/tcp
    Apache httpd
    2.4.7
```

## 13.2 Recherche CVE

La recherche CVE a également permis d'identifier une correspondance :

```text
CVE-2021-44224
```

Cette correspondance est considérée par UMBRALYN comme une **CVE candidate** issue de la corrélation produit/version.

Elle ne constitue pas, à elle seule, une preuve que le système ciblé est effectivement vulnérable.

---

# 14. Validation de l'export CVE sans nouveau scan

Une validation supplémentaire de la correction JSON a été réalisée sans effectuer de nouveau scan Nmap.

Un résultat de scan existant a été réutilisé avec une donnée CVE de test.

Cette méthode a permis de vérifier directement la logique d'export :

```text
Scan existant
      ↓
Ajout d'une CVE de test
      ↓
save_scan_json()
      ↓
Fichier JSON
      ↓
Lecture du fichier
      ↓
Vérification de la section "cves"
```

Cette approche évite de relancer inutilement un scan réseau uniquement pour tester une fonction de sauvegarde.

---

# 15. Historique Git

Les corrections ont été enregistrées dans Git afin de conserver un historique précis des modifications.

Les principaux commits associés à cette phase comprennent notamment :

```text
3edebc4 Add CVE JSON export test
```

Ce commit ajoute le test automatisé permettant de vérifier la conservation des CVE dans les exports JSON.

Les corrections précédentes ont également été intégrées et poussées sur le dépôt distant.

Le dernier push effectué pour cette phase a été confirmé avec succès.

---

# 16. État après correction

À l'issue de cette phase, les principales fonctionnalités vérifiées sont :

```text
Code principal              ✓
Configuration               ✓
Historisation               ✓
Comparaison                 ✓
Scoring                     ✓
Analyse des risques         ✓
Recherche CVE               ✓
Rapports HTML               ✓
Export JSON                 ✓
Export JSON + CVE           ✓
Scripts NSE                 ✓
Scheduler                   ✓
Tests automatisés           ✓
Packaging Python            ✓
```

La suite de tests automatisés présente actuellement :

```text
8 / 8 tests réussis
```

---

# 17. Conclusion

Cette phase de correction a permis de renforcer la fiabilité et la cohérence interne d'UMBRALYN.

Les principales améliorations concernent :

* la recherche et la gestion des CVE ;
* l'historisation des scans ;
* la comparaison des résultats ;
* la validation de la configuration ;
* le scheduler ;
* le scoring ;
* l'analyse des risques ;
* les rapports HTML ;
* l'export JSON ;
* l'export des CVE dans les fichiers JSON ;
* les tests automatisés ;
* le packaging Python.

Une attention particulière a été portée à la distinction entre les différents niveaux de résultat :

```text
Détection
    ↓
Exposition potentielle
    ↓
Finding / indication technique
    ↓
CVE candidate
    ↓
Vérification complémentaire
    ↓
Vulnérabilité confirmée
```

Cette distinction permet de conserver une interprétation prudente des résultats automatisés.

Avec ces corrections, UMBRALYN dispose d'une base plus cohérente pour poursuivre sa phase de validation sur des environnements de laboratoire contrôlés, notamment avec des machines volontairement vulnérables.

La prochaine étape consiste à continuer les tests fonctionnels et à enrichir progressivement la couverture du projet.
