# 🛡️ PhishGuard — Dashboard de monitoring SOC

Application web centralisant deux modules de sécurité :
1. un **scanner d'URLs de phishing** (analyse heuristique)
2. un **analyseur de logs** pour détecter les attaques par brute force

Les deux modules déclenchent automatiquement une **alerte email** dès qu'une anomalie à risque élevé est détectée.

Projet réalisé dans le cadre de mon apprentissage en cybersécurité, en complément de mes activités au sein de **Securinets** (club cybersécurité de l'ITeam University).

## Module 1 — Scanner de phishing

L'utilisateur colle une URL, l'application l'analyse côté serveur et retourne :
- un **score de risque** sur 100
- un **niveau** (faible / moyen / élevé)
- la **liste des indicateurs** ayant contribué au score

## Fonctionnement

Le moteur d'analyse (`app/analyzer.py`) applique une série de règles indépendantes sur l'URL fournie :

| Règle | Ce qu'elle détecte |
|---|---|
| IP brute | Domaine remplacé par une adresse IP |
| HTTPS absent | Connexion non chiffrée |
| Mots-clés suspects | `login`, `verify`, `secure`, `account`, etc. |
| Usurpation de marque | Nom de marque connue dans un domaine non officiel |
| TLD à risque | Extensions statistiquement liées au phishing (`.tk`, `.xyz`...) |
| Sous-domaines excessifs | Technique de dissimulation du vrai domaine |
| URL trop longue | Camouflage de données/domaine |
| Symbole `@` | Technique de redirection trompeuse |

Chaque règle ajoute des points au score final, plafonné à 100.

## Module 2 — Analyseur de logs (détection brute force)

Prend le contenu d'un fichier de log au format `auth.log` (SSH) et détecte les IPs qui font trop de tentatives de connexion échouées dans une fenêtre de temps donnée (seuil et fenêtre configurables).

Un fichier d'exemple synthétique (`app/sample_data/sample_auth.log`) est fourni pour tester sans avoir de vrai serveur — accessible directement dans l'interface via le bouton "Charger l'exemple".

Pour chaque IP qui dépasse le seuil, l'app renvoie :
- l'IP suspecte
- le nombre de tentatives
- les comptes ciblés
- l'heure de la première et dernière tentative

## Module 3 — Système d'alerte automatique

Dès qu'un scan phishing est classé "risque élevé" (score ≥ 60) ou qu'un incident de brute force est détecté, une alerte email est envoyée automatiquement via SMTP.

Si aucune configuration SMTP n'est présente (variables d'environnement absentes), l'app fonctionne quand même : les alertes sont **simulées** ("dry run") au lieu d'être réellement envoyées, ce qui permet de tester tout le système sans avoir de compte email dédié. Voir `.env.example` pour la configuration.

## Stack technique

- **Backend** : Python 3 / Flask
- **Frontend** : HTML / CSS / JavaScript vanilla (pas de framework, volontairement, pour rester léger)
- **Tests** : pytest
- **Email** : smtplib (bibliothèque standard Python)

## Installation

```bash
git clone https://github.com/<ton-username>/phishing-scanner.git
cd phishing-scanner
python -m venv venv
source venv/bin/activate  # Windows : venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env      # optionnel : configure le SMTP pour envoyer de vraies alertes
python run.py
```

L'application est ensuite accessible sur `http://localhost:5000` (scanner phishing) et `http://localhost:5000/logs` (analyseur de logs).

## Lancer les tests

```bash
pytest tests/
```

## Structure du projet

```
phishing-scanner/
├── app/
│   ├── __init__.py       # Factory Flask
│   ├── routes.py         # Tous les endpoints
│   ├── analyzer.py       # Moteur de détection phishing
│   ├── log_analyzer.py   # Moteur de détection brute force
│   ├── alerts.py         # Système d'alerte email (SMTP)
│   └── sample_data/
│       └── sample_auth.log   # Fichier de log d'exemple
├── templates/
│   ├── index.html        # Page scanner phishing
│   └── logs.html         # Page analyseur de logs
├── static/
│   ├── css/style.css
│   ├── js/scanner.js
│   └── js/logs.js
├── tests/
│   ├── test_analyzer.py
│   └── test_log_analyzer.py
├── run.py
├── .env.example
└── requirements.txt
```

## Limites connues

Ce projet est **pédagogique** : les règles heuristiques donnent une bonne intuition mais ne remplacent pas un vrai moteur de threat intelligence (pas de vérification WHOIS, pas de base de données de domaines connus, pas de réputation en temps réel). Des pistes d'amélioration possibles : intégration d'une API de réputation (VirusTotal, PhishTank), vérification de l'âge du domaine, détection de typosquatting par distance de Levenshtein.

## Auteur

Ahmed Bettaib — étudiant en ingénierie informatique, VP de Securinets.
