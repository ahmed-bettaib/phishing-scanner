# 🛡️ PhishGuard — Scanner d'URLs de phishing

Application web permettant d'analyser une URL et d'estimer son niveau de risque de phishing, à partir d'un ensemble de règles heuristiques (pas de machine learning — chaque décision est explicable).

Projet réalisé dans le cadre de mon apprentissage en cybersécurité, en complément de mes activités au sein de **Securinets** (club cybersécurité de l'ITeam University).

## Aperçu

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

## Stack technique

- **Backend** : Python 3 / Flask
- **Frontend** : HTML / CSS / JavaScript vanilla (pas de framework, volontairement, pour rester léger)
- **Tests** : pytest

## Installation

```bash
git clone https://github.com/<ton-username>/phishing-scanner.git
cd phishing-scanner
python -m venv venv
source venv/bin/activate  # Windows : venv\Scripts\activate
pip install -r requirements.txt
python run.py
```

L'application est ensuite accessible sur `http://localhost:5000`.

## Lancer les tests

```bash
pytest tests/
```

## Structure du projet

```
phishing-scanner/
├── app/
│   ├── __init__.py      # Factory Flask
│   ├── routes.py        # Endpoints (/scan, /history)
│   └── analyzer.py       # Moteur de détection heuristique
├── templates/
│   └── index.html
├── static/
│   ├── css/style.css     # Thème sombre + jauge animée
│   └── js/scanner.js     # Logique AJAX + animations
├── tests/
│   └── test_analyzer.py
├── run.py
└── requirements.txt
```

## Limites connues

Ce projet est **pédagogique** : les règles heuristiques donnent une bonne intuition mais ne remplacent pas un vrai moteur de threat intelligence (pas de vérification WHOIS, pas de base de données de domaines connus, pas de réputation en temps réel). Des pistes d'amélioration possibles : intégration d'une API de réputation (VirusTotal, PhishTank), vérification de l'âge du domaine, détection de typosquatting par distance de Levenshtein.

## Auteur

Ahmed Bettaib — étudiant en ingénierie informatique, VP de Securinets.
