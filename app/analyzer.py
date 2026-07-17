"""
analyzer.py
------------
Coeur du scanner : analyse une URL et calcule un score de risque
en se basant sur un ensemble de règles heuristiques classiques
utilisées en détection de phishing (pas de machine learning ici,
volontairement, pour que chaque décision soit explicable).

Chaque règle renvoie un tuple (points, raison). Le score final
est la somme des points, plafonné à 100.
"""

import re
from urllib.parse import urlparse

# Mots-clés fréquemment utilisés dans les URLs de phishing
# pour usurper des marques connues (banques, mails, paiement...)
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "confirm",
    "password", "banking", "webscr", "signin", "billing", "suspend"
]

# Marques souvent imitées : on vérifie si le nom de domaine
# contient le mot de la marque MAIS que ce n'est pas le vrai domaine
COMMONLY_SPOOFED_BRANDS = [
    "paypal", "google", "facebook", "apple", "microsoft",
    "amazon", "netflix", "instagram", "bankofamerica", "orange"
]

# Extensions de domaines statistiquement très utilisées en phishing
SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club"]


def _get_domain_parts(url: str):
    """Extrait proprement le domaine et sous-domaines d'une URL."""
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "http://" + url
    parsed = urlparse(url)
    return parsed, parsed.netloc.lower()


def check_ip_as_domain(parsed) -> tuple:
    """Une URL qui utilise une IP brute au lieu d'un nom de domaine
    est un signal fort de phishing (contournement de la réputation DNS)."""
    ip_pattern = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    host = parsed.netloc.split(":")[0]
    if ip_pattern.match(host):
        return 30, "Le domaine est une adresse IP brute au lieu d'un nom de domaine"
    return 0, None


def check_https(parsed) -> tuple:
    """Absence de HTTPS = pas de chiffrement, souvent négligé par
    les sites de phishing rapidement montés."""
    if parsed.scheme != "https":
        return 15, "Le site n'utilise pas HTTPS (connexion non chiffrée)"
    return 0, None


def check_suspicious_keywords(url: str) -> tuple:
    """Recherche de mots-clés typiques des tentatives d'hameçonnage
    dans le chemin ou les paramètres de l'URL."""
    url_lower = url.lower()
    found = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
    if found:
        points = min(len(found) * 8, 25)
        return points, f"Mots-clés suspects détectés : {', '.join(found)}"
    return 0, None


def check_brand_spoofing(domain: str) -> tuple:
    """Détecte une marque connue mentionnée dans un domaine qui
    n'est PAS le domaine officiel (ex: paypal-secure-login.tk)."""
    for brand in COMMONLY_SPOOFED_BRANDS:
        if brand in domain and not domain.endswith(f"{brand}.com"):
            return 25, f"Le domaine imite possiblement la marque '{brand}'"
    return 0, None


def check_suspicious_tld(domain: str) -> tuple:
    """Certaines extensions sont statistiquement surreprésentées
    dans les campagnes de phishing car peu coûteuses et peu régulées."""
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            return 15, f"Extension de domaine à risque ({tld})"
    return 0, None


def check_excessive_subdomains(domain: str) -> tuple:
    """Un nombre élevé de sous-domaines est souvent utilisé pour
    noyer le vrai domaine (ex: paypal.com.verify-account.xyz)."""
    parts = domain.split(".")
    if len(parts) > 4:
        return 15, "Nombre inhabituel de sous-domaines"
    return 0, None


def check_url_length(url: str) -> tuple:
    """Les URLs de phishing sont souvent anormalement longues pour
    dissimuler le vrai domaine ou embarquer des données encodées."""
    if len(url) > 90:
        return 10, "URL anormalement longue"
    return 0, None


def check_at_symbol(url: str) -> tuple:
    """Le symbole '@' dans une URL fait ignorer tout ce qui précède
    par le navigateur, une technique classique de camouflage."""
    if "@" in url:
        return 20, "Présence du symbole '@' (technique de camouflage d'URL)"
    return 0, None


# Liste ordonnée des règles à appliquer
RULES_URL_ONLY = [check_url_length, check_at_symbol, check_suspicious_keywords]
RULES_PARSED = [check_ip_as_domain, check_https]
RULES_DOMAIN_ONLY = [
    check_brand_spoofing, check_suspicious_tld, check_excessive_subdomains
]


def analyze_url(url: str) -> dict:
    """
    Point d'entrée principal : prend une URL brute, applique toutes
    les règles, et retourne un rapport structuré avec score, niveau
    de risque et détail des raisons.
    """
    url = url.strip()
    parsed, domain = _get_domain_parts(url)

    reasons = []
    total_score = 0

    for rule in RULES_URL_ONLY:
        points, reason = rule(url)
        if reason:
            reasons.append(reason)
            total_score += points

    for rule in RULES_PARSED:
        points, reason = rule(parsed)
        if reason:
            reasons.append(reason)
            total_score += points

    for rule in RULES_DOMAIN_ONLY:
        points, reason = rule(domain)
        if reason:
            reasons.append(reason)
            total_score += points

    total_score = min(total_score, 100)

    if total_score >= 60:
        risk_level = "high"
    elif total_score >= 30:
        risk_level = "medium"
    else:
        risk_level = "low"

    return {
        "url": url,
        "domain": domain,
        "score": total_score,
        "risk_level": risk_level,
        "reasons": reasons if reasons else ["Aucun indicateur suspect détecté"],
    }
