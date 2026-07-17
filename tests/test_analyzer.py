"""
Tests unitaires basiques pour le moteur d'analyse.
Lancer avec : pytest tests/
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.analyzer import analyze_url


def test_legit_https_url_is_low_risk():
    result = analyze_url("https://www.google.com")
    assert result["risk_level"] == "low"


def test_ip_based_url_flagged():
    result = analyze_url("http://192.168.1.10/login")
    reasons_text = " ".join(result["reasons"])
    assert "adresse IP" in reasons_text


def test_brand_spoofing_detected():
    result = analyze_url("http://paypal-secure-login.tk/verify")
    assert result["risk_level"] == "high"


def test_at_symbol_detected():
    result = analyze_url("http://trusted-site.com@malicious.com")
    reasons_text = " ".join(result["reasons"])
    assert "@" in reasons_text


def test_missing_url_handled_gracefully():
    result = analyze_url("example.com")
    assert "domain" in result
    assert result["domain"] == "example.com"
