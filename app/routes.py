# routes.py
# tous les endpoints de l'app :
# "/"           page principale (scanner phishing)
# "/scan"       POST -> analyse une url, renvoie le rapport JSON
# "/history"    historique des scans phishing
# "/logs"       page analyseur de logs (brute force)
# "/logs/analyze"  POST -> analyse un texte de log, renvoie les incidents
# "/alerts"     historique des alertes envoyees (dry run ou reelles)

import os
from flask import Blueprint, render_template, request, jsonify
from datetime import datetime

from .analyzer import analyze_url
from .log_analyzer import analyze_log_text
from .alerts import (
    send_email_alert, get_recent_alerts,
    build_phishing_alert, build_bruteforce_alert,
)

main_bp = Blueprint("main", __name__)

# historique en memoire, simple pour une demo locale
# (dans une vraie version prod ça irait en base de donnees)
scan_history = []

SAMPLE_LOG_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "sample_data", "sample_auth.log"
)

# a partir de quel score de risque on envoie une alerte auto
PHISHING_ALERT_THRESHOLD = 60


@main_bp.route("/")
def index():
    return render_template("index.html")


@main_bp.route("/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "Aucune URL fournie"}), 400

    if len(url) > 2048:
        return jsonify({"error": "URL trop longue"}), 400

    result = analyze_url(url)
    result["scanned_at"] = datetime.utcnow().isoformat() + "Z"

    scan_history.insert(0, result)
    if len(scan_history) > 50:
        scan_history.pop()

    # si le score est haut on declenche une alerte mail automatiquement
    if result["score"] >= PHISHING_ALERT_THRESHOLD:
        subject, body = build_phishing_alert(result)
        send_email_alert(subject, body)

    return jsonify(result)


@main_bp.route("/history")
def history():
    return jsonify(scan_history[:20])


# ------------------------------------------------------------------
# module 2 : analyseur de logs / detection brute force
# ------------------------------------------------------------------

@main_bp.route("/logs")
def logs_page():
    return render_template("logs.html")


@main_bp.route("/logs/sample")
def logs_sample():
    # renvoie le contenu du fichier d'exemple pour que le front puisse
    # pre-remplir le textarea (pratique pour tester sans avoir de vrai log)
    with open(SAMPLE_LOG_PATH, "r") as f:
        content = f.read()
    return jsonify({"content": content})


@main_bp.route("/logs/analyze", methods=["POST"])
def logs_analyze():
    data = request.get_json(silent=True) or {}
    raw_text = data.get("log_text", "")

    if not raw_text.strip():
        return jsonify({"error": "Aucun contenu de log fourni"}), 400

    threshold = int(data.get("threshold", 5))
    window_seconds = int(data.get("window_seconds", 300))

    report = analyze_log_text(raw_text, threshold=threshold, window_seconds=window_seconds)

    # chaque incident detecte declenche une alerte
    for incident in report["incidents"]:
        subject, body = build_bruteforce_alert(incident)
        send_email_alert(subject, body)

    return jsonify(report)


# ------------------------------------------------------------------
# historique des alertes (les deux modules l'utilisent)
# ------------------------------------------------------------------

@main_bp.route("/alerts")
def alerts_page():
    return jsonify(get_recent_alerts())
