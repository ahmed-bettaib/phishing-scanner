"""
routes.py
---------
Définit les endpoints de l'application :
- "/"        : page principale (formulaire de scan)
- "/scan"    : endpoint AJAX qui reçoit une URL et renvoie le rapport JSON
- "/history" : historique des scans effectués (en mémoire pour ce projet)
"""

from flask import Blueprint, render_template, request, jsonify
from datetime import datetime

from .analyzer import analyze_url

main_bp = Blueprint("main", __name__)

# Historique en mémoire (simple pour une démo locale).
# Dans une vraie version prod, ça irait dans une base de données.
scan_history = []


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

    return jsonify(result)


@main_bp.route("/history")
def history():
    return jsonify(scan_history[:20])
