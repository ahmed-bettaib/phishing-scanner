# alerts.py
#
# module d'envoi d'alertes email, utilise quand :
# - un scan d'URL revient "high risk"
# - un incident de brute force est detecte dans les logs
#
# la config SMTP se met dans des variables d'environnement (jamais en
# dur dans le code, surtout pas sur un repo public)
#
# si aucune config n'est trouvee, on log juste ce qui AURAIT ete envoye
# (mode "dry run") au lieu de planter -> pratique pour tester en local
# sans avoir un vrai compte SMTP

import os
import smtplib
from email.mime.text import MIMEText
from datetime import datetime

SMTP_HOST = os.environ.get("SMTP_HOST")
SMTP_PORT = int(os.environ.get("SMTP_PORT", 587))
SMTP_USER = os.environ.get("SMTP_USER")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")
ALERT_EMAIL_TO = os.environ.get("ALERT_EMAIL_TO")

# on garde une trace des alertes envoyees (utile pour les afficher dans l'UI)
alert_log = []


def _is_configured():
    return all([SMTP_HOST, SMTP_USER, SMTP_PASSWORD, ALERT_EMAIL_TO])


def send_email_alert(subject: str, body: str) -> dict:
    """
    Envoie une alerte email. Si la config SMTP n'est pas presente dans
    l'environnement, on simule l'envoi (dry run) pour pouvoir quand
    meme demo/tester le systeme sans vrai compte mail.
    """
    entry = {
        "subject": subject,
        "body": body,
        "sent_at": datetime.utcnow().isoformat() + "Z",
    }

    if not _is_configured():
        entry["status"] = "dry_run"
        entry["note"] = "SMTP non configure (variables d'environnement manquantes), alerte simulee"
        alert_log.append(entry)
        return entry

    try:
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = SMTP_USER
        msg["To"] = ALERT_EMAIL_TO

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_USER, [ALERT_EMAIL_TO], msg.as_string())

        entry["status"] = "sent"
    except Exception as e:
        entry["status"] = "failed"
        entry["error"] = str(e)

    alert_log.append(entry)
    return entry


def get_recent_alerts(limit=20):
    return alert_log[-limit:][::-1]


def build_phishing_alert(scan_result: dict) -> tuple:
    subject = f"[ALERTE] URL a risque eleve detectee - {scan_result['domain']}"
    body = (
        f"Une URL a risque eleve a ete scannee.\n\n"
        f"URL : {scan_result['url']}\n"
        f"Score : {scan_result['score']}/100\n"
        f"Raisons :\n- " + "\n- ".join(scan_result["reasons"])
    )
    return subject, body


def build_bruteforce_alert(incident: dict) -> tuple:
    subject = f"[ALERTE] Tentative de brute force detectee - {incident['ip']}"
    body = (
        f"Une IP suspecte a ete detectee dans les logs.\n\n"
        f"IP : {incident['ip']}\n"
        f"Nombre de tentatives : {incident['attempts']}\n"
        f"Comptes cibles : {', '.join(incident['users_targeted'])}\n"
        f"Premiere tentative : {incident['first_attempt']}\n"
        f"Derniere tentative : {incident['last_attempt']}"
    )
    return subject, body
