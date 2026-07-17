# log_analyzer.py
#
# module qui parse des logs d'authentification (style /var/log/auth.log
# sur linux) et detecte les tentatives de brute force
#
# logique simple : si une meme IP a trop d'echecs de connexion dans une
# fenetre de temps courte, on considere ca comme une attaque

import re
from datetime import datetime
from collections import defaultdict

# regex pour matcher les lignes "Failed password" d'un auth.log SSH classique
# exemple de ligne reelle :
# Jul 16 22:14:03 server sshd[1322]: Failed password for admin from 41.230.12.5 port 51422 ssh2
FAILED_LOGIN_PATTERN = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r".*Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

# seuils par defaut (modifiables selon le contexte)
DEFAULT_THRESHOLD = 5          # nb d'echecs
DEFAULT_WINDOW_SECONDS = 300   # fenetre de temps (5 min)


def _parse_timestamp(month, day, time_str, year=None):
    # les logs syslog n'ont pas l'annee dedans, on prend l'annee courante
    year = year or datetime.now().year
    dt_str = f"{year} {month} {day} {time_str}"
    return datetime.strptime(dt_str, "%Y %b %d %H:%M:%S")


def parse_log_lines(lines):
    """
    Prend une liste de lignes de log et extrait les tentatives de
    connexion echouees (user, ip, timestamp).
    """
    events = []
    for line in lines:
        match = FAILED_LOGIN_PATTERN.match(line.strip())
        if not match:
            continue
        try:
            ts = _parse_timestamp(match.group("month"), match.group("day"), match.group("time"))
        except ValueError:
            continue
        events.append({
            "timestamp": ts,
            "user": match.group("user"),
            "ip": match.group("ip"),
        })
    return events


def detect_brute_force(events, threshold=DEFAULT_THRESHOLD, window_seconds=DEFAULT_WINDOW_SECONDS):
    """
    Regroupe les evenements par IP et regarde si il y a "threshold"
    echecs ou plus dans une fenetre de "window_seconds".
    Renvoie la liste des IP suspectes avec le detail.
    """
    by_ip = defaultdict(list)
    for event in events:
        by_ip[event["ip"]].append(event)

    incidents = []
    for ip, attempts in by_ip.items():
        attempts.sort(key=lambda e: e["timestamp"])

        # fenetre glissante : pour chaque tentative, on regarde combien
        # de tentatives de la meme IP sont dans les X secondes suivantes
        for i, start_event in enumerate(attempts):
            window_end = start_event["timestamp"].timestamp() + window_seconds
            count_in_window = sum(
                1 for e in attempts[i:]
                if e["timestamp"].timestamp() <= window_end
            )
            if count_in_window >= threshold:
                users_targeted = sorted(set(e["user"] for e in attempts))
                incidents.append({
                    "ip": ip,
                    "attempts": len(attempts),
                    "users_targeted": users_targeted,
                    "first_attempt": attempts[0]["timestamp"].isoformat(),
                    "last_attempt": attempts[-1]["timestamp"].isoformat(),
                })
                break  # on a trouve l'incident pour cette IP, pas besoin de continuer

    # on trie par nombre de tentatives desc, les pires en premier
    incidents.sort(key=lambda x: x["attempts"], reverse=True)
    return incidents


def analyze_log_text(raw_text, threshold=DEFAULT_THRESHOLD, window_seconds=DEFAULT_WINDOW_SECONDS):
    """
    Point d'entree principal : prend le texte brut d'un fichier log,
    renvoie un rapport avec les incidents detectes.
    """
    lines = raw_text.splitlines()
    events = parse_log_lines(lines)
    incidents = detect_brute_force(events, threshold, window_seconds)

    return {
        "total_lines": len(lines),
        "failed_login_events": len(events),
        "incidents": incidents,
        "threshold_used": threshold,
        "window_seconds_used": window_seconds,
    }
