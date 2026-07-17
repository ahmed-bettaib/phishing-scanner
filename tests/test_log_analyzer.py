# test_log_analyzer.py
# tests pour la detection de brute force

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.log_analyzer import parse_log_lines, detect_brute_force, analyze_log_text


SAMPLE_LOGS = """\
Jul 16 22:10:01 server sshd[1201]: Failed password for root from 41.230.12.5 port 51201 ssh2
Jul 16 22:10:04 server sshd[1202]: Failed password for root from 41.230.12.5 port 51202 ssh2
Jul 16 22:10:07 server sshd[1203]: Failed password for admin from 41.230.12.5 port 51203 ssh2
Jul 16 22:10:11 server sshd[1204]: Failed password for admin from 41.230.12.5 port 51204 ssh2
Jul 16 22:10:14 server sshd[1205]: Failed password for root from 41.230.12.5 port 51205 ssh2
Jul 16 22:12:33 server sshd[1210]: Failed password for ahmed from 105.99.14.3 port 44011 ssh2
"""


def test_parse_log_lines_extracts_events():
    events = parse_log_lines(SAMPLE_LOGS.splitlines())
    assert len(events) == 6
    assert events[0]["ip"] == "41.230.12.5"
    assert events[0]["user"] == "root"


def test_detect_brute_force_flags_repeated_ip():
    events = parse_log_lines(SAMPLE_LOGS.splitlines())
    incidents = detect_brute_force(events, threshold=5, window_seconds=300)
    assert len(incidents) == 1
    assert incidents[0]["ip"] == "41.230.12.5"
    assert incidents[0]["attempts"] == 5


def test_single_attempt_not_flagged():
    events = parse_log_lines(SAMPLE_LOGS.splitlines())
    incidents = detect_brute_force(events, threshold=5, window_seconds=300)
    ips_flagged = [i["ip"] for i in incidents]
    assert "105.99.14.3" not in ips_flagged


def test_analyze_log_text_full_report():
    report = analyze_log_text(SAMPLE_LOGS, threshold=5, window_seconds=300)
    assert report["total_lines"] == 6
    assert report["failed_login_events"] == 6
    assert len(report["incidents"]) == 1


def test_ignores_unrelated_lines():
    text = "this is not a log line\nrandom text\n"
    report = analyze_log_text(text)
    assert report["failed_login_events"] == 0
    assert report["incidents"] == []
