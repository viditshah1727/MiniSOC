"""Seed MiniSOC with a realistic simulated dataset.

Builds ~7 days of telemetry: benign baseline traffic plus coherent attack
campaigns (brute force, port scans, web attacks, privilege escalation),
then runs the real detection engine over it so every alert on the dashboard
was genuinely produced by a rule — nothing is hand-planted.

Includes the flagship demo campaign: 192.168.1.105 brute-forcing SSH and
finally succeeding, which fires R001 (HIGH) and then R002 (CRITICAL).
"""
import random
from datetime import timedelta

from app.database import db
from app.detection_engine import ensure_default_rules, run_detection
from app.event_generator import (ATTACKER_IPS, OFFICE_IPS, USERS,
                                 brute_force_burst, make_firewall_block,
                                 make_malware_indicator, make_normal_login,
                                 make_privilege_escalation, make_ssh_failed,
                                 make_ssh_success, make_web_attack,
                                 port_scan_burst)
from app.models import (Alert, AnalystNote, Incident, SecurityEvent,
                        ThreatIntelEntry, User, utcnow)

ANALYSTS = ["A. Chen", "R. Patel", "J. Okafor"]

THREAT_INTEL = [
    # ip, reputation, threat_type, confidence, notes
    ("192.168.1.105", "MALICIOUS", "SSH Brute Force", 95,
     "Repeated SSH brute-force campaigns against lab servers. Demo attacker."),
    ("192.168.1.212", "MALICIOUS", "SSH Brute Force", 88,
     "Credential stuffing against multiple hosts."),
    ("172.16.34.101", "SUSPICIOUS", "Port Scanning", 72,
     "Recurring service enumeration sweeps."),
    ("172.16.34.187", "SUSPICIOUS", "SSH Brute Force", 64,
     "Low-and-slow authentication failures."),
    ("10.0.99.66", "MALICIOUS", "Malware C2 / Web Attacks", 91,
     "Hosts web attack tooling; observed C2 beaconing destination."),
    ("192.168.1.77", "MALICIOUS", "Reconnaissance", 80,
     "Port scanning followed by targeted logins."),
    ("192.168.10.25", "CLEAN", "None", 5,
     "Office workstation; included as a baseline/clean example."),
]


def _days_ago(days, hour=None, minute=None):
    ts = utcnow() - timedelta(days=days)
    if hour is not None:
        ts = ts.replace(hour=hour, minute=minute if minute is not None else
                        random.randint(0, 59), second=random.randint(0, 59))
    return ts


def seed_users():
    """Default dashboard login. Password comes from .env (DEFAULT_ANALYST_PASSWORD)
    or falls back to a documented dev-only default."""
    import os
    if User.query.filter_by(username="analyst").first():
        return
    user = User(username="analyst", display_name="SOC Analyst", role="analyst")
    user.set_password(os.environ.get("DEFAULT_ANALYST_PASSWORD", "ChangeMe_123!"))
    db.session.add(user)


def seed_threat_intel():
    now = utcnow()
    for ip, rep, ttype, conf, notes in THREAT_INTEL:
        if ThreatIntelEntry.query.filter_by(ip_address=ip).first():
            continue
        db.session.add(ThreatIntelEntry(
            ip_address=ip, reputation=rep, threat_type=ttype, confidence=conf,
            first_seen=now - timedelta(days=random.randint(8, 40)),
            last_seen=now - timedelta(hours=random.randint(1, 48)),
            source="local-simulation", notes=notes,
        ))


def seed_events():
    """Create the full 7-day simulated event history. Returns count."""
    events = []

    # --- benign baseline: office logins, noise blocks, odd typos -----------
    for day in range(7, 0, -1):
        for _ in range(random.randint(18, 26)):
            ts = _days_ago(day, hour=random.randint(6, 23))
            events.append(make_normal_login(ts))
        for _ in range(random.randint(4, 7)):
            ts = _days_ago(day, hour=random.randint(0, 23))
            events.append(make_firewall_block(random.choice(OFFICE_IPS + ATTACKER_IPS), ts))
        for _ in range(random.randint(1, 3)):   # employees mistyping passwords
            ts = _days_ago(day, hour=random.randint(8, 20))
            events.append(make_ssh_failed(random.choice(OFFICE_IPS),
                                          random.choice(USERS), ts))

    # --- campaign 1 (flagship demo): 192.168.1.105 brute force -> success --
    # Day 2: recon scan, then several brute bursts, the last one succeeds.
    events += port_scan_burst("192.168.1.105", _days_ago(2, hour=1, minute=10),
                              num_ports=14)
    events += brute_force_burst("192.168.1.105", _days_ago(2, hour=2, minute=5),
                                attempts=9)
    events += brute_force_burst("192.168.1.105", _days_ago(2, hour=3, minute=40),
                                attempts=11, succeed=True, victim_user="admin")
    # Post-compromise: privilege escalation on the same day.
    events.append(make_privilege_escalation("admin", _days_ago(2, hour=4, minute=5)))

    # Earlier probing by the same attacker days before the compromise.
    events += brute_force_burst("192.168.1.105", _days_ago(6, hour=23, minute=30),
                                attempts=7)

    # --- campaign 2: 192.168.1.212 brute force, never succeeds -------------
    for day, hour, minute, attempts in [(1, 13, 20, 12), (4, 9, 45, 8),
                                        (6, 11, 5, 9)]:
        events += brute_force_burst("192.168.1.212",
                                    _days_ago(day, hour=hour, minute=minute),
                                    attempts=attempts)

    # --- campaign 3: 172.16.34.101 recurring port scans --------------------
    for day, hour in [(6, 22), (5, 14), (3, 2), (1, 5)]:
        events += port_scan_burst("172.16.34.101", _days_ago(day, hour=hour),
                                  num_ports=random.randint(12, 18))

    # --- campaign 4: 172.16.34.187 low-and-slow brute force -----------------
    for day, hour, minute in [(5, 7, 25), (3, 16, 10), (2, 21, 50)]:
        events += brute_force_burst("172.16.34.187",
                                    _days_ago(day, hour=hour, minute=minute),
                                    attempts=random.randint(6, 9))

    # --- campaign 5: 10.0.99.66 web attacks + malware indicators ------------
    for day in (5, 4, 2, 1):
        for _ in range(random.randint(2, 4)):
            events.append(make_web_attack("10.0.99.66",
                                          _days_ago(day, hour=random.randint(0, 23))))
    for day in (4, 2):
        events.append(make_malware_indicator(_days_ago(day, hour=random.randint(6, 20))))

    # --- campaign 6: 192.168.1.77 scan then off-hours login -----------------
    for day, hour in [(5, 3), (2, 4)]:
        events += port_scan_burst("192.168.1.77", _days_ago(day, hour=hour,
                                                            minute=15),
                                  num_ports=random.randint(12, 16))
    events.append(make_ssh_success("192.168.1.77", "svc_backup",
                                   _days_ago(5, hour=3, minute=55)))

    # --- campaign 7: 10.0.99.66 also brute forces and gets in on day 3 ------
    events += brute_force_burst("10.0.99.66", _days_ago(3, hour=1, minute=30),
                                attempts=10, succeed=True,
                                victim_user="svc_deploy")

    # --- anomalous logins flagged by the (simulated) UEBA source -------------
    for day, user, ip in [(6, "dana", "192.168.10.31"),
                          (3, "bob", "192.168.10.28"),
                          (1, "erik", "192.168.10.35")]:
        anomalous = make_ssh_success(ip, user, _days_ago(day, hour=2, minute=20))
        anomalous.event_type = "SUSPICIOUS_LOGIN"
        anomalous.severity = "MEDIUM"
        events.append(anomalous)

    # --- scattered privilege-escalation indicators ---------------------------
    for day, user in [(6, "erik"), (5, "dana"), (4, "svc_backup"),
                      (3, "svc_deploy"), (2, "bob"), (1, "charlie")]:
        events.append(make_privilege_escalation(user,
                                                _days_ago(day, hour=random.randint(7, 22))))

    # --- a couple of recent events so "last hour" isn't empty ----------------
    now = utcnow()
    for minutes in (55, 40, 25, 12, 5):
        events.append(make_normal_login(now - timedelta(minutes=minutes)))
    events += brute_force_burst("192.168.1.212", now - timedelta(minutes=30),
                                attempts=6)

    db.session.add_all(events)
    db.session.commit()
    return len(events)


def seed_incidents():
    """Escalate a subset of alerts into incidents, the way an analyst would."""
    incidents_spec = [
        # (alert filter kwargs, title, status, analyst, note)
        (dict(severity="CRITICAL"),
         "Account compromise via SSH brute force",
         "INVESTIGATING", "A. Chen",
         "Confirmed successful login after brute-force burst. Pulled auth logs, "
         "session review in progress. Password reset issued for the account."),
        (dict(severity="HIGH", event_type="SSH_LOGIN_FAILED"),
         "Sustained SSH brute-force campaign",
         "CONTAINED", "R. Patel",
         "Source IP blocked at perimeter firewall. Monitoring for re-attempts "
         "from adjacent address space."),
        (dict(event_type="PRIVILEGE_ESCALATION"),
         "Unauthorised privilege escalation on server",
         "OPEN", "J. Okafor",
         "Root shell spawned outside change window. Owner contacted for "
         "verification."),
        (dict(event_type="PORT_SCAN"),
         "Internal network reconnaissance activity",
         "RESOLVED", "R. Patel",
         "Scan traced to compromised lab VM. VM re-imaged, credentials rotated. "
         "Closing after 48h of quiet."),
        (dict(event_type="SSH_LOGIN_SUCCESS"),
         "Suspicious off-hours service-account login",
         "INVESTIGATING", "A. Chen",
         "svc_backup login at 03:55 from an IP with malicious reputation. "
         "Reviewing what the session accessed."),
    ]

    created = []
    used_alert_ids = set()
    # First pass: one incident per spec, bound to a matching alert.
    for filters, title, status, analyst, note in incidents_spec:
        query = Alert.query.filter_by(**filters).order_by(Alert.timestamp.desc())
        alert = next((a for a in query.all() if a.id not in used_alert_ids), None)
        if alert is None:
            continue
        incident = _incident_from_alert(alert, title, status, analyst, note)
        used_alert_ids.add(alert.id)
        created.append(incident)

    # Second pass: escalate more alerts with generated titles until >= 12.
    remaining = [a for a in Alert.query.order_by(Alert.timestamp.desc()).all()
                 if a.id not in used_alert_ids]
    statuses = ["OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED"]
    while len(created) < 12 and remaining:
        alert = remaining.pop(0)
        status = random.choice(statuses)
        incident = _incident_from_alert(
            alert, alert.title, status, random.choice(ANALYSTS),
            "Escalated from alert during seed-data triage." if status != "OPEN"
            else None)
        used_alert_ids.add(alert.id)
        created.append(incident)
    db.session.commit()
    return len(created)


def _incident_from_alert(alert, title, status, analyst, note_text):
    incident = Incident(
        title=title,
        description=alert.description,
        severity=alert.severity,
        status=status,
        source_ip=alert.source_ip,
        affected_host=alert.hostname,
        affected_user=alert.username,
        detection_source=alert.rule.name if alert.rule else "Manual",
        mitre_technique=alert.mitre_technique,
        assigned_analyst=analyst,
        created_at=alert.timestamp + timedelta(minutes=random.randint(5, 90)),
    )
    db.session.add(incident)
    db.session.flush()          # get incident.id for the FK below
    alert.incident_id = incident.id
    if status != "NEW":
        alert.status = "INVESTIGATING" if status in ("OPEN", "INVESTIGATING") \
            else "RESOLVED"
    if note_text:
        db.session.add(AnalystNote(author=analyst, content=note_text,
                                   incident_id=incident.id,
                                   created_at=incident.created_at +
                                   timedelta(minutes=random.randint(10, 120))))
    return incident


def seed_alert_notes():
    """Sprinkle some triage notes on alerts that aren't tied to incidents."""
    notes = [
        "Checked threat intel — source IP has prior brute-force history.",
        "No successful authentication observed from this source. Monitoring.",
        "Confirmed authorised vulnerability scan window. Marking false positive.",
        "User confirmed the login. Closing as expected activity.",
    ]
    candidates = Alert.query.filter(Alert.incident_id.is_(None)).limit(8).all()
    for i, alert in enumerate(candidates):
        if i % 2 == 0:
            db.session.add(AnalystNote(
                author=random.choice(ANALYSTS), content=notes[i % len(notes)],
                alert_id=alert.id,
                created_at=alert.timestamp + timedelta(minutes=random.randint(10, 240))))
            if "false positive" in notes[i % len(notes)].lower():
                alert.status = "FALSE_POSITIVE"
    db.session.commit()


def seed_all(reset=False, verbose=True):
    """Full seed: rules, users, threat intel, events, detection run, incidents."""
    if reset:
        db.drop_all()
        db.create_all()

    random.seed(42)             # reproducible demo dataset
    ensure_default_rules()
    seed_users()
    seed_threat_intel()
    db.session.commit()

    n_events = seed_events()
    alerts = run_detection()
    n_incidents = seed_incidents()
    seed_alert_notes()

    summary = {
        "events": n_events,
        "alerts": len(alerts),
        "incidents": n_incidents,
    }
    if verbose:
        print(f"Seeded {summary['events']} events, "
              f"{summary['alerts']} alerts (via detection engine), "
              f"{summary['incidents']} incidents.")
    return summary
