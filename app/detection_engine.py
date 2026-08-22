"""MiniSOC detection engine.

The engine reads SecurityEvent rows that have not been processed yet,
evaluates each one against the enabled detection rules, and creates Alert
rows when a rule matches. Rule metadata and tunable parameters (threshold,
time window, severity, MITRE mapping, enabled flag) live in the
DetectionRule table; the matching logic itself lives in this module and is
looked up by ``rule_code``.

Because correlation rules (brute force, port scan) need history, each rule
queries back over the event table within its configured time window —
exactly how a SIEM correlation search works, just on a smaller scale.
"""
from datetime import timedelta

from app.database import db
from app.models import Alert, DetectionRule, SecurityEvent, ThreatIntelEntry

# Rule definitions seeded into the DetectionRule table. Logic is keyed by rule_code.
DEFAULT_RULES = [
    {
        "rule_code": "R001",
        "name": "SSH Brute Force",
        "description": "5 or more failed SSH login attempts from the same source IP "
                       "within 5 minutes.",
        "severity": "HIGH",
        "mitre_technique": "T1110",
        "mitre_name": "Brute Force",
        "threshold": 5,
        "window_minutes": 5,
    },
    {
        "rule_code": "R002",
        "name": "Successful Login After Brute Force",
        "description": "A successful SSH login from a source IP that produced 3 or "
                       "more failed logins in the previous 10 minutes — possible "
                       "account compromise.",
        "severity": "CRITICAL",
        "mitre_technique": "T1110",
        "mitre_name": "Brute Force -> Valid Accounts (T1110 / T1078)",
        "threshold": 3,
        "window_minutes": 10,
    },
    {
        "rule_code": "R003",
        "name": "Port Scan Detected",
        "description": "One source IP probed 10 or more distinct destination ports "
                       "within 3 minutes.",
        "severity": "MEDIUM",
        "mitre_technique": "T1046",
        "mitre_name": "Network Service Discovery",
        "threshold": 10,
        "window_minutes": 3,
    },
    {
        "rule_code": "R004",
        "name": "Suspicious Login",
        "description": "A successful login from an IP with a bad threat-intel "
                       "reputation, or interactive login during unusual hours "
                       "(00:00-05:00 UTC).",
        "severity": "MEDIUM",
        "mitre_technique": "T1078",
        "mitre_name": "Valid Accounts",
        "threshold": 1,
        "window_minutes": 60,
    },
    {
        "rule_code": "R005",
        "name": "Privilege Escalation Indicator",
        "description": "Suspicious sudo/root activity: sudoers modification, root "
                       "shell spawned, or repeated sudo authentication failures.",
        "severity": "HIGH",
        "mitre_technique": "T1548",
        "mitre_name": "Abuse Elevation Control Mechanism",
        "threshold": 1,
        "window_minutes": 30,
    },
]

# Investigation playbook shown on the alert detail page, per rule.
INVESTIGATION_STEPS = {
    "R001": [
        "Confirm the volume and time span of failed logins from this source IP.",
        "Check which usernames were targeted — spraying many users vs. hammering one.",
        "Look for any SSH_LOGIN_SUCCESS from the same IP after the failures.",
        "Check threat intelligence for the source IP.",
        "If ongoing, block the source IP at the firewall / fail2ban and document it.",
    ],
    "R002": [
        "Treat as possible account compromise until proven otherwise.",
        "Identify the account that logged in and the number of failures preceding it.",
        "Review what the session did after login (commands, sudo usage, new files).",
        "Force a password reset and invalidate active sessions for the account.",
        "Escalate to an incident and consider isolating the affected host.",
    ],
    "R003": [
        "Identify which ports/services were probed and whether any are exposed.",
        "Check if the scan was followed by connection attempts to open services.",
        "Verify whether the source IP is an authorised scanner (vuln management).",
        "Check threat intelligence for the source IP; block it if malicious.",
    ],
    "R004": [
        "Verify with the account owner whether the login was expected.",
        "Compare the source IP and login time against the account's normal pattern.",
        "Check threat intelligence for the source IP.",
        "If unauthorised, reset credentials and review account activity since login.",
    ],
    "R005": [
        "Identify the exact command and whether it succeeded.",
        "Establish how the user obtained elevation (sudoers entry, misconfig, exploit).",
        "Review the user's recent history for staging activity (downloads, new tools).",
        "If unauthorised, contain the host and escalate to an incident.",
    ],
}


def ensure_default_rules():
    """Insert any missing default rules (idempotent)."""
    for spec in DEFAULT_RULES:
        if not DetectionRule.query.filter_by(rule_code=spec["rule_code"]).first():
            db.session.add(DetectionRule(**spec))
    db.session.commit()


def _get_rule(code):
    return DetectionRule.query.filter_by(rule_code=code, enabled=True).first()


def _already_alerted(rule, source_ip, since):
    """Deduplication: one alert per (rule, source IP) per time window."""
    return db.session.query(Alert.id).filter(
        Alert.rule_id == rule.id,
        Alert.source_ip == source_ip,
        Alert.timestamp >= since,
    ).first() is not None


def _create_alert(rule, event, title, description, severity=None):
    alert = Alert(
        timestamp=event.timestamp,
        title=title,
        description=description,
        severity=severity or rule.severity,
        status="NEW",
        source_ip=event.source_ip,
        destination_ip=event.destination_ip,
        source_port=event.source_port,
        destination_port=event.destination_port,
        username=event.username,
        hostname=event.hostname,
        event_type=event.event_type,
        mitre_technique=rule.mitre_technique,
        event_id=event.id,
        rule_id=rule.id,
    )
    db.session.add(alert)
    return alert


# --------------------------------------------------------------------------
# Rule logic. Each function receives one event and returns an Alert or None.
# --------------------------------------------------------------------------

def check_ssh_brute_force(event):
    """R001 — >= threshold failed SSH logins from one IP inside the window."""
    if event.event_type != "SSH_LOGIN_FAILED" or not event.source_ip:
        return None
    rule = _get_rule("R001")
    if rule is None:
        return None
    window_start = event.timestamp - timedelta(minutes=rule.window_minutes)
    failures = SecurityEvent.query.filter(
        SecurityEvent.event_type == "SSH_LOGIN_FAILED",
        SecurityEvent.source_ip == event.source_ip,
        SecurityEvent.timestamp >= window_start,
        SecurityEvent.timestamp <= event.timestamp,
    ).count()
    if failures < rule.threshold:
        return None
    if _already_alerted(rule, event.source_ip, window_start):
        return None
    targeted = [row[0] for row in db.session.query(SecurityEvent.username).filter(
        SecurityEvent.event_type == "SSH_LOGIN_FAILED",
        SecurityEvent.source_ip == event.source_ip,
        SecurityEvent.timestamp >= window_start,
        SecurityEvent.username.isnot(None),
    ).distinct().all()]
    return _create_alert(
        rule, event,
        title=f"SSH brute force from {event.source_ip}",
        description=(f"{failures} failed SSH logins from {event.source_ip} against "
                     f"{event.hostname or 'unknown host'} within "
                     f"{rule.window_minutes} minutes. Targeted accounts: "
                     f"{', '.join(targeted) or 'unknown'}."),
    )


def check_success_after_brute_force(event):
    """R002 — successful SSH login preceded by a burst of failures from same IP."""
    if event.event_type != "SSH_LOGIN_SUCCESS" or not event.source_ip:
        return None
    rule = _get_rule("R002")
    if rule is None:
        return None
    window_start = event.timestamp - timedelta(minutes=rule.window_minutes)
    prior_failures = SecurityEvent.query.filter(
        SecurityEvent.event_type == "SSH_LOGIN_FAILED",
        SecurityEvent.source_ip == event.source_ip,
        SecurityEvent.timestamp >= window_start,
        SecurityEvent.timestamp < event.timestamp,
    ).count()
    if prior_failures < rule.threshold:
        return None
    if _already_alerted(rule, event.source_ip, window_start):
        return None
    return _create_alert(
        rule, event,
        title=f"Possible account compromise: successful login after brute force "
              f"({event.source_ip})",
        description=(f"Account '{event.username}' logged in successfully on "
                     f"{event.hostname or 'unknown host'} from {event.source_ip} "
                     f"after {prior_failures} failed attempts in the previous "
                     f"{rule.window_minutes} minutes. Treat as compromised until "
                     f"verified."),
    )


def check_port_scan(event):
    """R003 — one source IP probing many distinct ports inside the window."""
    if event.event_type not in ("PORT_SCAN", "FIREWALL_BLOCK") or not event.source_ip:
        return None
    rule = _get_rule("R003")
    if rule is None:
        return None
    window_start = event.timestamp - timedelta(minutes=rule.window_minutes)
    distinct_ports = db.session.query(SecurityEvent.destination_port).filter(
        SecurityEvent.event_type.in_(["PORT_SCAN", "FIREWALL_BLOCK"]),
        SecurityEvent.source_ip == event.source_ip,
        SecurityEvent.timestamp >= window_start,
        SecurityEvent.timestamp <= event.timestamp,
        SecurityEvent.destination_port.isnot(None),
    ).distinct().count()
    if distinct_ports < rule.threshold:
        return None
    if _already_alerted(rule, event.source_ip, window_start):
        return None
    return _create_alert(
        rule, event,
        title=f"Port scan from {event.source_ip}",
        description=(f"{event.source_ip} probed {distinct_ports} distinct ports on "
                     f"{event.destination_ip or 'multiple hosts'} within "
                     f"{rule.window_minutes} minutes — likely service enumeration "
                     f"prior to an attack."),
    )


def check_suspicious_login(event):
    """R004 — successful login from a bad-reputation IP or at unusual hours."""
    if event.event_type not in ("SSH_LOGIN_SUCCESS", "SUSPICIOUS_LOGIN"):
        return None
    if not event.source_ip:
        return None
    rule = _get_rule("R004")
    if rule is None:
        return None

    reasons = []
    severity = None
    intel = ThreatIntelEntry.query.filter_by(ip_address=event.source_ip).first()
    if intel and intel.reputation in ("MALICIOUS", "SUSPICIOUS"):
        reasons.append(f"source IP has {intel.reputation} threat-intel reputation "
                       f"({intel.threat_type}, confidence {intel.confidence}%)")
        if intel.reputation == "MALICIOUS":
            severity = "HIGH"   # escalate above the rule's default MEDIUM
    if event.timestamp.hour < 5:
        reasons.append(f"login at unusual hour ({event.timestamp.strftime('%H:%M')} UTC)")
    if event.event_type == "SUSPICIOUS_LOGIN":
        reasons.append("login flagged as anomalous by the event source")

    if not reasons:
        return None
    window_start = event.timestamp - timedelta(minutes=rule.window_minutes)
    if _already_alerted(rule, event.source_ip, window_start):
        return None
    return _create_alert(
        rule, event,
        title=f"Suspicious login for '{event.username}' from {event.source_ip}",
        description=(f"Successful login for '{event.username}' on "
                     f"{event.hostname or 'unknown host'}: " + "; ".join(reasons) + "."),
        severity=severity,
    )


def check_privilege_escalation(event):
    """R005 — suspicious sudo/root activity reported by the host."""
    if event.event_type != "PRIVILEGE_ESCALATION":
        return None
    rule = _get_rule("R005")
    if rule is None:
        return None
    window_start = event.timestamp - timedelta(minutes=rule.window_minutes)
    if _already_alerted(rule, event.source_ip or event.hostname, window_start):
        return None
    return _create_alert(
        rule, event,
        title=f"Privilege escalation indicator on {event.hostname or 'unknown host'}",
        description=(f"User '{event.username}' triggered a privilege-escalation "
                     f"indicator on {event.hostname}: {event.action} "
                     f"(result: {event.result})."),
    )


# Order matters: R002 must see the success event before R004 to give the
# compromise alert precedence in the timeline.
RULE_CHECKS = [
    check_ssh_brute_force,
    check_success_after_brute_force,
    check_port_scan,
    check_suspicious_login,
    check_privilege_escalation,
]


def process_event(event):
    """Run every rule against one event; returns the list of alerts created."""
    created = []
    for check in RULE_CHECKS:
        alert = check(event)
        if alert is not None:
            created.append(alert)
    event.processed = True
    return created


def run_detection(limit=None):
    """Process all unprocessed events in chronological order.

    Returns the list of created Alert objects. Commits once at the end so a
    failure mid-run doesn't leave half-marked events.
    """
    query = SecurityEvent.query.filter_by(processed=False).order_by(
        SecurityEvent.timestamp.asc(), SecurityEvent.id.asc())
    if limit:
        query = query.limit(limit)
    created = []
    for event in query.all():
        created.extend(process_event(event))
    db.session.commit()
    return created
