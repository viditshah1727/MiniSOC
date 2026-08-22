"""Database models for MiniSOC.

Data flow: SecurityEvent (raw telemetry) -> Alert (a detection rule matched)
-> Incident (an analyst confirmed something is worth tracking).
AnalystNote rows can attach to either an alert or an incident.
"""
from datetime import datetime, timezone

from werkzeug.security import check_password_hash, generate_password_hash

from app.database import db

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
ALERT_STATUSES = ["NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"]
INCIDENT_STATUSES = ["OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED"]

EVENT_TYPES = [
    "SSH_LOGIN_FAILED",
    "SSH_LOGIN_SUCCESS",
    "PORT_SCAN",
    "SUSPICIOUS_LOGIN",
    "PRIVILEGE_ESCALATION",
    "WEB_ATTACK",
    "MALWARE_INDICATOR",
    "FIREWALL_BLOCK",
]


def utcnow():
    """Naive UTC timestamp — SQLite stores naive datetimes, so the whole app
    standardises on naive UTC to keep comparisons consistent."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class SecurityEvent(db.Model):
    """One raw security event (a parsed log line in a real deployment).

    ``processed`` marks whether the detection engine has already evaluated
    the event, so the engine can be re-run safely without duplicate alerts.
    """
    __tablename__ = "security_events"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)
    event_type = db.Column(db.String(50), nullable=False, index=True)
    source_ip = db.Column(db.String(45), index=True)          # 45 chars fits IPv6
    destination_ip = db.Column(db.String(45))
    source_port = db.Column(db.Integer)
    destination_port = db.Column(db.Integer)
    protocol = db.Column(db.String(10))
    username = db.Column(db.String(80), index=True)
    hostname = db.Column(db.String(120), index=True)
    action = db.Column(db.String(80))
    result = db.Column(db.String(20))                          # SUCCESS / FAILURE / BLOCKED
    severity = db.Column(db.String(10), default="INFO")
    raw_log = db.Column(db.Text)
    processed = db.Column(db.Boolean, default=False, nullable=False, index=True)

    alerts = db.relationship("Alert", back_populates="event")

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "event_type": self.event_type,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "username": self.username,
            "hostname": self.hostname,
            "action": self.action,
            "result": self.result,
            "severity": self.severity,
            "raw_log": self.raw_log,
        }


class DetectionRule(db.Model):
    """A detection rule. The matching logic lives in detection_engine.py and is
    looked up by ``rule_code``; the row holds tunable parameters and metadata
    so rules can be enabled/disabled and tuned without code changes."""
    __tablename__ = "detection_rules"

    id = db.Column(db.Integer, primary_key=True)
    rule_code = db.Column(db.String(20), unique=True, nullable=False)   # e.g. R001
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.String(10), nullable=False)
    mitre_technique = db.Column(db.String(20))
    mitre_name = db.Column(db.String(120))
    threshold = db.Column(db.Integer)          # e.g. number of failures
    window_minutes = db.Column(db.Integer)     # e.g. time window for the threshold
    enabled = db.Column(db.Boolean, default=True, nullable=False)

    alerts = db.relationship("Alert", back_populates="rule")

    def to_dict(self):
        return {
            "id": self.id,
            "rule_code": self.rule_code,
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "mitre_technique": self.mitre_technique,
            "mitre_name": self.mitre_name,
            "threshold": self.threshold,
            "window_minutes": self.window_minutes,
            "enabled": self.enabled,
        }


class Alert(db.Model):
    """Raised by the detection engine when a rule matches one or more events."""
    __tablename__ = "alerts"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.String(10), nullable=False, index=True)
    status = db.Column(db.String(20), nullable=False, default="NEW", index=True)
    source_ip = db.Column(db.String(45), index=True)
    destination_ip = db.Column(db.String(45))
    source_port = db.Column(db.Integer)
    destination_port = db.Column(db.Integer)
    username = db.Column(db.String(80))
    hostname = db.Column(db.String(120))
    event_type = db.Column(db.String(50))
    mitre_technique = db.Column(db.String(20), index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=utcnow, onupdate=utcnow)

    event_id = db.Column(db.Integer, db.ForeignKey("security_events.id"))
    rule_id = db.Column(db.Integer, db.ForeignKey("detection_rules.id"))
    incident_id = db.Column(db.Integer, db.ForeignKey("incidents.id"))

    event = db.relationship("SecurityEvent", back_populates="alerts")
    rule = db.relationship("DetectionRule", back_populates="alerts")
    incident = db.relationship("Incident", back_populates="alerts")
    notes = db.relationship("AnalystNote", back_populates="alert",
                            order_by="AnalystNote.created_at")

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "status": self.status,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "username": self.username,
            "hostname": self.hostname,
            "event_type": self.event_type,
            "mitre_technique": self.mitre_technique,
            "detection_rule": self.rule.name if self.rule else None,
            "rule_code": self.rule.rule_code if self.rule else None,
            "event_id": self.event_id,
            "incident_id": self.incident_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class Incident(db.Model):
    """A tracked investigation, usually escalated from one or more alerts."""
    __tablename__ = "incidents"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.String(10), nullable=False, index=True)
    status = db.Column(db.String(20), nullable=False, default="OPEN", index=True)
    source_ip = db.Column(db.String(45))
    affected_host = db.Column(db.String(120))
    affected_user = db.Column(db.String(80))
    detection_source = db.Column(db.String(120))
    mitre_technique = db.Column(db.String(20))
    assigned_analyst = db.Column(db.String(80))
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)
    updated_at = db.Column(db.DateTime, nullable=False, default=utcnow, onupdate=utcnow)

    alerts = db.relationship("Alert", back_populates="incident")
    notes = db.relationship("AnalystNote", back_populates="incident",
                            order_by="AnalystNote.created_at")

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "status": self.status,
            "source_ip": self.source_ip,
            "affected_host": self.affected_host,
            "affected_user": self.affected_user,
            "detection_source": self.detection_source,
            "mitre_technique": self.mitre_technique,
            "assigned_analyst": self.assigned_analyst,
            "alert_count": len(self.alerts),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class AnalystNote(db.Model):
    """Free-text note added by an analyst to an alert or an incident."""
    __tablename__ = "analyst_notes"

    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(80), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    alert_id = db.Column(db.Integer, db.ForeignKey("alerts.id"))
    incident_id = db.Column(db.Integer, db.ForeignKey("incidents.id"))

    alert = db.relationship("Alert", back_populates="notes")
    incident = db.relationship("Incident", back_populates="notes")

    def to_dict(self):
        return {
            "id": self.id,
            "author": self.author,
            "content": self.content,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class ThreatIntelEntry(db.Model):
    """Local threat-intelligence record for an IP address.

    Version 1 is fully local/simulated; the schema mirrors what an external
    feed (AbuseIPDB, OTX, ...) would return so a real integration can simply
    upsert into this table later.
    """
    __tablename__ = "threat_intel"

    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False, index=True)
    reputation = db.Column(db.String(20), nullable=False)      # MALICIOUS / SUSPICIOUS / CLEAN
    threat_type = db.Column(db.String(80))
    confidence = db.Column(db.Integer, default=0)              # 0 - 100
    first_seen = db.Column(db.DateTime)
    last_seen = db.Column(db.DateTime)
    source = db.Column(db.String(80), default="local-simulation")
    notes = db.Column(db.Text)

    def to_dict(self):
        return {
            "id": self.id,
            "ip_address": self.ip_address,
            "reputation": self.reputation,
            "threat_type": self.threat_type,
            "confidence": self.confidence,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "source": self.source,
            "notes": self.notes,
        }


class User(db.Model):
    """Dashboard user (SOC analyst). Passwords are stored as salted hashes."""
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    display_name = db.Column(db.String(120))
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(30), default="analyst")
    created_at = db.Column(db.DateTime, default=utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
