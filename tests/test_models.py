"""Model tests: relationships, defaults, serialisation, password hashing."""
from datetime import datetime

from app.models import (Alert, AnalystNote, DetectionRule, Incident,
                        SecurityEvent, ThreatIntelEntry, User)


def test_security_event_defaults_and_to_dict(db):
    event = SecurityEvent(event_type="SSH_LOGIN_FAILED", source_ip="10.0.0.1",
                          username="root", result="FAILURE")
    db.session.add(event)
    db.session.commit()

    assert event.id is not None
    assert event.processed is False
    assert isinstance(event.timestamp, datetime)
    data = event.to_dict()
    assert data["event_type"] == "SSH_LOGIN_FAILED"
    assert data["source_ip"] == "10.0.0.1"


def test_alert_event_rule_relationships(db):
    event = SecurityEvent(event_type="SSH_LOGIN_FAILED", source_ip="10.0.0.9")
    rule = DetectionRule.query.filter_by(rule_code="R001").first()
    db.session.add(event)
    db.session.flush()
    alert = Alert(title="test alert", severity="HIGH", source_ip="10.0.0.9",
                  event_id=event.id, rule_id=rule.id)
    db.session.add(alert)
    db.session.commit()

    assert alert.event is event
    assert alert.rule.rule_code == "R001"
    assert alert.status == "NEW"
    assert event.alerts == [alert]
    assert alert.to_dict()["detection_rule"] == rule.name


def test_incident_links_alerts_and_notes(db):
    incident = Incident(title="test incident", severity="CRITICAL")
    db.session.add(incident)
    db.session.flush()
    alert = Alert(title="linked alert", severity="CRITICAL",
                  incident_id=incident.id)
    note = AnalystNote(author="tester", content="containment done",
                       incident_id=incident.id)
    db.session.add_all([alert, note])
    db.session.commit()

    assert incident.status == "OPEN"
    assert incident.alerts == [alert]
    assert incident.notes[0].content == "containment done"
    assert incident.to_dict()["alert_count"] == 1


def test_user_password_is_hashed(db):
    user = User.query.filter_by(username="tester").first()
    assert user.password_hash != "test-password-123"
    assert user.check_password("test-password-123")
    assert not user.check_password("wrong")


def test_threat_intel_entry(db):
    entry = ThreatIntelEntry(ip_address="192.168.1.105", reputation="MALICIOUS",
                             threat_type="SSH Brute Force", confidence=95)
    db.session.add(entry)
    db.session.commit()
    assert entry.to_dict()["reputation"] == "MALICIOUS"
