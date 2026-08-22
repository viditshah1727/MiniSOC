"""Detection engine tests: each rule's trigger condition, its negative case,
and alert deduplication."""
from datetime import timedelta

from app.database import db as _db
from app.detection_engine import run_detection
from app.event_generator import (brute_force_burst, make_privilege_escalation,
                                 make_ssh_failed, make_ssh_success,
                                 port_scan_burst)
from app.models import Alert, DetectionRule, SecurityEvent, ThreatIntelEntry, utcnow

HOST = ("web-srv-01", "10.0.0.11")


def _add(db, events):
    db.session.add_all(events)
    db.session.commit()


def test_r001_fires_on_five_failures(db):
    start = utcnow() - timedelta(minutes=4)
    events = [make_ssh_failed("192.168.1.50", "root",
                              start + timedelta(seconds=30 * i), host=HOST)
              for i in range(5)]
    _add(db, events)
    alerts = run_detection()
    r001 = [a for a in alerts if a.rule.rule_code == "R001"]
    assert len(r001) == 1
    assert r001[0].severity == "HIGH"
    assert r001[0].mitre_technique == "T1110"
    assert r001[0].source_ip == "192.168.1.50"


def test_r001_does_not_fire_below_threshold(db):
    start = utcnow() - timedelta(minutes=4)
    events = [make_ssh_failed("192.168.1.51", "root",
                              start + timedelta(seconds=30 * i), host=HOST)
              for i in range(4)]
    _add(db, events)
    assert run_detection() == []


def test_r001_does_not_fire_outside_window(db):
    # 5 failures spread over 50 minutes: never 5 inside any 5-minute window.
    start = utcnow() - timedelta(minutes=55)
    events = [make_ssh_failed("192.168.1.52", "root",
                              start + timedelta(minutes=10 * i), host=HOST)
              for i in range(5)]
    _add(db, events)
    assert run_detection() == []


def test_r002_fires_on_success_after_failures(db):
    start = utcnow() - timedelta(minutes=5)
    events = [make_ssh_failed("192.168.1.60", "admin",
                              start + timedelta(seconds=20 * i), host=HOST)
              for i in range(6)]
    events.append(make_ssh_success("192.168.1.60", "admin",
                                   start + timedelta(minutes=3), host=HOST))
    _add(db, events)
    alerts = run_detection()
    codes = {a.rule.rule_code for a in alerts}
    assert "R001" in codes          # the burst itself
    assert "R002" in codes          # the compromise
    critical = next(a for a in alerts if a.rule.rule_code == "R002")
    assert critical.severity == "CRITICAL"


def test_r002_ignores_clean_success(db):
    _add(db, [make_ssh_success("192.168.10.30", "alice",
                               utcnow().replace(hour=12), host=HOST)])
    assert run_detection() == []


def test_r003_fires_on_port_scan(db):
    events = port_scan_burst("172.16.34.200", utcnow() - timedelta(minutes=2),
                             num_ports=12, host=HOST)
    _add(db, events)
    alerts = run_detection()
    assert len(alerts) == 1
    assert alerts[0].rule.rule_code == "R003"
    assert alerts[0].severity == "MEDIUM"
    assert alerts[0].mitre_technique == "T1046"


def test_r003_does_not_fire_on_few_ports(db):
    events = port_scan_burst("172.16.34.201", utcnow() - timedelta(minutes=2),
                             num_ports=5, host=HOST)
    _add(db, events)
    assert run_detection() == []


def test_r004_fires_for_malicious_ip_login(db):
    db.session.add(ThreatIntelEntry(ip_address="10.0.99.66",
                                    reputation="MALICIOUS",
                                    threat_type="C2", confidence=90))
    _add(db, [make_ssh_success("10.0.99.66", "svc_backup",
                               utcnow().replace(hour=12), host=HOST)])
    alerts = run_detection()
    assert len(alerts) == 1
    assert alerts[0].rule.rule_code == "R004"
    assert alerts[0].severity == "HIGH"      # escalated for MALICIOUS reputation


def test_r005_fires_on_privilege_escalation(db):
    _add(db, [make_privilege_escalation("charlie", utcnow(), host=HOST)])
    alerts = run_detection()
    assert len(alerts) == 1
    assert alerts[0].rule.rule_code == "R005"
    assert alerts[0].mitre_technique == "T1548"


def test_detection_is_idempotent(db):
    """Re-running the engine must not duplicate alerts (processed flag +
    per-window dedup)."""
    events = brute_force_burst("192.168.1.70", utcnow() - timedelta(minutes=4),
                               attempts=7, host=HOST)
    _add(db, events)
    first = run_detection()
    second = run_detection()
    assert len(first) >= 1
    assert second == []
    assert SecurityEvent.query.filter_by(processed=False).count() == 0


def test_disabled_rule_does_not_fire(db):
    rule = DetectionRule.query.filter_by(rule_code="R001").first()
    rule.enabled = False
    db.session.commit()
    events = [make_ssh_failed("192.168.1.80", "root",
                              utcnow() - timedelta(seconds=30 * i), host=HOST)
              for i in range(6)]
    _add(db, events)
    alerts = run_detection()
    assert all(a.rule.rule_code != "R001" for a in alerts)


def test_alert_created_in_database(db):
    events = brute_force_burst("192.168.1.90", utcnow() - timedelta(minutes=4),
                               attempts=6, host=HOST)
    _add(db, events)
    run_detection()
    stored = Alert.query.filter_by(source_ip="192.168.1.90").all()
    assert len(stored) == 1
    assert stored[0].event_id is not None
    assert stored[0].status == "NEW"
