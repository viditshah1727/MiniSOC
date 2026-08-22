"""API tests: authentication, CSRF, metrics consistency, filtering,
alert workflow (status, notes, escalation), and simulation."""
from datetime import timedelta

from app.detection_engine import run_detection
from app.event_generator import brute_force_burst
from app.models import Alert, Incident, SecurityEvent, utcnow

from conftest import csrf_headers

HOST = ("web-srv-01", "10.0.0.11")


def _seed_brute_force(db, ip="192.168.1.105"):
    db.session.add_all(brute_force_burst(ip, utcnow() - timedelta(minutes=4),
                                         attempts=7, succeed=True, host=HOST))
    db.session.commit()
    return run_detection()


# ------------------------------ auth & CSRF -------------------------------

def test_api_requires_authentication(client):
    assert client.get("/api/metrics/summary").status_code == 401
    assert client.get("/api/alerts").status_code == 401


def test_pages_redirect_to_login(client):
    res = client.get("/")
    assert res.status_code == 302
    assert "/login" in res.headers["Location"]


def test_login_flow(client):
    # fetch login page first so the session gets a CSRF token
    page = client.get("/login")
    assert page.status_code == 200
    with client.session_transaction() as sess:
        token = sess["_csrf_token"]
    res = client.post("/login", data={"username": "tester",
                                      "password": "test-password-123",
                                      "csrf_token": token})
    assert res.status_code == 302
    assert client.get("/api/metrics/summary").status_code == 200


def test_login_rejects_bad_password(client):
    client.get("/login")
    with client.session_transaction() as sess:
        token = sess["_csrf_token"]
    res = client.post("/login", data={"username": "tester",
                                      "password": "wrong",
                                      "csrf_token": token})
    assert res.status_code == 401


def test_csrf_required_on_state_changes(auth_client, db):
    alerts = _seed_brute_force(db)
    alert_id = alerts[0].id
    # no CSRF header -> rejected
    res = auth_client.patch(f"/api/alerts/{alert_id}",
                            json={"status": "RESOLVED"})
    assert res.status_code == 400
    assert "CSRF" in res.get_json()["error"]


# ------------------------------ metrics -----------------------------------

def test_metrics_summary_matches_database(auth_client, db):
    _seed_brute_force(db)
    data = auth_client.get("/api/metrics/summary").get_json()
    assert data["total_events"] == SecurityEvent.query.count()
    assert data["failed_logins_24h"] == SecurityEvent.query.filter_by(
        event_type="SSH_LOGIN_FAILED").count()
    assert data["high_alerts"] == Alert.query.filter_by(severity="HIGH").count()


def test_timeline_rejects_bad_range(auth_client):
    data = auth_client.get("/api/metrics/timeline?range=99y").get_json()
    assert data["range"] == "24h"          # falls back to the default


# ------------------------------- alerts -----------------------------------

def test_alert_filtering(auth_client, db):
    _seed_brute_force(db)
    all_alerts = auth_client.get("/api/alerts").get_json()
    assert all_alerts["total"] >= 2
    high_only = auth_client.get("/api/alerts?severity=HIGH").get_json()
    assert all(a["severity"] == "HIGH" for a in high_only["items"])
    by_ip = auth_client.get("/api/alerts?source_ip=192.168.1.105").get_json()
    assert all(a["source_ip"] == "192.168.1.105" for a in by_ip["items"])
    none = auth_client.get("/api/alerts?source_ip=1.2.3.4").get_json()
    assert none["total"] == 0


def test_alert_status_update_and_validation(auth_client, db):
    alerts = _seed_brute_force(db)
    alert_id = alerts[0].id
    ok = auth_client.patch(f"/api/alerts/{alert_id}",
                           json={"status": "INVESTIGATING"},
                           headers=csrf_headers())
    assert ok.status_code == 200
    assert ok.get_json()["status"] == "INVESTIGATING"
    bad = auth_client.patch(f"/api/alerts/{alert_id}",
                            json={"status": "NOT_A_STATUS"},
                            headers=csrf_headers())
    assert bad.status_code == 400


def test_alert_notes(auth_client, db):
    alerts = _seed_brute_force(db)
    alert_id = alerts[0].id
    res = auth_client.post(f"/api/alerts/{alert_id}/notes",
                           json={"content": "checked source IP history"},
                           headers=csrf_headers())
    assert res.status_code == 201
    assert res.get_json()["author"] == "Test Analyst"
    empty = auth_client.post(f"/api/alerts/{alert_id}/notes",
                             json={"content": "  "}, headers=csrf_headers())
    assert empty.status_code == 400


def test_alert_escalation_creates_incident(auth_client, db):
    alerts = _seed_brute_force(db)
    critical = next(a for a in alerts if a.severity == "CRITICAL")
    res = auth_client.post(f"/api/alerts/{critical.id}/escalate", json={},
                           headers=csrf_headers())
    assert res.status_code == 201
    incident = res.get_json()
    assert incident["severity"] == "CRITICAL"
    assert incident["source_ip"] == critical.source_ip
    stored = db.session.get(Incident, incident["id"])
    assert stored is not None
    assert db.session.get(Alert, critical.id).incident_id == stored.id
    # escalating twice is rejected
    again = auth_client.post(f"/api/alerts/{critical.id}/escalate", json={},
                             headers=csrf_headers())
    assert again.status_code == 409


# ------------------------------ incidents ---------------------------------

def test_incident_update(auth_client, db):
    alerts = _seed_brute_force(db)
    auth_client.post(f"/api/alerts/{alerts[0].id}/escalate", json={},
                     headers=csrf_headers())
    incident = Incident.query.first()
    res = auth_client.patch(f"/api/incidents/{incident.id}",
                            json={"status": "CONTAINED",
                                  "assigned_analyst": "Test Analyst"},
                            headers=csrf_headers())
    assert res.status_code == 200
    body = res.get_json()
    assert body["status"] == "CONTAINED"
    assert body["assigned_analyst"] == "Test Analyst"
    bad = auth_client.patch(f"/api/incidents/{incident.id}",
                            json={"status": "BOGUS"}, headers=csrf_headers())
    assert bad.status_code == 400


# ------------------------------- events -----------------------------------

def test_event_listing_and_pagination(auth_client, db):
    _seed_brute_force(db)
    page = auth_client.get("/api/events?per_page=3&page=1").get_json()
    assert len(page["items"]) == 3
    assert page["total"] == SecurityEvent.query.count()
    filtered = auth_client.get(
        "/api/events?event_type=SSH_LOGIN_FAILED").get_json()
    assert all(e["event_type"] == "SSH_LOGIN_FAILED" for e in filtered["items"])


# ------------------------------ simulation --------------------------------

def test_simulate_creates_events_and_runs_detection(auth_client, db):
    before = SecurityEvent.query.count()
    res = auth_client.post("/api/simulate", json={}, headers=csrf_headers())
    assert res.status_code == 201
    body = res.get_json()
    assert body["events_created"] >= 1
    assert SecurityEvent.query.count() == before + body["events_created"]
    # every new event was processed by the engine
    assert SecurityEvent.query.filter_by(processed=False).count() == 0


# ------------------------------- reports ----------------------------------

def test_report_summary_and_csv(auth_client, db):
    _seed_brute_force(db)
    summary = auth_client.get("/api/reports/summary").get_json()
    assert summary["total_alerts"] == Alert.query.count()
    csv_res = auth_client.get("/api/reports/export.csv")
    assert csv_res.status_code == 200
    assert csv_res.mimetype == "text/csv"
    assert b"alert_id" in csv_res.data
