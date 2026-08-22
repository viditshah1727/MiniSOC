"""JSON REST API. Everything shown on the dashboard — KPI cards, charts,
tables, filters — is served from these endpoints, which query SQLite through
SQLAlchemy (parameterised queries throughout).

All state-changing endpoints require a valid session AND a CSRF token
(enforced globally in app/__init__.py).
"""
import csv
import io
from datetime import datetime, timedelta
from functools import wraps

from flask import Blueprint, Response, jsonify, request, session

from app.database import db
from app.detection_engine import INVESTIGATION_STEPS, run_detection
from app.event_generator import generate_live_batch
from app.mitre import MITRE_TECHNIQUES
from app.models import (ALERT_STATUSES, INCIDENT_STATUSES, SEVERITIES, Alert,
                        AnalystNote, DetectionRule, Incident, SecurityEvent,
                        ThreatIntelEntry, utcnow)

api_bp = Blueprint("api", __name__)

RANGES = {"1h": timedelta(hours=1), "6h": timedelta(hours=6),
          "24h": timedelta(hours=24), "7d": timedelta(days=7)}
BUCKET_MINUTES = {"1h": 5, "6h": 30, "24h": 60, "7d": 360}

ATTACK_CATEGORIES = {
    "SSH_LOGIN_FAILED": "Brute Force",
    "PORT_SCAN": "Port Scanning",
    "SUSPICIOUS_LOGIN": "Suspicious Login",
    "PRIVILEGE_ESCALATION": "Privilege Escalation",
    "WEB_ATTACK": "Web Attack",
    "MALWARE_INDICATOR": "Malware Indicator",
}


def api_login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return jsonify(error="Authentication required"), 401
        return view(*args, **kwargs)
    return wrapped


# --------------------------- validation helpers ---------------------------

def _int_arg(name, default, lo, hi):
    try:
        value = int(request.args.get(name, default))
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, value))


def _enum_arg(name, allowed):
    value = request.args.get(name, "").strip().upper()
    return value if value in allowed else None


def _date_arg(name):
    raw = request.args.get(name, "").strip()
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        return None


def _range_arg(default="24h"):
    value = request.args.get("range", default)
    return value if value in RANGES else default


def _paginate(query):
    page = _int_arg("page", 1, 1, 10_000)
    per_page = _int_arg("per_page", 25, 1, 100)
    total = query.count()
    items = query.offset((page - 1) * per_page).limit(per_page).all()
    pages = max(1, -(-total // per_page))
    return {"items": [i.to_dict() for i in items], "page": page,
            "per_page": per_page, "total": total, "pages": pages}


# ------------------------------- metrics ----------------------------------

@api_bp.route("/metrics/summary")
@api_login_required
def metrics_summary():
    last_24h = utcnow() - timedelta(hours=24)
    active = ["OPEN", "INVESTIGATING", "CONTAINED"]
    return jsonify({
        "total_events": db.session.query(SecurityEvent.id).count(),
        "critical_alerts": Alert.query.filter(
            Alert.severity == "CRITICAL",
            Alert.status.in_(["NEW", "INVESTIGATING"])).count(),
        "high_alerts": Alert.query.filter(
            Alert.severity == "HIGH",
            Alert.status.in_(["NEW", "INVESTIGATING"])).count(),
        "active_incidents": Incident.query.filter(
            Incident.status.in_(active)).count(),
        "failed_logins_24h": SecurityEvent.query.filter(
            SecurityEvent.event_type == "SSH_LOGIN_FAILED",
            SecurityEvent.timestamp >= last_24h).count(),
        "unique_source_ips_24h": db.session.query(SecurityEvent.source_ip)
            .filter(SecurityEvent.timestamp >= last_24h,
                    SecurityEvent.source_ip.isnot(None)).distinct().count(),
        "generated_at": utcnow().isoformat(),
    })


@api_bp.route("/metrics/timeline")
@api_login_required
def metrics_timeline():
    rng = _range_arg()
    since = utcnow() - RANGES[rng]
    bucket = timedelta(minutes=BUCKET_MINUTES[rng])

    def bucketise(timestamps):
        counts = {}
        for (ts,) in timestamps:
            slot = since + bucket * int((ts - since) / bucket)
            counts[slot] = counts.get(slot, 0) + 1
        return counts

    event_counts = bucketise(db.session.query(SecurityEvent.timestamp)
                             .filter(SecurityEvent.timestamp >= since).all())
    alert_counts = bucketise(db.session.query(Alert.timestamp)
                             .filter(Alert.timestamp >= since).all())

    labels, events_series, alerts_series = [], [], []
    slot = since
    now = utcnow()
    while slot <= now:
        labels.append(slot.isoformat())
        events_series.append(event_counts.get(slot, 0))
        alerts_series.append(alert_counts.get(slot, 0))
        slot += bucket
    return jsonify({"range": rng, "labels": labels,
                    "events": events_series, "alerts": alerts_series})


@api_bp.route("/metrics/severity")
@api_login_required
def metrics_severity():
    rows = (db.session.query(Alert.severity, db.func.count(Alert.id))
            .group_by(Alert.severity).all())
    counts = dict(rows)
    return jsonify({sev: counts.get(sev, 0) for sev in SEVERITIES})


@api_bp.route("/metrics/top-ips")
@api_login_required
def metrics_top_ips():
    rng = _range_arg("7d")
    since = utcnow() - RANGES[rng]
    rows = (db.session.query(SecurityEvent.source_ip,
                             db.func.count(SecurityEvent.id))
            .filter(SecurityEvent.timestamp >= since,
                    SecurityEvent.source_ip.isnot(None),
                    SecurityEvent.event_type.in_(list(ATTACK_CATEGORIES)))
            .group_by(SecurityEvent.source_ip)
            .order_by(db.func.count(SecurityEvent.id).desc())
            .limit(10).all())
    return jsonify([{"ip": ip, "count": count} for ip, count in rows])


@api_bp.route("/metrics/categories")
@api_login_required
def metrics_categories():
    rng = _range_arg("7d")
    since = utcnow() - RANGES[rng]
    rows = (db.session.query(SecurityEvent.event_type,
                             db.func.count(SecurityEvent.id))
            .filter(SecurityEvent.timestamp >= since,
                    SecurityEvent.event_type.in_(list(ATTACK_CATEGORIES)))
            .group_by(SecurityEvent.event_type).all())
    counts = {}
    for event_type, count in rows:
        label = ATTACK_CATEGORIES[event_type]
        counts[label] = counts.get(label, 0) + count
    return jsonify(counts)


# -------------------------------- alerts ----------------------------------

def _filtered_alerts_query():
    query = Alert.query
    severity = _enum_arg("severity", SEVERITIES)
    if severity:
        query = query.filter(Alert.severity == severity)
    status = _enum_arg("status", ALERT_STATUSES)
    if status:
        query = query.filter(Alert.status == status)
    source_ip = request.args.get("source_ip", "").strip()
    if source_ip and len(source_ip) <= 45:
        query = query.filter(Alert.source_ip == source_ip)
    date_from = _date_arg("date_from")
    if date_from:
        query = query.filter(Alert.timestamp >= date_from)
    date_to = _date_arg("date_to")
    if date_to:
        query = query.filter(Alert.timestamp <= date_to + timedelta(days=1))
    q = request.args.get("q", "").strip()
    if q and len(q) <= 120:
        like = f"%{q}%"
        query = query.filter(db.or_(Alert.title.ilike(like),
                                    Alert.description.ilike(like),
                                    Alert.source_ip.ilike(like),
                                    Alert.username.ilike(like),
                                    Alert.hostname.ilike(like),
                                    Alert.mitre_technique.ilike(like)))
    return query


@api_bp.route("/alerts")
@api_login_required
def list_alerts():
    query = _filtered_alerts_query().order_by(Alert.timestamp.desc())
    return jsonify(_paginate(query))


@api_bp.route("/alerts/recent")
@api_login_required
def recent_alerts():
    limit = _int_arg("limit", 8, 1, 25)
    query = (Alert.query.filter(Alert.severity.in_(["CRITICAL", "HIGH"]))
             .order_by(Alert.timestamp.desc()).limit(limit))
    return jsonify([a.to_dict() for a in query.all()])


@api_bp.route("/alerts/<int:alert_id>")
@api_login_required
def get_alert(alert_id):
    alert = db.session.get(Alert, alert_id)
    if alert is None:
        return jsonify(error="Not found"), 404
    data = alert.to_dict()
    data["notes"] = [n.to_dict() for n in alert.notes]
    data["raw_log"] = alert.event.raw_log if alert.event else None
    data["investigation_steps"] = INVESTIGATION_STEPS.get(
        alert.rule.rule_code if alert.rule else "", [])
    return jsonify(data)


@api_bp.route("/alerts/<int:alert_id>", methods=["PATCH"])
@api_login_required
def update_alert(alert_id):
    alert = db.session.get(Alert, alert_id)
    if alert is None:
        return jsonify(error="Not found"), 404
    payload = request.get_json(silent=True) or {}
    status = str(payload.get("status", "")).strip().upper()
    if status not in ALERT_STATUSES:
        return jsonify(error=f"status must be one of {ALERT_STATUSES}"), 400
    alert.status = status
    db.session.commit()
    return jsonify(alert.to_dict())


@api_bp.route("/alerts/<int:alert_id>/notes", methods=["POST"])
@api_login_required
def add_alert_note(alert_id):
    alert = db.session.get(Alert, alert_id)
    if alert is None:
        return jsonify(error="Not found"), 404
    payload = request.get_json(silent=True) or {}
    content = str(payload.get("content", "")).strip()
    if not content or len(content) > 4000:
        return jsonify(error="Note must be 1-4000 characters"), 400
    note = AnalystNote(author=session.get("display_name", "analyst"),
                       content=content, alert_id=alert.id)
    db.session.add(note)
    db.session.commit()
    return jsonify(note.to_dict()), 201


@api_bp.route("/alerts/<int:alert_id>/escalate", methods=["POST"])
@api_login_required
def escalate_alert(alert_id):
    """Create an incident from an alert — the alert -> incident workflow."""
    alert = db.session.get(Alert, alert_id)
    if alert is None:
        return jsonify(error="Not found"), 404
    if alert.incident_id:
        return jsonify(error="Alert is already linked to an incident",
                       incident_id=alert.incident_id), 409
    payload = request.get_json(silent=True) or {}
    title = str(payload.get("title", "")).strip() or alert.title
    if len(title) > 200:
        return jsonify(error="Title too long (max 200)"), 400

    incident = Incident(
        title=title,
        description=alert.description,
        severity=alert.severity,
        status="OPEN",
        source_ip=alert.source_ip,
        affected_host=alert.hostname,
        affected_user=alert.username,
        detection_source=alert.rule.name if alert.rule else "Manual",
        mitre_technique=alert.mitre_technique,
        assigned_analyst=session.get("display_name", "analyst"),
    )
    db.session.add(incident)
    db.session.flush()
    alert.incident_id = incident.id
    if alert.status == "NEW":
        alert.status = "INVESTIGATING"
    db.session.commit()
    return jsonify(incident.to_dict()), 201


# ------------------------------- incidents --------------------------------

@api_bp.route("/incidents")
@api_login_required
def list_incidents():
    query = Incident.query
    severity = _enum_arg("severity", SEVERITIES)
    if severity:
        query = query.filter(Incident.severity == severity)
    status = _enum_arg("status", INCIDENT_STATUSES)
    if status:
        query = query.filter(Incident.status == status)
    q = request.args.get("q", "").strip()
    if q and len(q) <= 120:
        like = f"%{q}%"
        query = query.filter(db.or_(Incident.title.ilike(like),
                                    Incident.description.ilike(like),
                                    Incident.source_ip.ilike(like),
                                    Incident.affected_host.ilike(like),
                                    Incident.affected_user.ilike(like)))
    query = query.order_by(Incident.created_at.desc())
    return jsonify(_paginate(query))


@api_bp.route("/incidents/recent")
@api_login_required
def recent_incidents():
    limit = _int_arg("limit", 6, 1, 25)
    query = Incident.query.order_by(Incident.created_at.desc()).limit(limit)
    return jsonify([i.to_dict() for i in query.all()])


@api_bp.route("/incidents/<int:incident_id>", methods=["PATCH"])
@api_login_required
def update_incident(incident_id):
    incident = db.session.get(Incident, incident_id)
    if incident is None:
        return jsonify(error="Not found"), 404
    payload = request.get_json(silent=True) or {}
    changed = False
    if "status" in payload:
        status = str(payload["status"]).strip().upper()
        if status not in INCIDENT_STATUSES:
            return jsonify(error=f"status must be one of {INCIDENT_STATUSES}"), 400
        incident.status = status
        changed = True
    if "assigned_analyst" in payload:
        analyst = str(payload["assigned_analyst"]).strip()
        if len(analyst) > 80:
            return jsonify(error="Analyst name too long (max 80)"), 400
        incident.assigned_analyst = analyst or None
        changed = True
    if not changed:
        return jsonify(error="Nothing to update"), 400
    db.session.commit()
    return jsonify(incident.to_dict())


@api_bp.route("/incidents/<int:incident_id>/notes", methods=["POST"])
@api_login_required
def add_incident_note(incident_id):
    incident = db.session.get(Incident, incident_id)
    if incident is None:
        return jsonify(error="Not found"), 404
    payload = request.get_json(silent=True) or {}
    content = str(payload.get("content", "")).strip()
    if not content or len(content) > 4000:
        return jsonify(error="Note must be 1-4000 characters"), 400
    note = AnalystNote(author=session.get("display_name", "analyst"),
                       content=content, incident_id=incident.id)
    db.session.add(note)
    db.session.commit()
    return jsonify(note.to_dict()), 201


# -------------------------------- events ----------------------------------

@api_bp.route("/events")
@api_login_required
def list_events():
    query = SecurityEvent.query
    event_type = request.args.get("event_type", "").strip().upper()
    if event_type and len(event_type) <= 50:
        query = query.filter(SecurityEvent.event_type == event_type)
    severity = _enum_arg("severity", SEVERITIES)
    if severity:
        query = query.filter(SecurityEvent.severity == severity)
    for field in ("source_ip", "username", "hostname", "result"):
        value = request.args.get(field, "").strip()
        if value and len(value) <= 120:
            query = query.filter(getattr(SecurityEvent, field) == value)
    date_from = _date_arg("date_from")
    if date_from:
        query = query.filter(SecurityEvent.timestamp >= date_from)
    date_to = _date_arg("date_to")
    if date_to:
        query = query.filter(SecurityEvent.timestamp <= date_to + timedelta(days=1))
    q = request.args.get("q", "").strip()
    if q and len(q) <= 120:
        like = f"%{q}%"
        query = query.filter(db.or_(SecurityEvent.raw_log.ilike(like),
                                    SecurityEvent.source_ip.ilike(like),
                                    SecurityEvent.username.ilike(like),
                                    SecurityEvent.hostname.ilike(like),
                                    SecurityEvent.action.ilike(like)))
    query = query.order_by(SecurityEvent.timestamp.desc())
    return jsonify(_paginate(query))


@api_bp.route("/events/<int:event_id>")
@api_login_required
def get_event(event_id):
    event = db.session.get(SecurityEvent, event_id)
    if event is None:
        return jsonify(error="Not found"), 404
    data = event.to_dict()
    data["alerts"] = [{"id": a.id, "title": a.title, "severity": a.severity}
                      for a in event.alerts]
    return jsonify(data)


# ------------------------------ simulation --------------------------------

@api_bp.route("/simulate", methods=["POST"])
@api_login_required
def simulate():
    """Generate a simulated event batch, persist it, and run detection.
    This powers the 'Generate Security Event' button (demo mode)."""
    scenario, events = generate_live_batch()
    db.session.add_all(events)
    db.session.commit()
    alerts = run_detection()
    return jsonify({
        "scenario": scenario,
        "events_created": len(events),
        "alerts_created": len(alerts),
        "alerts": [{"id": a.id, "title": a.title, "severity": a.severity}
                   for a in alerts],
    }), 201


# ----------------------------- rules / settings ---------------------------

@api_bp.route("/rules")
@api_login_required
def list_rules():
    rules = DetectionRule.query.order_by(DetectionRule.rule_code).all()
    return jsonify([r.to_dict() for r in rules])


@api_bp.route("/rules/<int:rule_id>", methods=["PATCH"])
@api_login_required
def update_rule(rule_id):
    rule = db.session.get(DetectionRule, rule_id)
    if rule is None:
        return jsonify(error="Not found"), 404
    payload = request.get_json(silent=True) or {}
    if "enabled" not in payload or not isinstance(payload["enabled"], bool):
        return jsonify(error="'enabled' (boolean) is required"), 400
    rule.enabled = payload["enabled"]
    db.session.commit()
    return jsonify(rule.to_dict())


# ------------------------------ threat intel ------------------------------

@api_bp.route("/threat-intel")
@api_login_required
def list_threat_intel():
    entries = ThreatIntelEntry.query.order_by(
        ThreatIntelEntry.confidence.desc()).all()
    result = []
    for entry in entries:
        data = entry.to_dict()
        data["alert_count"] = Alert.query.filter(
            Alert.source_ip == entry.ip_address).count()
        result.append(data)
    return jsonify(result)


# -------------------------------- reports ---------------------------------

def _report_summary():
    top_ips = (db.session.query(SecurityEvent.source_ip,
                                db.func.count(SecurityEvent.id))
               .filter(SecurityEvent.source_ip.isnot(None),
                       SecurityEvent.event_type.in_(list(ATTACK_CATEGORIES)))
               .group_by(SecurityEvent.source_ip)
               .order_by(db.func.count(SecurityEvent.id).desc())
               .limit(10).all())
    attack_types = (db.session.query(SecurityEvent.event_type,
                                     db.func.count(SecurityEvent.id))
                    .filter(SecurityEvent.event_type.in_(list(ATTACK_CATEGORIES)))
                    .group_by(SecurityEvent.event_type)
                    .order_by(db.func.count(SecurityEvent.id).desc()).all())
    techniques = (db.session.query(Alert.mitre_technique,
                                   db.func.count(Alert.id))
                  .filter(Alert.mitre_technique.isnot(None))
                  .group_by(Alert.mitre_technique)
                  .order_by(db.func.count(Alert.id).desc()).all())
    return {
        "total_events": db.session.query(SecurityEvent.id).count(),
        "total_alerts": db.session.query(Alert.id).count(),
        "critical_alerts": Alert.query.filter_by(severity="CRITICAL").count(),
        "high_alerts": Alert.query.filter_by(severity="HIGH").count(),
        "total_incidents": db.session.query(Incident.id).count(),
        "open_incidents": Incident.query.filter(
            Incident.status.in_(["OPEN", "INVESTIGATING", "CONTAINED"])).count(),
        "top_source_ips": [{"ip": ip, "count": c} for ip, c in top_ips],
        "attack_types": [{"type": ATTACK_CATEGORIES.get(t, t), "count": c}
                         for t, c in attack_types],
        "mitre_techniques": [
            {"technique": t,
             "name": MITRE_TECHNIQUES.get(t, {}).get("name", "Unknown"),
             "count": c} for t, c in techniques],
        "generated_at": utcnow().isoformat(),
    }


@api_bp.route("/reports/summary")
@api_login_required
def report_summary():
    return jsonify(_report_summary())


@api_bp.route("/reports/export.csv")
@api_login_required
def report_export():
    """Export all alerts plus a summary header as CSV."""
    summary = _report_summary()
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["MiniSOC Security Report (simulated data)",
                     summary["generated_at"]])
    writer.writerow([])
    writer.writerow(["Total events", summary["total_events"]])
    writer.writerow(["Total alerts", summary["total_alerts"]])
    writer.writerow(["Critical alerts", summary["critical_alerts"]])
    writer.writerow(["High alerts", summary["high_alerts"]])
    writer.writerow(["Total incidents", summary["total_incidents"]])
    writer.writerow([])
    writer.writerow(["alert_id", "timestamp", "severity", "status", "title",
                     "source_ip", "username", "hostname", "detection_rule",
                     "mitre_technique"])
    for alert in Alert.query.order_by(Alert.timestamp.desc()).all():
        writer.writerow([alert.id, alert.timestamp.isoformat(), alert.severity,
                         alert.status, alert.title, alert.source_ip,
                         alert.username, alert.hostname,
                         alert.rule.name if alert.rule else "",
                         alert.mitre_technique])
    filename = f"minisoc_report_{utcnow().strftime('%Y%m%d_%H%M')}.csv"
    return Response(buffer.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition":
                             f"attachment; filename={filename}"})
