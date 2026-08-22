"""Page routes (HTML). List pages are shells whose tables/charts are filled
by JavaScript calling the JSON API; detail pages are server-rendered from
the database so an analyst can deep-link to an alert or incident."""
from flask import Blueprint, render_template, abort

from app.auth import login_required
from app.database import db
from app.detection_engine import INVESTIGATION_STEPS
from app.mitre import MITRE_TECHNIQUES, get_technique
from app.models import (Alert, DetectionRule, Incident, SecurityEvent,
                        ThreatIntelEntry)

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
@login_required
def dashboard():
    return render_template("dashboard.html", active="dashboard")


@main_bp.route("/alerts")
@login_required
def alerts():
    return render_template("alerts.html", active="alerts")


@main_bp.route("/alerts/<int:alert_id>")
@login_required
def alert_detail(alert_id):
    alert = db.session.get(Alert, alert_id)
    if alert is None:
        abort(404)

    technique = get_technique(alert.mitre_technique)
    steps = INVESTIGATION_STEPS.get(alert.rule.rule_code if alert.rule else "", [])
    intel = (ThreatIntelEntry.query.filter_by(ip_address=alert.source_ip).first()
             if alert.source_ip else None)

    # Related activity: other events/alerts from the same source IP around
    # the alert time — the pivot an analyst always does first.
    related_events, related_alerts = [], []
    if alert.source_ip:
        related_events = (SecurityEvent.query
                          .filter(SecurityEvent.source_ip == alert.source_ip)
                          .order_by(SecurityEvent.timestamp.desc())
                          .limit(15).all())
        related_alerts = (Alert.query
                          .filter(Alert.source_ip == alert.source_ip,
                                  Alert.id != alert.id)
                          .order_by(Alert.timestamp.desc())
                          .limit(10).all())

    return render_template("alert_detail.html", active="alerts", alert=alert,
                           technique=technique, steps=steps, intel=intel,
                           related_events=related_events,
                           related_alerts=related_alerts)


@main_bp.route("/incidents")
@login_required
def incidents():
    return render_template("incidents.html", active="incidents")


@main_bp.route("/incidents/<int:incident_id>")
@login_required
def incident_detail(incident_id):
    incident = db.session.get(Incident, incident_id)
    if incident is None:
        abort(404)
    technique = get_technique(incident.mitre_technique)
    return render_template("incident_detail.html", active="incidents",
                           incident=incident, technique=technique)


@main_bp.route("/events")
@login_required
def events():
    return render_template("events.html", active="events")


@main_bp.route("/threat-intel")
@login_required
def threat_intel():
    return render_template("threat_intel.html", active="threat_intel")


@main_bp.route("/mitre")
@login_required
def mitre():
    # Detection counts per technique come straight from the alerts table.
    techniques = []
    for tid, info in MITRE_TECHNIQUES.items():
        count = Alert.query.filter(Alert.mitre_technique == tid).count()
        rules = DetectionRule.query.filter_by(mitre_technique=tid).all()
        recent = (Alert.query.filter(Alert.mitre_technique == tid)
                  .order_by(Alert.timestamp.desc()).limit(5).all())
        techniques.append({"info": info, "count": count, "rules": rules,
                           "recent_alerts": recent})
    techniques.sort(key=lambda t: t["count"], reverse=True)
    return render_template("mitre.html", active="mitre", techniques=techniques)


@main_bp.route("/reports")
@login_required
def reports():
    return render_template("reports.html", active="reports")


@main_bp.route("/settings")
@login_required
def settings():
    rules = DetectionRule.query.order_by(DetectionRule.rule_code).all()
    return render_template("settings.html", active="settings", rules=rules)
