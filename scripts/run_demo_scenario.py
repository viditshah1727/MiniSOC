"""Reproducible interview demo: replay the SSH brute-force -> compromise
attack live, showing each stage of the SOC workflow.

Usage (from the project root, venv active, after seeding):
    python scripts/run_demo_scenario.py

What it does, step by step:
  1. Injects a burst of failed SSH logins from 192.168.1.105 (fresh timestamps)
  2. Runs the detection engine  -> R001 fires a HIGH alert
  3. Injects a successful login from the same IP
  4. Runs the detection engine  -> R002 fires a CRITICAL alert
  5. Escalates the CRITICAL alert to an incident (status INVESTIGATING)
  6. Adds analyst notes, then resolves the incident

Refresh the dashboard after running it — the new alerts and incident are
at the top of every list.
"""
import sys
import time
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import create_app                                    # noqa: E402
from app.database import db                                   # noqa: E402
from app.detection_engine import run_detection                # noqa: E402
from app.event_generator import make_ssh_failed, make_ssh_success  # noqa: E402
from app.models import AnalystNote, Incident, utcnow          # noqa: E402

ATTACKER = "192.168.1.105"
TARGET = ("web-srv-01", "10.0.0.11")
ANALYST = "SOC Analyst (demo)"


def banner(text):
    print(f"\n=== {text} " + "=" * max(0, 60 - len(text)))


def main():
    app = create_app()
    with app.app_context():
        banner("STAGE 1: brute force begins")
        start = utcnow() - timedelta(minutes=4)
        users = ["admin", "root", "admin", "user", "admin", "test", "admin"]
        for i, username in enumerate(users):
            event = make_ssh_failed(ATTACKER, username,
                                    start + timedelta(seconds=30 * i),
                                    host=TARGET)
            db.session.add(event)
            print(f"  [event] failed SSH login: user={username} "
                  f"src={ATTACKER} -> {TARGET[0]}")
        db.session.commit()

        alerts = run_detection()
        for alert in alerts:
            print(f"  [ALERT {alert.severity}] #{alert.id} {alert.title}  "
                  f"(rule {alert.rule.rule_code}, MITRE {alert.mitre_technique})")
        time.sleep(1)

        banner("STAGE 2: the attacker gets in")
        success = make_ssh_success(ATTACKER, "admin", utcnow(), host=TARGET)
        db.session.add(success)
        db.session.commit()
        print(f"  [event] SUCCESSFUL SSH login: user=admin src={ATTACKER} "
              f"-> {TARGET[0]}")

        alerts = run_detection()
        critical = None
        for alert in alerts:
            print(f"  [ALERT {alert.severity}] #{alert.id} {alert.title}  "
                  f"(rule {alert.rule.rule_code}, MITRE {alert.mitre_technique})")
            if alert.severity == "CRITICAL":
                critical = alert
        time.sleep(1)

        if critical is None:
            print("  (CRITICAL alert already existed from a previous demo run "
                  "within the dedup window — re-seed to replay from scratch)")
            return

        banner("STAGE 3: analyst escalates to an incident")
        incident = Incident(
            title=f"Account compromise via SSH brute force ({ATTACKER})",
            description=critical.description,
            severity="CRITICAL", status="INVESTIGATING",
            source_ip=ATTACKER, affected_host=TARGET[0], affected_user="admin",
            detection_source=critical.rule.name,
            mitre_technique=critical.mitre_technique,
            assigned_analyst=ANALYST)
        db.session.add(incident)
        db.session.flush()
        critical.incident_id = incident.id
        critical.status = "INVESTIGATING"
        db.session.commit()
        print(f"  [incident] #{incident.id} created, status=INVESTIGATING, "
              f"assigned to {ANALYST}")

        banner("STAGE 4: investigation notes")
        for text in [
            "Confirmed 7 failed logins from 192.168.1.105 followed by a "
            "successful 'admin' login. Treating account as compromised.",
            "Password reset forced for 'admin'; attacker IP blocked at the "
            "firewall; session history reviewed — no lateral movement found.",
        ]:
            db.session.add(AnalystNote(author=ANALYST, content=text,
                                       incident_id=incident.id))
            print(f"  [note] {text[:70]}...")
        db.session.commit()

        banner("STAGE 5: containment complete — incident resolved")
        incident.status = "RESOLVED"
        critical.status = "RESOLVED"
        db.session.commit()
        print(f"  [incident] #{incident.id} status=RESOLVED")

        print("\nDemo complete. Open the dashboard: the new CRITICAL alert and "
              f"incident #{incident.id} are at the top of the lists.")


if __name__ == "__main__":
    main()
