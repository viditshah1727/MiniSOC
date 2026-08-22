"""Simulated security-event generator.

Version 1 of MiniSOC runs entirely on simulated telemetry. This module is
the single place that fabricates events, used by both the database seeder
and the live "Generate Security Event" button. All source IPs are from
private (RFC 1918) ranges, so no real-world address is ever implicated.

The generator produces *patterns*, not pure random noise: a brute-force
burst is a sequence of failed logins from one IP against a few accounts, a
port scan walks through real service ports, etc. That is what makes the
detection engine's correlation rules meaningful.

To add real log ingestion later, write a collector that parses e.g.
/var/log/auth.log lines into the same SecurityEvent fields these helpers
produce — the detection engine does not care where events come from.
"""
import random
from datetime import timedelta

from app.models import SecurityEvent, utcnow

# --- simulation inventory (all private-range, fictional) -------------------
INTERNAL_HOSTS = [
    ("web-srv-01", "10.0.0.11"),
    ("web-srv-02", "10.0.0.12"),
    ("db-srv-01", "10.0.0.21"),
    ("app-srv-01", "10.0.0.31"),
    ("file-srv-01", "10.0.0.41"),
    ("dc-01", "10.0.0.5"),
]

USERS = ["alice", "bob", "charlie", "dana", "erik", "svc_backup", "svc_deploy"]
ATTACK_USERS = ["admin", "root", "user", "test", "oracle", "postgres", "guest"]

# IPs the workforce normally uses (treated as benign).
OFFICE_IPS = [f"192.168.10.{i}" for i in range(20, 40)]

# IPs used by simulated attackers (referenced by seed data + threat intel).
ATTACKER_IPS = [
    "192.168.1.105", "192.168.1.212", "10.0.99.66",
    "172.16.34.101", "172.16.34.187", "192.168.1.77",
]

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993,
                1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200]

WEB_ATTACK_PAYLOADS = [
    ("SQL injection attempt", "GET /products?id=1' OR '1'='1 HTTP/1.1"),
    ("Path traversal attempt", "GET /../../../etc/passwd HTTP/1.1"),
    ("Command injection attempt", "GET /ping?host=127.0.0.1;cat+/etc/shadow HTTP/1.1"),
    ("XSS attempt", "GET /search?q=<script>alert(1)</script> HTTP/1.1"),
    ("Web shell probe", "POST /uploads/shell.php HTTP/1.1"),
]

MALWARE_INDICATORS = [
    ("Known malware hash observed", "sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 (EICAR-style test indicator)"),
    ("Beaconing to known C2 pattern", "periodic outbound connections every 60s to 10.0.99.66:8443"),
    ("Suspicious scheduled task created", "cron entry added: */5 * * * * /tmp/.hidden/update.sh"),
]

PRIVESC_ACTIONS = [
    ("sudo /bin/bash", "SUCCESS", "user spawned root shell via sudo"),
    ("sudo vi /etc/sudoers", "SUCCESS", "sudoers file opened for modification"),
    ("sudo su -", "FAILURE", "3 consecutive sudo authentication failures"),
    ("pkexec /bin/sh", "SUCCESS", "polkit elevation to root shell"),
]


def _host():
    return random.choice(INTERNAL_HOSTS)


def _raw_ssh(result, user, src_ip, host):
    """Build an auth.log-style line so the Raw Log field looks like real telemetry."""
    if result == "FAILURE":
        return (f"{host}0 sshd[{random.randint(1000, 9999)}]: Failed password for "
                f"{'invalid user ' if user in ATTACK_USERS else ''}{user} "
                f"from {src_ip} port {random.randint(40000, 65000)} ssh2")
    return (f"{host}0 sshd[{random.randint(1000, 9999)}]: Accepted password for "
            f"{user} from {src_ip} port {random.randint(40000, 65000)} ssh2")


# --------------------------------------------------------------------------
# Single-event builders. All return unsaved SecurityEvent objects.
# --------------------------------------------------------------------------

def make_ssh_failed(src_ip, username, ts, host=None):
    hostname, host_ip = host or _host()
    return SecurityEvent(
        timestamp=ts, event_type="SSH_LOGIN_FAILED", source_ip=src_ip,
        destination_ip=host_ip, source_port=random.randint(40000, 65000),
        destination_port=22, protocol="TCP", username=username,
        hostname=hostname, action="ssh password authentication",
        result="FAILURE", severity="LOW",
        raw_log=_raw_ssh("FAILURE", username, src_ip, hostname),
    )


def make_ssh_success(src_ip, username, ts, host=None):
    hostname, host_ip = host or _host()
    return SecurityEvent(
        timestamp=ts, event_type="SSH_LOGIN_SUCCESS", source_ip=src_ip,
        destination_ip=host_ip, source_port=random.randint(40000, 65000),
        destination_port=22, protocol="TCP", username=username,
        hostname=hostname, action="ssh password authentication",
        result="SUCCESS", severity="INFO",
        raw_log=_raw_ssh("SUCCESS", username, src_ip, hostname),
    )


def make_port_probe(src_ip, dst_port, ts, host=None):
    hostname, host_ip = host or _host()
    return SecurityEvent(
        timestamp=ts, event_type="PORT_SCAN", source_ip=src_ip,
        destination_ip=host_ip, source_port=random.randint(40000, 65000),
        destination_port=dst_port, protocol="TCP", username=None,
        hostname=hostname, action=f"connection attempt to port {dst_port}",
        result="BLOCKED", severity="LOW",
        raw_log=(f"kernel: [UFW BLOCK] IN=eth0 SRC={src_ip} DST={host_ip} "
                 f"PROTO=TCP SPT={random.randint(40000, 65000)} DPT={dst_port} "
                 f"SYN URGP=0"),
    )


def make_web_attack(src_ip, ts, host=None):
    hostname, host_ip = host or random.choice(INTERNAL_HOSTS[:2])
    label, payload = random.choice(WEB_ATTACK_PAYLOADS)
    return SecurityEvent(
        timestamp=ts, event_type="WEB_ATTACK", source_ip=src_ip,
        destination_ip=host_ip, source_port=random.randint(40000, 65000),
        destination_port=443, protocol="HTTPS", username=None,
        hostname=hostname, action=label, result="BLOCKED", severity="MEDIUM",
        raw_log=f'{src_ip} - - "{payload}" 403 162 "-" "Mozilla/5.0"',
    )


def make_malware_indicator(ts, host=None, src_ip=None):
    hostname, host_ip = host or _host()
    label, detail = random.choice(MALWARE_INDICATORS)
    return SecurityEvent(
        timestamp=ts, event_type="MALWARE_INDICATOR",
        source_ip=src_ip or host_ip, destination_ip=None,
        protocol=None, username=random.choice(USERS), hostname=hostname,
        action=label, result="DETECTED", severity="HIGH",
        raw_log=f"edr[{random.randint(100, 999)}]: {label}: {detail} on {hostname}",
    )


def make_privilege_escalation(username, ts, host=None):
    hostname, host_ip = host or _host()
    action, result, detail = random.choice(PRIVESC_ACTIONS)
    return SecurityEvent(
        timestamp=ts, event_type="PRIVILEGE_ESCALATION", source_ip=host_ip,
        destination_ip=None, protocol=None, username=username,
        hostname=hostname, action=action, result=result, severity="MEDIUM",
        raw_log=(f"{hostname} sudo: {username} : TTY=pts/1 ; PWD=/home/{username} ; "
                 f"USER=root ; COMMAND={action.replace('sudo ', '')} ({detail})"),
    )


def make_normal_login(ts):
    """Benign baseline traffic: an employee logging in from an office IP."""
    return make_ssh_success(random.choice(OFFICE_IPS), random.choice(USERS), ts)


def make_firewall_block(src_ip, ts):
    hostname, host_ip = _host()
    port = random.choice(COMMON_PORTS)
    return SecurityEvent(
        timestamp=ts, event_type="FIREWALL_BLOCK", source_ip=src_ip,
        destination_ip=host_ip, source_port=random.randint(40000, 65000),
        destination_port=port, protocol="TCP", hostname=hostname,
        action=f"blocked inbound connection to port {port}",
        result="BLOCKED", severity="INFO",
        raw_log=(f"kernel: [UFW BLOCK] IN=eth0 SRC={src_ip} DST={host_ip} "
                 f"PROTO=TCP DPT={port}"),
    )


# --------------------------------------------------------------------------
# Scenario builders — coherent attack patterns spanning multiple events.
# --------------------------------------------------------------------------

def brute_force_burst(src_ip, start_ts, attempts=8, succeed=False, host=None,
                      victim_user=None):
    """Failed SSH logins in quick succession; optionally ends with a success
    (which should trigger R002 on top of R001)."""
    host = host or _host()
    events = []
    ts = start_ts
    for i in range(attempts):
        user = random.choice(ATTACK_USERS)
        events.append(make_ssh_failed(src_ip, user, ts, host=host))
        ts += timedelta(seconds=random.randint(5, 25))
    if succeed:
        events.append(make_ssh_success(src_ip, victim_user or "admin", ts +
                                       timedelta(seconds=random.randint(10, 40)),
                                       host=host))
    return events


def port_scan_burst(src_ip, start_ts, num_ports=15, host=None):
    """A walk across common service ports from one source IP."""
    host = host or _host()
    ports = random.sample(COMMON_PORTS, min(num_ports, len(COMMON_PORTS)))
    events = []
    ts = start_ts
    for port in ports:
        events.append(make_port_probe(src_ip, port, ts, host=host))
        ts += timedelta(seconds=random.randint(1, 8))
    return events


SCENARIOS = ["normal_login", "failed_login", "brute_force", "brute_force_success",
             "port_scan", "web_attack", "malware", "privilege_escalation",
             "firewall_noise"]


def generate_live_batch():
    """Used by the 'Generate Security Event' button: pick a weighted random
    scenario and return a list of new (unsaved) events with fresh timestamps."""
    now = utcnow()
    scenario = random.choices(
        SCENARIOS,
        weights=[25, 15, 12, 6, 12, 10, 6, 8, 6],
        k=1,
    )[0]

    if scenario == "normal_login":
        return scenario, [make_normal_login(now)]
    if scenario == "failed_login":
        # An employee fat-fingering a password — not enough to alert.
        ip = random.choice(OFFICE_IPS)
        user = random.choice(USERS)
        return scenario, [make_ssh_failed(ip, user, now)]
    if scenario == "brute_force":
        ip = random.choice(ATTACKER_IPS)
        return scenario, brute_force_burst(ip, now - timedelta(minutes=3),
                                           attempts=random.randint(6, 12))
    if scenario == "brute_force_success":
        ip = random.choice(ATTACKER_IPS)
        return scenario, brute_force_burst(ip, now - timedelta(minutes=4),
                                           attempts=random.randint(6, 10),
                                           succeed=True)
    if scenario == "port_scan":
        ip = random.choice(ATTACKER_IPS)
        return scenario, port_scan_burst(ip, now - timedelta(minutes=2),
                                         num_ports=random.randint(11, 18))
    if scenario == "web_attack":
        ip = random.choice(ATTACKER_IPS)
        return scenario, [make_web_attack(ip, now)]
    if scenario == "malware":
        return scenario, [make_malware_indicator(now)]
    if scenario == "privilege_escalation":
        return scenario, [make_privilege_escalation(random.choice(USERS), now)]
    # firewall_noise
    ip = random.choice(ATTACKER_IPS + OFFICE_IPS)
    return scenario, [make_firewall_block(ip, now)]
