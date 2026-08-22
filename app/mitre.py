"""Local MITRE ATT&CK reference data.

Only the techniques used by MiniSOC's detection rules are included.
This is NOT a full or official ATT&CK implementation — it is a small local
lookup table so alerts can be mapped to technique context offline.
Descriptions are paraphrased summaries, see https://attack.mitre.org.
"""

MITRE_TECHNIQUES = {
    "T1110": {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1110/",
        "description": (
            "Adversaries repeatedly guess credentials to gain access to accounts, "
            "for example by hammering an SSH service with common username/password "
            "combinations. Typical signals: bursts of failed logins from one source "
            "IP, often across several usernames."
        ),
    },
    "T1078": {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Defense Evasion / Persistence / Initial Access",
        "url": "https://attack.mitre.org/techniques/T1078/",
        "description": (
            "Adversaries use legitimate (stolen or guessed) credentials to log in, "
            "blending in with normal activity. Typical signals: a successful login "
            "that immediately follows a brute-force burst, or a login from an IP / "
            "at an hour that is unusual for that account."
        ),
    },
    "T1046": {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "url": "https://attack.mitre.org/techniques/T1046/",
        "description": (
            "Adversaries scan the network to enumerate hosts and listening services "
            "before attacking them. Typical signals: one source IP touching many "
            "different destination ports or hosts in a short period."
        ),
    },
    "T1548": {
        "id": "T1548",
        "name": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation / Defense Evasion",
        "url": "https://attack.mitre.org/techniques/T1548/",
        "description": (
            "Adversaries abuse mechanisms such as sudo to run commands with "
            "elevated privileges. Typical signals: unexpected sudo usage, edits to "
            "sudoers, or shells spawned as root by a normal user account."
        ),
    },
    "T1190": {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1190/",
        "description": (
            "Adversaries exploit vulnerabilities in internet-facing applications "
            "(SQL injection, path traversal, ...) to gain a foothold. Typical "
            "signals: attack patterns in web server request logs."
        ),
    },
    "T1105": {
        "id": "T1105",
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1105/",
        "description": (
            "Adversaries transfer tools or malware into the environment from an "
            "external system. Typical signals: downloads of known-bad files, "
            "connections to known malware distribution hosts."
        ),
    },
}


def get_technique(technique_id):
    """Look up a technique by ID (e.g. 'T1110'); returns None if unknown."""
    if not technique_id:
        return None
    return MITRE_TECHNIQUES.get(technique_id.split(".")[0])
