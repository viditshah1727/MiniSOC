// Local MITRE ATT&CK reference: the 15 techniques relevant to what MiniSOC
// watches (authentication, network, process and download telemetry).
// Deliberately NOT the full framework. Descriptions are short summaries
// written for analysts; see https://attack.mitre.org for the originals.
// Techniques with no rule mapped to them show up as coverage gaps in the UI.

export interface MitreTechniqueData {
  id: string;
  name: string;
  tactics: string[];
  description: string;
}

/** ATT&CK enterprise tactics in kill-chain order (used to sort techniques). */
export const TACTIC_ORDER = [
  'Reconnaissance',
  'Resource Development',
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Command and Control',
  'Exfiltration',
  'Impact',
];

export const MITRE_TECHNIQUES: MitreTechniqueData[] = [
  {
    id: 'T1595',
    name: 'Active Scanning',
    tactics: ['Reconnaissance'],
    description:
      'Probing victim infrastructure from outside, such as sweeping address ranges or ports, to find exposed services before attacking them.',
  },
  {
    id: 'T1190',
    name: 'Exploit Public-Facing Application',
    tactics: ['Initial Access'],
    description:
      'Exploiting a weakness in internet-facing software such as a web application, database or network appliance to gain a first foothold.',
  },
  {
    id: 'T1133',
    name: 'External Remote Services',
    tactics: ['Initial Access', 'Persistence'],
    description:
      'Using remote-access services exposed to the internet, such as VPN gateways or SSH, to get into a network and keep coming back.',
  },
  {
    id: 'T1078',
    name: 'Valid Accounts',
    tactics: ['Initial Access', 'Persistence', 'Privilege Escalation', 'Defense Evasion'],
    description:
      'Logging in with legitimate credentials that were stolen or guessed, so malicious activity looks like normal use. Often visible as a login from an unfamiliar source.',
  },
  {
    id: 'T1059',
    name: 'Command and Scripting Interpreter',
    tactics: ['Execution'],
    description:
      'Running commands through shells and interpreters such as bash, PowerShell or Python to execute attacker tooling.',
  },
  {
    id: 'T1053',
    name: 'Scheduled Task/Job',
    tactics: ['Execution', 'Persistence', 'Privilege Escalation'],
    description:
      'Using cron, systemd timers or the Windows Task Scheduler to run malicious code repeatedly or at startup.',
  },
  {
    id: 'T1136',
    name: 'Create Account',
    tactics: ['Persistence'],
    description: 'Creating new local, domain or cloud accounts to keep access to compromised systems.',
  },
  {
    id: 'T1098',
    name: 'Account Manipulation',
    tactics: ['Persistence', 'Privilege Escalation'],
    description:
      'Changing existing accounts to keep or raise access, for example adding a user to an administrative group or planting SSH keys.',
  },
  {
    id: 'T1548',
    name: 'Abuse Elevation Control Mechanism',
    tactics: ['Privilege Escalation', 'Defense Evasion'],
    description:
      'Abusing mechanisms that grant elevated rights, such as sudo or setuid binaries, to run code as root or administrator.',
  },
  {
    id: 'T1068',
    name: 'Exploitation for Privilege Escalation',
    tactics: ['Privilege Escalation'],
    description:
      'Exploiting a software vulnerability, for example in the kernel or a privileged service, to gain higher privileges.',
  },
  {
    id: 'T1110',
    name: 'Brute Force',
    tactics: ['Credential Access'],
    description:
      'Guessing passwords repeatedly, against one account or many, to obtain valid credentials. Typically seen as bursts of failed logins from one source.',
  },
  {
    id: 'T1046',
    name: 'Network Service Discovery',
    tactics: ['Discovery'],
    description:
      'Scanning hosts to list the services listening on them (formerly "Network Service Scanning"). Seen as one source contacting many ports in a short time.',
  },
  {
    id: 'T1003',
    name: 'OS Credential Dumping',
    tactics: ['Credential Access'],
    description:
      'Collecting password hashes or credentials from the operating system, for example reading /etc/shadow on Linux or LSASS memory on Windows, to crack or reuse them.',
  },
  {
    id: 'T1071',
    name: 'Application Layer Protocol',
    tactics: ['Command and Control'],
    description:
      'Hiding command-and-control traffic inside common protocols such as HTTPS or DNS so that it blends in with normal traffic.',
  },
  {
    id: 'T1105',
    name: 'Ingress Tool Transfer',
    tactics: ['Command and Control'],
    description:
      'Downloading tools or malware into the compromised environment, for example with curl, wget or a browser.',
  },
];
