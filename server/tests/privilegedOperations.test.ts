// Unit tests for R004's command patterns: the detection logic that is most
// likely to cause false positives or misses, so every pattern is pinned down.
import { describe, expect, it } from 'vitest';
import { findPrivilegedOperation } from '../src/detection/rules/privilegeEscalation.js';

describe('findPrivilegedOperation', () => {
  it.each([
    ['sudo su -', 'switched to root'],
    ['sudo -E su', 'switched to root'],
    ['sudo -i', 'root shell with "sudo -i/-s"'],
    ['sudo -s', 'root shell with "sudo -i/-s"'],
    ['sudo bash', 'spawned a root shell'],
    ['sudo /bin/bash -p', 'spawned a root shell'],
    ['pkexec /bin/sh', 'pkexec'],
    ['sudo visudo', 'sudoers'],
    ["echo 'jsmith ALL=(ALL) NOPASSWD:ALL' | sudo tee -a /etc/sudoers", 'sudoers'],
    ['chmod u+s /tmp/rootbash', 'SUID'],
    ['sudo chmod 4755 /usr/local/bin/helper', 'SUID'],
    ['sudo cat /etc/shadow', '/etc/shadow'],
    ['sudo usermod -aG sudo jsmith', 'administrator group'],
    ['usermod -G wheel,docker jsmith', 'administrator group'],
    ['sudo passwd root', "root's password"],
  ])('detects %j', (commandLine, expected) => {
    expect(findPrivilegedOperation(commandLine)?.behaviour).toContain(expected);
  });

  it.each([
    'ls -la /home/jsmith',
    'sudo systemctl restart nginx',
    'sudo apt-get update',
    'sudo -u postgres psql',
    'sudo shutdown -r now',
    'ssh admin@db-01',
    'bash backup.sh',
    'chmod 755 deploy.sh',
    'chmod +x deploy.sh',
    'cat /etc/hosts',
    'usermod -aG docker jsmith',
    'passwd',
  ])('ignores the ordinary command %j', (commandLine) => {
    expect(findPrivilegedOperation(commandLine)).toBeUndefined();
  });
});
