/** Shared Linux lab scenario data for just-bash FS seeding and custom commands. */

export const HOST = 'cyberrange-training-01';
export const USER = 'blueteam-user';
export const HOME = `/home/${USER}`;
export const ATTACKER_IP = '203.0.113.45';

export const QUIET_AUTH_LOG = `Sep 23 19:40:01 ${HOST} sshd[12001]: Accepted password for blueteam-user from 192.168.1.100 port 51234 ssh2
Sep 23 19:41:12 ${HOST} CRON[12010]: (root) CMD (cd / && run-parts --report /etc/cron.hourly)
Sep 23 19:42:03 ${HOST} systemd[1]: Started Session 42 of user blueteam-user.
Sep 23 19:43:44 ${HOST} sshd[12100]: Accepted publickey for blueteam-user from 192.168.1.55 port 49821 ssh2
Sep 23 19:45:01 ${HOST} sshd[12345]: Accepted password for blueteam-user from 192.168.1.100 port 51302 ssh2
[NORMAL] No failed attempts`;

export const ATTACK_AUTH_LOG = `Sep 23 19:45:01 ${HOST} sshd[12345]: Accepted password for blueteam-user from 192.168.1.100 port 51302 ssh2
Sep 23 19:46:01 ${HOST} sshd[54321]: Failed password for blueteam-user from ${ATTACKER_IP} port 22 ssh2
Sep 23 19:46:02 ${HOST} sshd[54322]: Failed password for root from ${ATTACKER_IP} port 22 ssh2
Sep 23 19:46:03 ${HOST} sshd[54323]: Failed password for admin from ${ATTACKER_IP} port 22 ssh2
Sep 23 19:46:04 ${HOST} sshd[54324]: Failed password for invalid user oracle from ${ATTACKER_IP} port 22 ssh2
Sep 23 19:46:05 ${HOST} sshd[54325]: Failed password for blueteam-user from ${ATTACKER_IP} port 22 ssh2
Sep 23 19:46:06 ${HOST} sshd[54326]: Failed password for root from ${ATTACKER_IP} port 22 ssh2
[ALERT] Brute force SSH from ${ATTACKER_IP}`;

export const NETSTAT = `Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN
tcp6       0      0 :::22                   :::*                    LISTEN`;

export const PS_AUX = `USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1 168012 11420 ?        Ss   19:40   0:01 /sbin/init
root       412  0.0  0.2  72340 18400 ?        Ss   19:40   0:00 /usr/sbin/sshd -D
mysql      588  0.1  1.8 1120840 148220 ?      Ssl  19:40   0:04 /usr/sbin/mysqld
blueteam+ 1402  0.0  0.1  21488  5420 pts/0    Ss   19:45   0:00 -bash
blueteam+ 1510  0.0  0.0  13528  3488 pts/0    R+   19:50   0:00 ps aux`;

export const PS_AUX_ATTACK = `USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1 168012 11420 ?        Ss   19:40   0:01 /sbin/init
root       412  2.4  0.4  82340 32400 ?        Ss   19:40   0:12 /usr/sbin/sshd -D
mysql      588  0.1  1.8 1120840 148220 ?      Ssl  19:40   0:04 /usr/sbin/mysqld
sshd     54321  1.1  0.1  14788  8900 ?        R    19:46   0:01 sshd: [net]
sshd     54322  1.0  0.1  14788  8840 ?        R    19:46   0:01 sshd: [net]
blueteam+ 1402  0.0  0.1  21488  5420 pts/0    Ss   19:45   0:00 -bash
blueteam+ 1599  0.0  0.0  13528  3488 pts/0    R+   19:51   0:00 ps aux`;

export function topOutput(attackActive: boolean): string {
  const load = attackActive ? '0.92, 0.71, 0.48' : '0.08, 0.11, 0.09';
  const cpu = attackActive ? '12.4 us,  4.1 sy' : '1.8 us,  0.6 sy';
  return `top - 19:50:12 up 1:10,  1 user,  load average: ${load}
Tasks: 112 total,   ${attackActive ? 3 : 1} running, 109 sleeping,   0 stopped,   0 zombie
%Cpu(s):  ${cpu},  0.0 ni, ${attackActive ? '82.0' : '97.2'} id
MiB Mem :   7844.0 total,   2094.0 free,   2140.0 used,   3610.0 buff/cache
MiB Swap:   2048.0 total,   2048.0 free,      0.0 used.   5000.0 avail Mem

  PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND
    1 root      20   0  168012  11420   8320 S   0.0   0.1   0:01.12 systemd
  412 root      20   0   72340  ${attackActive ? '32400' : '18400'}  10200 S   ${attackActive ? '4.2' : '0.1'}   0.2   0:00.88 sshd
  588 mysql     20   0 1120840 148220  18900 S   0.3   1.8   0:04.21 mysqld`;
}

/** Flat path → content map for just-bash InitialFiles */
export function buildLinuxFiles(attackActive = false): Record<string, string> {
  const auth = attackActive ? ATTACK_AUTH_LOG : QUIET_AUTH_LOG;
  return {
    [`${HOME}/Desktop/.keep`]: '',
    [`${HOME}/Documents/notes.txt`]:
      'Blue team notes\n- Establish baseline before investigating alerts\n- Watch /var/log/auth.log for SSH failures\n',
    [`${HOME}/Documents/incident-checklist.md`]:
      '# Incident Checklist\n1. Identify host\n2. Capture process and port baseline\n3. Review auth logs\n4. Document findings\n',
    [`${HOME}/Downloads/.keep`]: '',
    [`${HOME}/.bashrc`]:
      '# ~/.bashrc\nexport PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nexport PS1="\\u@\\h:\\w\\$ "\n',
    [`${HOME}/.bash_history`]: 'whoami\nhostname\npwd\nls\n',
    [`${HOME}/README.txt`]: 'Welcome to the Cyberrange Linux lab.\nType help for common commands.\n',
    '/etc/hostname': `${HOST}\n`,
    '/etc/passwd':
      'root:x:0:0:root:/root:/bin/bash\nsshd:x:108:65534::/run/sshd:/usr/sbin/nologin\nblueteam-user:x:1000:1000:Blue Team User:/home/blueteam-user:/bin/bash\n',
    '/etc/hosts': `127.0.0.1 localhost\n192.168.1.50 ${HOST}\n`,
    '/etc/os-release':
      'NAME="Ubuntu"\nVERSION="22.04.4 LTS (Jammy Jellyfish)"\nID=ubuntu\nVERSION_ID="22.04"\n',
    '/etc/ssh/sshd_config': 'Port 22\nPermitRootLogin no\nPasswordAuthentication yes\n',
    '/var/log/auth.log': auth,
    '/var/log/syslog': `Sep 23 19:40:00 ${HOST} kernel: Linux version 5.15.0-112-generic\nSep 23 19:40:01 ${HOST} systemd[1]: Started User Manager for UID 1000.\n`,
    '/var/log/nginx/access.log':
      '192.168.1.20 - - [23/Sep/2026:19:40:11 +0000] "GET / HTTP/1.1" 200 1234\n',
    '/var/www/html/index.html': '<!doctype html><html><body><h1>Cyberrange</h1></body></html>\n',
    '/tmp/.keep': '',
    '/root/.profile': '# root profile\n',
    '/proc/version': 'Linux version 5.15.0-112-generic (buildd@lcy02) (gcc version 11.4.0)\n',
    '/proc/cpuinfo': 'processor\t: 0\nmodel name\t: Cyberrange Virtual CPU\ncpu cores\t: 2\n',
    '/proc/meminfo': 'MemTotal:        8042124 kB\nMemFree:         2145020 kB\nMemAvailable:    5120440 kB\n',
  };
}

export const BASH_LAB_NOTES = {
  baseline:
    '=== BASELINE ESTABLISHED ===\nSaved a quiet-host snapshot (processes, ports 22/3306, clean auth.log).\nNEXT: Type start-attack to inject the SSH brute-force simulation.',
  'start-attack':
    `=== ATTACK STARTED ===\nSimulated SSH brute force from ${ATTACKER_IP} is active.\n1) Inspect: grep Failed /var/log/auth.log\n2) Or: tail -n 20 /var/log/auth.log\n3) When finished investigating: type stop-attack`,
  'stop-attack':
    '=== ATTACK STOPPED ===\nBrute-force simulation ended. Logs and host metrics return to baseline.\nYou can type start-attack again while the baseline is still saved.',
  'lab-info':
    'BLUE TEAM LAB: Network Intrusion Detection\n1) Gather host facts (hostname, whoami, date)\n2) Baseline processes, ports, resources, and auth.log\n3) Type baseline\n4) Type start-attack\n5) Find Failed password lines from 203.0.113.45\n6) Type stop-attack when done',
};
