/** PowerShell scenario outputs for the Windows lab (table-driven). */

export const ATTACKER_IP = '203.0.113.45';

export const POWERSHELL_COMMANDS: Record<string, string> = {
  whoami: 'cyberrange\\blueteam-user',
  hostname: 'WIN-SRV-2025-01',
  pwd: 'C:\\Users\\blueteam-user',
  'Get-Process':
    'Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName\n-------  ------    -----      -----     ------     --  -- -----------\n    412      18    12480      22140       0.22   1084   1 explorer\n    220      12     4820       9100       0.05    884   0 services\n    980      45    88200     120400       1.40    712   0 svchost\n    156       8     3200       6100       0.01   4500   1 powershell',
  'Get-NetTCPConnection -State Listen':
    'LocalAddress LocalPort State  OwningProcess\n------------ --------- -----  -------------\n0.0.0.0            3389 Listen          1092\n0.0.0.0              445 Listen           4\n127.0.0.1           5985 Listen          2140',
  'Get-Service | Where-Object { $_.Status -eq "Running" }':
    'Status  Name               DisplayName\n------  ----               -----------\nRunning EventLog           Windows Event Log\nRunning TermService        Remote Desktop Services\nRunning WinRM              Windows Remote Management (WS-Management)\nRunning wuauserv           Windows Update',
  'Get-WinEvent -LogName Security -MaxEvents 5':
    'TimeCreated           Id LevelDisplayName Message\n-----------           -- ---------------- -------\n9/23/2026 7:40:01 PM 4624 Information      An account was successfully logged on\n9/23/2026 7:39:12 PM 4624 Information      An account was successfully logged on\n9/23/2026 7:38:00 PM 4634 Information      An account was logged off',
  'Get-WinEvent -LogName Security -MaxEvents 5 attack':
    `TimeCreated           Id LevelDisplayName Message\n-----------           -- ---------------- -------\n9/23/2026 7:46:05 PM 4625 Failure          Failed logon from ${ATTACKER_IP}\n9/23/2026 7:46:04 PM 4625 Failure          Failed logon from ${ATTACKER_IP}\n9/23/2026 7:46:03 PM 4625 Failure          Failed logon from ${ATTACKER_IP}\n9/23/2026 7:46:02 PM 4625 Failure          Failed logon from ${ATTACKER_IP}\n9/23/2026 7:40:01 PM 4624 Information      An account was successfully logged on`,
  'Get-WinEvent -FilterHashtable @{LogName="Security"}':
    'TimeCreated           Id LevelDisplayName Message\n-----------           -- ---------------- -------\n9/23/2026 7:40:01 PM 4624 Information      An account was successfully logged on',
  'Get-WinEvent -FilterHashtable @{LogName="Security"} attack':
    `TimeCreated           Id LevelDisplayName Message\n-----------           -- ---------------- -------\n9/23/2026 7:46:06 PM 4625 Failure          Account failed to log on from ${ATTACKER_IP} (RDP)\n9/23/2026 7:46:05 PM 4625 Failure          Account failed to log on from ${ATTACKER_IP} (RDP)\n9/23/2026 7:46:04 PM 4625 Failure          Account failed to log on from ${ATTACKER_IP} (RDP)\n9/23/2026 7:40:01 PM 4624 Information      An account was successfully logged on`,
  baseline:
    '=== BASELINE ESTABLISHED ===\nSaved quiet Windows snapshot (processes, listeners, Security log).\nNEXT: Type start-attack to inject the RDP brute-force simulation.',
  'start-attack':
    `=== ATTACK STARTED ===\nSimulated RDP brute force from ${ATTACKER_IP} is active.\n1) Inspect: Get-WinEvent -FilterHashtable @{LogName="Security"}\n2) When finished: type stop-attack`,
  'stop-attack':
    '=== ATTACK STOPPED ===\nRDP brute-force simulation ended. Security log returns toward baseline.',
  'lab-info':
    'BLUE TEAM LAB: Windows Server 2025 Hardening\n1) hostname / whoami / Get-Date\n2) Get-Process, listeners, services, Security events\n3) baseline → start-attack → investigate → stop-attack',
  help: 'Available: whoami, hostname, Get-Date, pwd, Get-Process, Get-NetTCPConnection, Get-Service, Get-WinEvent, baseline, start-attack, stop-attack, lab-info, Clear-Host',
};

export function lookupPowerShell(command: string, attackActive: boolean): string | null {
  const normalized = command.trim().replace(/\s+/g, ' ');
  if (normalized === 'Get-Date') {
    return new Date().toString();
  }
  const attackKey = `${normalized} attack`;
  if (attackActive && Object.prototype.hasOwnProperty.call(POWERSHELL_COMMANDS, attackKey)) {
    return POWERSHELL_COMMANDS[attackKey];
  }
  if (Object.prototype.hasOwnProperty.call(POWERSHELL_COMMANDS, normalized)) {
    return POWERSHELL_COMMANDS[normalized];
  }
  return null;
}

export const SECURITY_EVENTS_QUIET = [
  { time: '9/23/2026 7:40:01 PM', id: '4624', level: 'Information', message: 'An account was successfully logged on' },
  { time: '9/23/2026 7:39:12 PM', id: '4624', level: 'Information', message: 'An account was successfully logged on' },
  { time: '9/23/2026 7:38:00 PM', id: '4634', level: 'Information', message: 'An account was logged off' },
];

export const SECURITY_EVENTS_ATTACK = [
  { time: '9/23/2026 7:46:06 PM', id: '4625', level: 'Failure', message: `Account failed to log on from ${ATTACKER_IP} (RDP)` },
  { time: '9/23/2026 7:46:05 PM', id: '4625', level: 'Failure', message: `Account failed to log on from ${ATTACKER_IP} (RDP)` },
  { time: '9/23/2026 7:46:04 PM', id: '4625', level: 'Failure', message: `Account failed to log on from ${ATTACKER_IP} (RDP)` },
  { time: '9/23/2026 7:40:01 PM', id: '4624', level: 'Information', message: 'An account was successfully logged on' },
];
