/**
 * Cyberrange Cloudflare Worker
 * Blue Team Training Platform with Simulated Shell
 * Supports bash (Linux) and PowerShell (Windows Server 2025)
 */

import {
  createBashSession,
  createDefaultFilesystem,
  executeBash,
  formatBashPrompt,
  type FsNode,
} from './bashSimulator';

export interface Env {
  CYBERRANGE_ENV?: string;
  ASSETS?: Fetcher;
}

// Types
type ShellType = 'bash' | 'powershell';
type ShellMode = 'learning' | 'free';

interface Lab {
  id: string;
  title: string;
  description: string;
  difficulty: string;
  category: string;
  tags: string[];
}

interface ShellState {
  commandHistory: string[];
  currentStep: number;
  mode: ShellMode;
  shellType: ShellType;
  attackActive: boolean;
  baselineEstablished: boolean;
  cwd: string;
  filesystem: FsNode | null;
}

interface LearningStep {
  label: string;
  why: string;
  observe: string;
  action: string;
  accept: string[];
  requireAll?: boolean;
}

// Lab Definitions
const LABS: Lab[] = [
  {
    id: 'network-intrusion-baseline',
    title: 'Network Intrusion Detection',
    description: 'Establish system baseline and detect brute force SSH attacks on Linux',
    difficulty: 'Beginner',
    category: 'Network Security',
    tags: ['ssh', 'brute-force', 'baseline', 'linux'],
  },
  {
    id: 'windows-server-2025',
    title: 'Windows Server 2025 Hardening',
    description: 'Secure and monitor Windows Server 2025 environment with PowerShell',
    difficulty: 'Intermediate',
    category: 'Windows Security',
    tags: ['windows', 'server-2025', 'hardening', 'powershell', 'event-viewer'],
  },
  {
    id: 'web-application-attack',
    title: 'Web Application Attack Detection',
    description: 'Detect SQL injection and XSS attempts',
    difficulty: 'Intermediate',
    category: 'Web Security',
    tags: ['sql-injection', 'xss'],
  },
];

// Mounted under cyber.ensign.quest/range via CyberEnforcer service binding.
const MOUNT_PREFIX = '/range';

const getBasePath = (pathname: string): string => {
  if (pathname === MOUNT_PREFIX || pathname.startsWith(`${MOUNT_PREFIX}/`)) {
    return MOUNT_PREFIX;
  }
  return '';
};

const stripBasePath = (pathname: string, base: string): string => {
  if (!base) return pathname;
  if (pathname === base) return '/';
  if (pathname.startsWith(`${base}/`)) {
    const rest = pathname.slice(base.length);
    return rest || '/';
  }
  return pathname;
};

const appPath = (base: string, path: string): string => {
  if (path === '/' || path === '') return base || '/';
  const normalized = path.startsWith('/') ? path : `/${path}`;
  return `${base}${normalized}`;
};

// Helper to escape HTML
const esc = (t: string): string => {
  return t
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
};

// Shared lab narrative for special commands.
const BASH_LAB = {
  baseline:
    '=== BASELINE ESTABLISHED ===\nSaved a quiet-host snapshot (processes, ports 22/3306, clean auth.log).\nNEXT: Type start-attack to inject the SSH brute-force simulation.',
  'start-attack':
    '=== ATTACK STARTED ===\nSimulated SSH brute force from 203.0.113.45 is active.\n1) Inspect: grep Failed /var/log/auth.log\n2) Or: tail -n 20 /var/log/auth.log\n3) When finished investigating: type stop-attack',
  'stop-attack':
    '=== ATTACK STOPPED ===\nBrute-force simulation ended. Logs and host metrics return to baseline.\nYou can type start-attack again while the baseline is still saved.',
  'lab-info':
    'BLUE TEAM LAB: Network Intrusion Detection\n1) Gather host facts (hostname, whoami, date)\n2) Baseline processes, ports, resources, and auth.log\n3) Type baseline\n4) Type start-attack\n5) Find Failed password lines from 203.0.113.45\n6) Type stop-attack when done',
};

const POWERSHELL_LAB = {
  baseline:
    '=== BASELINE ESTABLISHED ===\nSaved a quiet Windows snapshot (services, listening ports, clean Security log).\nNEXT: Type start-attack to inject the RDP brute-force simulation.',
  'start-attack':
    '=== ATTACK STARTED ===\nSimulated RDP brute force from 203.0.113.45 is active.\n1) Inspect: Get-WinEvent -FilterHashtable @{LogName="Security"}\n2) When finished investigating: type stop-attack',
  'stop-attack':
    '=== ATTACK STOPPED ===\nBrute-force simulation ended. Security events return to baseline noise.\nYou can type start-attack again while the baseline is still saved.',
  'lab-info':
    'BLUE TEAM LAB: Windows Server 2025 Hardening\n1) Gather host facts (hostname, whoami, Get-Date)\n2) Baseline processes, ports, services, and Security log\n3) Type baseline\n4) Type start-attack\n5) Look for failed logons from 203.0.113.45\n6) Type stop-attack when done',
};

// PowerShell stays table-driven. Bash uses the stateful Linux simulator.
const COMMANDS: Record<'powershell', Record<string, { output: string; baseline?: boolean; triggersAttack?: boolean }>> = {
  powershell: {
    'whoami': { output: 'CYBERRANGE\\blueteam-user' },
    'hostname': { output: 'WIN-SRV-2025-01' },
    '$env:COMPUTERNAME': { output: 'WIN-SRV-2025-01' },
    'Get-Date': { output: new Date().toLocaleString() },
    'pwd': { output: 'C:\\Users\\blueteam-user' },
    'Get-Process': { output: 'Handles  NPM(K)  PM(K)  WS(K)  CPU(s)  Id  ProcessName\n123      10    5432   16948    2.5  123  System\n456      15   34567   54320   10.2  567  svchost', baseline: true },
    'Get-NetTCPConnection -State Listen': { output: 'LocalAddress  LocalPort  State\n0.0.0.0      22        Listen\n0.0.0.0      80        Listen\n0.0.0.0      443       Listen\n0.0.0.0      3389       Listen', baseline: true },
    'Get-Service | Where-Object { $_.Status -eq "Running" }': { output: 'Status  Name          DisplayName\nRunning WinRM         Windows Remote Management\nRunning lanmanserver  Server', baseline: true },
    'Get-WinEvent -LogName Security -MaxEvents 5': { output: 'TimeCreated           Id  Message\n9/23/2026 7:45:00 PM  4624  An account was successfully logged on.\nNormal activity detected', baseline: true },
    'help': { output: 'Available: whoami, hostname, Get-Date, pwd, Get-Process, Get-NetTCPConnection, Get-Service, Get-WinEvent, baseline, start-attack, stop-attack, shell-type bash|powershell, lab-info' },
    'lab-info': { output: POWERSHELL_LAB['lab-info'] },
    'baseline': { output: POWERSHELL_LAB.baseline, baseline: true },
    'start-attack': { output: POWERSHELL_LAB['start-attack'], triggersAttack: true },
    'stop-attack': { output: POWERSHELL_LAB['stop-attack'] },
    'shell-type bash': { output: 'Switched to bash shell. Use Linux commands.' },
    'shell-type powershell': { output: 'Switched to PowerShell shell. Use Windows commands.' },
    'Get-WinEvent -FilterHashtable @{LogName="Security"} attack': { output: 'TimeCreated           Id  Message\n9/23/2026 7:46:01  4625  Failed login from 203.0.113.45\n[ALERT] Brute Force detected!' },
  }
};

// Learning steps per shell type. `accept` is the exact command that completes the step.
const LEARNING_STEPS: Record<ShellType, LearningStep[]> = {
  bash: [
    {
      label: 'Identify the host',
      why: 'You need to know which machine and account you are investigating before you trust any log timestamps.',
      observe: 'Write down: hostname, your username, and the current time.',
      action: 'Do this now:\n1. hostname\n2. whoami\n3. date',
      accept: ['hostname', 'whoami', 'date'],
      requireAll: true,
    },
    {
      label: 'Check processes',
      why: 'A quiet process list is your “normal” picture. Later you will compare it against attack noise.',
      observe: 'Expect sshd, mysqld, and systemd. Note anything unexpected.',
      action: 'Do this now:\nps aux',
      accept: ['ps aux'],
    },
    {
      label: 'Check listening ports',
      why: 'Listening ports show what attackers can reach from the network.',
      observe: 'Expect port 22 (SSH) and 3306 (MySQL on localhost). Record them.',
      action: 'Do this now:\nnetstat -tuln',
      accept: ['netstat -tuln'],
    },
    {
      label: 'Check resources',
      why: 'CPU/memory baselines help you spot a brute-force flood later.',
      observe: 'Note load average and that the host looks idle.',
      action: 'Do this now:\ntop',
      accept: ['top'],
    },
    {
      label: 'Read authentication logs',
      why: 'auth.log is where SSH success/failure appears. Read it while quiet first.',
      observe: 'You should see successful logins and NO repeated Failed password lines.',
      action: 'Do this now:\ntail -n 20 /var/log/auth.log',
      accept: ['tail -n 20 /var/log/auth.log'],
    },
    {
      label: 'Save the baseline',
      why: 'This locks the quiet-host snapshot so the lab can inject an attack afterward.',
      observe: 'Summarize ports + quiet auth.log in the observation notepad.',
      action: 'Do this now:\nbaseline',
      accept: ['baseline'],
    },
    {
      label: 'Start the attack',
      why: 'This turns on a simulated SSH brute force from 203.0.113.45.',
      observe: 'Status should flip to ATTACK ACTIVE. Do not stop yet — investigate first.',
      action: 'Do this now:\nstart-attack',
      accept: ['start-attack'],
    },
    {
      label: 'Investigate the attack',
      why: 'Compare live evidence against your baseline. Failed password lines are the smoking gun.',
      observe: 'Look for Failed password and source IP 203.0.113.45. Write them in the notepad.',
      action: 'Do this now (either command works):\ngrep Failed /var/log/auth.log\nOR\ntail -n 20 /var/log/auth.log',
      accept: ['grep Failed /var/log/auth.log', 'tail -n 20 /var/log/auth.log'],
    },
    {
      label: 'Stop the attack',
      why: 'After you have evidence, end the simulation so the host returns to baseline.',
      observe: 'ATTACK ACTIVE should clear. Re-check auth.log if you want to confirm it is quiet again.',
      action: 'Do this now:\nstop-attack\n(You can also use the Stop attack button in the sidebar.)',
      accept: ['stop-attack'],
    },
  ],
  powershell: [
    {
      label: 'Identify the host',
      why: 'Confirm computer name, user, and clock before reading Security events.',
      observe: 'Write down: hostname, user, and Get-Date output.',
      action: 'Do this now:\n1. hostname\n2. whoami\n3. Get-Date',
      accept: ['hostname', 'whoami', 'Get-Date'],
      requireAll: true,
    },
    {
      label: 'Check processes',
      why: 'Capture normal Windows processes before the attack starts.',
      observe: 'Note System/svchost and anything unusual.',
      action: 'Do this now:\nGet-Process',
      accept: ['Get-Process'],
    },
    {
      label: 'Check listening ports',
      why: 'Exposed listeners (especially RDP 3389) are high-value targets.',
      observe: 'Record listening ports, including 3389 if present.',
      action: 'Do this now:\nGet-NetTCPConnection -State Listen',
      accept: ['Get-NetTCPConnection -State Listen'],
    },
    {
      label: 'Check running services',
      why: 'Services show long-lived attack surface and persistence options.',
      observe: 'Note WinRM/Server and anything unexpected.',
      action: 'Do this now:\nGet-Service | Where-Object { $_.Status -eq "Running" }',
      accept: ['Get-Service | Where-Object { $_.Status -eq "Running" }'],
    },
    {
      label: 'Read the security log',
      why: 'Security events (4624/4625) are the Windows login trail.',
      observe: 'Confirm the log looks quiet before the attack.',
      action: 'Do this now:\nGet-WinEvent -LogName Security -MaxEvents 5',
      accept: ['Get-WinEvent -LogName Security -MaxEvents 5'],
    },
    {
      label: 'Save the baseline',
      why: 'Lock the quiet Windows snapshot before injecting the attack.',
      observe: 'Summarize ports/services/quiet Security log in the notepad.',
      action: 'Do this now:\nbaseline',
      accept: ['baseline'],
    },
    {
      label: 'Start the attack',
      why: 'This turns on a simulated RDP brute force from 203.0.113.45.',
      observe: 'Status should flip to ATTACK ACTIVE. Investigate before stopping.',
      action: 'Do this now:\nstart-attack',
      accept: ['start-attack'],
    },
    {
      label: 'Investigate the attack',
      why: 'Failed logons should now appear for the attacker IP.',
      observe: 'Look for failed logons / 4625 from 203.0.113.45 and note them.',
      action: 'Do this now:\nGet-WinEvent -FilterHashtable @{LogName="Security"}',
      accept: ['Get-WinEvent -FilterHashtable @{LogName="Security"}'],
    },
    {
      label: 'Stop the attack',
      why: 'End the simulation once you have documented the evidence.',
      observe: 'ATTACK ACTIVE should clear after you stop it.',
      action: 'Do this now:\nstop-attack\n(You can also use the Stop attack button in the sidebar.)',
      accept: ['stop-attack'],
    },
  ],
};

const clampStep = (shellType: ShellType, step: number): number => {
  const total = LEARNING_STEPS[shellType].length;
  if (!Number.isFinite(step) || step < 0) return 0;
  return Math.min(Math.floor(step), total);
};

const parseShellType = (value: string | null | undefined): ShellType =>
  value === 'powershell' ? 'powershell' : 'bash';

const parseMode = (value: string | null | undefined): ShellMode =>
  value === 'free' ? 'free' : 'learning';

const normalizeCommand = (command: string): string => command.trim().replace(/\s+/g, ' ');

const lookupCommand = (
  command: string,
  attackActive: boolean,
): { output: string } | null => {
  const commands = COMMANDS.powershell;
  const attackKey = `${command} attack`;
  if (attackActive && Object.prototype.hasOwnProperty.call(commands, attackKey)) {
    return commands[attackKey];
  }
  if (Object.prototype.hasOwnProperty.call(commands, command)) {
    return commands[command];
  }
  return null;
};

interface ExecInput {
  command?: string;
  currentStep?: number;
  mode?: ShellMode;
  shellType?: ShellType;
  attackActive?: boolean;
  baselineEstablished?: boolean;
  commandHistory?: unknown;
  cwd?: string;
  filesystem?: unknown;
}

interface ExecResult {
  output: string | null;
  error: string | null;
  progressNote: string | null;
  commandHistory: string[];
  currentStep: number;
  mode: ShellMode;
  shellType: ShellType;
  attackActive: boolean;
  baselineEstablished: boolean;
  stepChanged: boolean;
  cwd: string;
  filesystem: FsNode | null;
  prompt: string;
  clear?: boolean;
}

const executeCommand = (body: ExecInput): ExecResult => {
  const cmd = normalizeCommand(body.command || '');
  const mode = parseMode(body.mode);
  const shellType = parseShellType(body.shellType);
  const steps = LEARNING_STEPS[shellType];
  const history = Array.isArray(body.commandHistory)
    ? body.commandHistory
        .filter((entry): entry is string => typeof entry === 'string')
        .slice(-200)
        .map(normalizeCommand)
    : [];

  const state: ShellState = {
    commandHistory: history,
    currentStep: clampStep(shellType, body.currentStep ?? 0),
    mode,
    shellType,
    attackActive: body.attackActive === true,
    baselineEstablished: body.baselineEstablished === true,
    cwd: typeof body.cwd === 'string' ? body.cwd : '/home/blueteam-user',
    filesystem: null,
  };

  let output: string | null = null;
  let error: string | null = null;
  let stepChanged = false;
  let progressNote: string | null = null;
  let clear = false;
  let trackedCmd = cmd;

  if (cmd === 'stop attack' || cmd === 'end-attack') {
    trackedCmd = 'stop-attack';
  }

  if (cmd === 'baseline') {
    output = shellType === 'bash' ? BASH_LAB.baseline : COMMANDS.powershell.baseline.output;
    state.baselineEstablished = true;
  } else if (cmd === 'start-attack') {
    if (state.baselineEstablished) {
      output = shellType === 'bash' ? BASH_LAB['start-attack'] : COMMANDS.powershell['start-attack'].output;
      state.attackActive = true;
    } else {
      error = 'Cannot start attack: Baseline not established. Type "baseline" first.';
    }
  } else if (trackedCmd === 'stop-attack') {
    if (state.attackActive) {
      state.attackActive = false;
      output = shellType === 'bash' ? BASH_LAB['stop-attack'] : COMMANDS.powershell['stop-attack'].output;
      if (shellType === 'bash') {
        const session = createBashSession({
          cwd: body.cwd,
          filesystem: body.filesystem,
          history,
          attackActive: false,
        });
        state.cwd = session.cwd;
        state.filesystem = session.filesystem;
      }
    } else {
      error = 'No attack is active. Type start-attack first (after baseline).';
    }
  } else if (cmd.startsWith('shell-type ')) {
    const newType = cmd.slice('shell-type '.length);
    if (newType === 'bash' || newType === 'powershell') {
      state.shellType = newType;
      output = `Shell switched to ${newType}. Use ${newType} commands.`;
      if (newType === 'bash') {
        state.cwd = '/home/blueteam-user';
        state.filesystem = null;
      }
    } else {
      error = `Unknown shell type: ${newType}. Use 'bash' or 'powershell'.`;
    }
  } else if (cmd === 'lab-info') {
    output = shellType === 'bash' ? BASH_LAB['lab-info'] : COMMANDS.powershell['lab-info'].output;
  } else if (shellType === 'bash') {
    const session = createBashSession({
      cwd: body.cwd,
      filesystem: body.filesystem,
      history,
      attackActive: state.attackActive,
    });
    const result = executeBash(session, cmd, { attackActive: state.attackActive });
    output = result.output || null;
    error = result.error;
    state.cwd = result.cwd;
    state.filesystem = result.filesystem;
    clear = result.clear === true;
    if (clear) {
      output = null;
      error = null;
    }
  } else {
    const entry = lookupCommand(cmd, state.attackActive);
    if (entry) {
      output = cmd === 'Get-Date' ? new Date().toLocaleString() : entry.output;
    } else {
      error = `Command not found: ${cmd}. Type 'help' for available commands.`;
    }
  }

  // Advance only for the shell the learner is still on, and only on a successful command.
  if (mode === 'learning' && output && !error && state.shellType === shellType) {
    const stepDef = steps[state.currentStep];
    if (stepDef && stepDef.accept.includes(trackedCmd)) {
      const seen = new Set([...history, trackedCmd]);
      const finished = !stepDef.requireAll || stepDef.accept.every((expected) => seen.has(expected));
      if (finished) {
        state.currentStep += 1;
        stepChanged = true;
      } else {
        const missing = stepDef.accept.filter((expected) => !seen.has(expected));
        progressNote = `Recorded ${trackedCmd}. Still run: ${missing.join(', ')}`;
      }
    }
  }

  if (cmd) {
    state.commandHistory = [...history, trackedCmd === 'stop-attack' ? trackedCmd : cmd].slice(-200);
  }

  const prompt =
    state.shellType === 'powershell'
      ? getShellPrompt('powershell')
      : formatBashPrompt(state.cwd);

  return {
    output,
    error,
    progressNote,
    commandHistory: state.commandHistory,
    currentStep: state.currentStep,
    mode: state.mode,
    shellType: state.shellType,
    attackActive: state.attackActive,
    baselineEstablished: state.baselineEstablished,
    stepChanged,
    cwd: state.cwd,
    filesystem: state.shellType === 'bash' ? state.filesystem : null,
    prompt,
    clear,
  };
};

// HTML Generation
const baseStyles = `
:root {
  --bg: #161d17; --bg2: #1f2721; --bg3: #2a342d;
  --border: #3a453f; --text: #e6edf3; --text2: #b8c5d1; --text3: #7a8a99;
  --accent: #3b82f6; --accent2: #2563eb; --good: #4ade80; --bad: #f87171;
  --r: 12px; --r2: 6px; --shadow: 0 1px 3px rgba(0,0,0,.3);
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif; background: var(--bg); color: var(--text); min-height: 100vh; }
.bar { display: flex; justify-content: space-between; align-items: center; gap: 16px; padding: 14px 28px; border-bottom: 1px solid var(--border); background: var(--bg); flex-wrap: wrap; }
.brand { display: flex; align-items: center; gap: 12px; }
.t { letter-spacing: -.01em; margin: 0; font-size: 16px; font-weight: 700; }
.st { color: var(--text3); margin: 1px 0 0; font-size: 12px; }
.btn { background: var(--accent); color: #fff; letter-spacing: .06em; text-transform: uppercase; box-shadow: var(--shadow); border: none; border-radius: 999px; display: inline-flex; align-items: center; gap: 8px; padding: 9px 22px; font-size: 13px; font-weight: 700; cursor: pointer; text-decoration: none; }
.btn:hover { background: var(--accent2); }
.panel { background: var(--bg); border: 1px solid var(--border); border-top: 3px solid var(--good); border-radius: var(--r); box-shadow: var(--shadow); padding: 16px 18px 18px; }
.kicker { letter-spacing: .12em; text-transform: uppercase; color: var(--good); margin: 0; font-size: 10px; font-weight: 700; }
.pt { letter-spacing: -.01em; margin: 6px 0 2px; font-size: 17px; font-weight: 700; }
.cap { color: var(--text3); margin: 0 0 12px; font-size: 12px; }
.container { max-width: 1400px; margin: 0 auto; padding: 24px; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px,1fr)); gap: 20px; }
.tag { letter-spacing: .08em; text-transform: uppercase; border-radius: 999px; padding: 2px 8px; font-size: 10px; font-weight: 700; border: 1px solid var(--border); color: var(--text2); background: var(--bg); }
.back { color: var(--accent); text-decoration: none; display: inline-flex; align-items: center; gap: 4px; font-size: 13px; margin-bottom: 16px; }
.back:hover { text-decoration: underline; }
.main { padding: 24px 0; }
.list { flex-direction: column; gap: 8px; margin: 0; padding: 0; list-style: none; display: flex; }
.li { border: 1px solid var(--border); border-radius: var(--r2); background: var(--bg3); padding: 8px 10px; }
.lil { color: var(--text); overflow-wrap: anywhere; word-break: break-word; margin: 0; font-size: 13px; font-weight: 600; line-height: 1.35; }
`;

const getShellPrompt = (shellType: ShellType, cwd = '/home/blueteam-user'): string => {
  if (shellType === 'powershell') {
    return 'PS C:\\Users\\blueteam-user>';
  }
  return formatBashPrompt(cwd);
};

const getWelcomeMessage = (shellType: ShellType): string => {
  if (shellType === 'powershell') {
    return 'Windows Server 2025 PowerShell Terminal. Type help for commands.';
  }
  return 'Linux Terminal. Type help, then try ls, cd, pwd, and cat.';
};

const labsIndexHTML = (base = ''): string => {
  const cards = LABS.map(l => {
    const c = { Beginner: '#4ade80', Intermediate: '#fbbf24', Advanced: '#f87171' }[l.difficulty];
    return `
<a href="${appPath(base, `/labs/${l.id}`)}" class="panel" style="text-decoration:none;color:inherit">
  <p class="kicker">${l.category}</p>
  <h2 class="pt">${l.title}</h2>
  <p class="cap">${l.description}</p>
  <div style="display:flex;gap:8px;margin-top:12px;flex-wrap:wrap">
    <span class="tag" style="border-color:${c};color:${c}">${l.difficulty}</span>
    ${l.tags.map(t => `<span class="tag">${t}</span>`).join('')}
  </div>
</a>`;
  }).join('');

  return `<!doctype html>
<html><head><meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Select Lab - Cyberrange</title><style>${baseStyles}</style>
</head><body>
<div class="bar"><div class="brand"><div><h1 class="t">Cyberrange</h1><p class="st">Blue Team Training</p></div></div>
<div><a href="${appPath(base, '/')}" class="btn">Dashboard</a></div></div>
<div class="container"><div class="main">
<a href="${appPath(base, '/')}" class="back">← Back</a>
<div class="panel"><p class="kicker">Blue Team</p><h2 class="pt">Available Labs</h2>
<p class="cap">Select a lab. Each includes learning mode with baseline → attack simulation.</p></div>
<div class="grid">${cards}</div>
<div class="panel" style="margin-top: 20px;">
  <p class="kicker">Resources</p>
  <h2 class="pt">Training Materials</h2>
  <ul class="list">
    <li class="li"><a href="${appPath(base, '/resources/cyberforce101.pdf.txt')}" class="lil" style="color: var(--accent);">Cyber Force 101 - Course notes</a></li>
    <li class="li"><a href="${appPath(base, '/desktop/windows-server-2025')}" class="lil" style="color: var(--accent);">Windows Server 2025 Desktop UI</a></li>
    <li class="li"><a href="${appPath(base, '/resources/powershell-reference.txt')}" class="lil" style="color: var(--accent);">PowerShell Command Reference</a></li>
    <li class="li"><p class="lil">Blue Team Playbooks</p></li>
  </ul>
</div>
</div></div>
</body></html>`;
};

const shellClientScript = (lab: Lab, state: ShellState, base = ''): string => String.raw`
const BOOT = ${JSON.stringify({
  labId: lab.id,
  base,
  step: state.currentStep,
  mode: state.mode,
  shellType: state.shellType,
  attackActive: state.attackActive,
  baselineEstablished: state.baselineEstablished,
  cwd: state.cwd || '/home/blueteam-user',
  filesystem: state.shellType === 'bash' ? (state.filesystem || createDefaultFilesystem(state.attackActive)) : null,
})};
const BASE = BOOT.base || '';
function appPath(path) {
  return BASE + path;
}
const STEPS = ${JSON.stringify(LEARNING_STEPS)};
const PROMPTS = ${JSON.stringify({
  bash: getShellPrompt('bash'),
  powershell: getShellPrompt('powershell'),
})};
const WELCOME = ${JSON.stringify({
  bash: getWelcomeMessage('bash'),
  powershell: getWelcomeMessage('powershell'),
})};

const lid = BOOT.labId;
const o = document.getElementById('out');
let transcript = [];
let h = [];
let s = BOOT.step;
let m = BOOT.mode;
let st = BOOT.shellType;
let a = BOOT.attackActive;
let b = BOOT.baselineEstablished;
let cwd = BOOT.cwd || '/home/blueteam-user';
let filesystem = BOOT.filesystem || null;
let browse = -1;
let draft = '';

const BASH_COMMANDS = [
  'help','pwd','cd','ls','cat','less','more','head','tail','mkdir','touch','rm','rmdir','cp','mv',
  'echo','grep','find','tree','wc','sort','clear','history','whoami','id','hostname','date','uname',
  'env','printenv','df','free','uptime','ps','top','netstat','ss','ifconfig','ip','ping','which',
  'file','chmod','chown','man','baseline','start-attack','stop-attack','lab-info','shell-type'
];
const POWERSHELL_COMMANDS = [
  'whoami','hostname','Get-Date','pwd','Get-Process','Get-NetTCPConnection','Get-Service','Get-WinEvent',
  'baseline','start-attack','stop-attack','lab-info','shell-type','help','Clear-Host','cls'
];

function storageKey() {
  return 'cyberrange-session-' + lid;
}

function readStore() {
  try {
    return JSON.parse(localStorage.getItem(storageKey()) || 'null');
  } catch (err) {
    return null;
  }
}

function saveSession() {
  try {
    const notesEl = document.getElementById('obs-notes');
    localStorage.setItem(storageKey(), JSON.stringify({
      transcript: transcript,
      commandHistory: h,
      step: s,
      mode: m,
      shellType: st,
      attackActive: a,
      baselineEstablished: b,
      cwd: cwd,
      filesystem: filesystem,
      observations: notesEl ? notesEl.value : (window.__obsNotes || ''),
    }));
  } catch (err) {}
}

function loadObservations(stored) {
  const notesEl = document.getElementById('obs-notes');
  if (!notesEl) return;
  const text = stored && typeof stored.observations === 'string' ? stored.observations : '';
  notesEl.value = text;
  window.__obsNotes = text;
}

function labQuery() {
  return '?mode=' + encodeURIComponent(m)
    + '&step=' + encodeURIComponent(String(s))
    + '&shellType=' + encodeURIComponent(st)
    + '&attack=' + (a ? 'true' : 'false')
    + '&baseline=' + (b ? 'true' : 'false');
}

function syncUrl() {
  history.replaceState(null, '', appPath('/labs/' + lid) + labQuery());
}

function formatBashPrompt(path) {
  const home = '/home/blueteam-user';
  let shown = path || home;
  if (shown === home) shown = '~';
  else if (shown.indexOf(home + '/') === 0) shown = '~' + shown.slice(home.length);
  return 'blueteam-user@cyberrange:' + shown + '$';
}

function promptText() {
  if (st === 'powershell') return PROMPTS.powershell;
  return formatBashPrompt(cwd);
}

function normalize(command) {
  return String(command || '').trim().replace(/\s+/g, ' ');
}

function setInputValue(input, value) {
  input.value = value;
  const end = value.length;
  if (typeof input.setSelectionRange === 'function') {
    input.setSelectionRange(end, end);
  }
}

function commonPrefix(items) {
  if (!items.length) return '';
  let prefix = items[0];
  for (let i = 1; i < items.length; i++) {
    while (items[i].indexOf(prefix) !== 0) {
      prefix = prefix.slice(0, -1);
      if (!prefix) return '';
    }
  }
  return prefix;
}

function normalizeFsPath(path) {
  const parts = String(path || '/').split('/').filter(function (part) { return part && part !== '.'; });
  const stack = [];
  for (let i = 0; i < parts.length; i++) {
    if (parts[i] === '..') stack.pop();
    else stack.push(parts[i]);
  }
  return '/' + stack.join('/');
}

function expandFsPath(base, target) {
  let path = String(target || '.');
  const home = '/home/blueteam-user';
  if (path === '~' || path.indexOf('~/') === 0) path = home + path.slice(1);
  if (path.charAt(0) !== '/') path = (base === '/' ? '/' : base + '/') + path;
  return normalizeFsPath(path);
}

function getFsNode(root, absolutePath) {
  if (!root) return null;
  const path = normalizeFsPath(absolutePath);
  if (path === '/') return root;
  let current = root;
  const parts = path.split('/').filter(Boolean);
  for (let i = 0; i < parts.length; i++) {
    if (!current || current.type !== 'dir' || !current.children || !Object.prototype.hasOwnProperty.call(current.children, parts[i])) {
      return null;
    }
    current = current.children[parts[i]];
  }
  return current;
}

function listFsNames(absoluteDir) {
  const node = getFsNode(filesystem, absoluteDir);
  if (!node || node.type !== 'dir' || !node.children) return [];
  return Object.keys(node.children).sort();
}

function commandSuggestions() {
  return st === 'powershell' ? POWERSHELL_COMMANDS.slice() : BASH_COMMANDS.slice();
}

function pathSuggestions(token) {
  if (!filesystem) return [];
  const home = '/home/blueteam-user';
  let raw = token || '';
  let dirname = '';
  let partial = raw;
  const slash = raw.lastIndexOf('/');
  if (slash >= 0) {
    dirname = raw.slice(0, slash + 1);
    partial = raw.slice(slash + 1);
  }

  let searchDir;
  if (!dirname) {
    searchDir = cwd;
  } else if (dirname === '~/') {
    searchDir = home;
  } else if (dirname.indexOf('~/') === 0) {
    searchDir = expandFsPath(cwd, dirname.slice(0, -1) || '~');
  } else {
    searchDir = expandFsPath(cwd, dirname.slice(0, -1) || (dirname.charAt(0) === '/' ? '/' : '.'));
  }

  return listFsNames(searchDir)
    .filter(function (name) { return name.indexOf(partial) === 0; })
    .map(function (name) {
      const node = getFsNode(filesystem, normalizeFsPath(searchDir + '/' + name));
      const suffix = node && node.type === 'dir' ? '/' : '';
      return dirname + name + suffix;
    });
}

function autocomplete(input) {
  const value = input.value;
  const cursor = typeof input.selectionStart === 'number' ? input.selectionStart : value.length;
  const before = value.slice(0, cursor);
  const after = value.slice(cursor);
  const match = before.match(/^(.*?)(\S*)$/);
  if (!match) return;
  const prefix = match[1];
  const token = match[2];
  const isFirst = !prefix.trim();

  let matches = [];
  if (isFirst) {
    matches = commandSuggestions().filter(function (cmd) { return cmd.indexOf(token) === 0; });
  } else if (st === 'bash') {
    matches = pathSuggestions(token);
  } else {
    matches = commandSuggestions().filter(function (cmd) { return cmd.indexOf(token) === 0; });
  }

  if (!matches.length) return;

  if (matches.length === 1) {
    setInputValue(input, prefix + matches[0] + after);
    return;
  }

  const shared = commonPrefix(matches);
  if (shared && shared.length > token.length) {
    setInputValue(input, prefix + shared + after);
    return;
  }

  addBlock(matches.join('  '), '#7a8a99');
  o.scrollTop = o.scrollHeight;
}

function statusHtml() {
  if (a) return '<span class="sb sb-a">ATTACK ACTIVE</span>';
  if (b) return '<span class="sb sb-b">BASELINE OK</span>';
  return '<span class="tag">Establish Baseline</span>';
}

function updateSidebar() {
  const steps = STEPS[st] || STEPS.bash;
  const total = steps.length;
  const done = s >= total;
  const view = steps[Math.min(s, total - 1)];
  const count = document.getElementById('step-count');
  const title = document.getElementById('step-title');
  const why = document.getElementById('step-why');
  const observe = document.getElementById('step-observe');
  const action = document.getElementById('step-action');
  const fill = document.getElementById('progress-fill');
  const slot = document.getElementById('status-slot');
  const prev = document.getElementById('prev');
  const kicker = document.getElementById('mode-kicker');
  const term = document.getElementById('term-label');
  if (kicker) kicker.textContent = m === 'free' ? 'Free Mode' : 'Learning Mode';
  if (term) term.textContent = 'Terminal (' + st + ')';

  const freeWhy = 'Free mode is open practice on the same simulated host.';
  const freeObserve = 'Write anything useful: paths, ports, log lines, or attack indicators.';
  const freeAction = 'Type help for commands.\nArrow keys = history, Tab = autocomplete.\nUse start-attack / stop-attack to control the simulation.';
  const doneWhy = 'Guided path complete. You can keep investigating in Free mode, or restart the attack.';
  const doneObserve = 'Your notepad should include the attacker IP 203.0.113.45 and how you found it.';
  const doneAction = a
    ? 'Attack is still active.\nDo this now:\nstop-attack'
    : (st === 'powershell'
      ? 'Optional: start-attack again, or switch to Free mode.'
      : 'Optional: start-attack again, or switch to Free mode.');

  if (m === 'free') {
    if (count) count.textContent = 'Free mode';
    if (title) title.textContent = 'Open investigation';
    if (why) why.textContent = freeWhy;
    if (observe) observe.textContent = freeObserve;
    if (action) action.textContent = freeAction;
  } else if (done) {
    if (count) count.textContent = 'Lab complete';
    if (title) title.textContent = a ? 'Attack still active' : 'Lab complete';
    if (why) why.textContent = doneWhy;
    if (observe) observe.textContent = doneObserve;
    if (action) action.textContent = doneAction;
  } else {
    if (count) count.textContent = 'Step ' + (s + 1) + ' of ' + total;
    if (title) title.textContent = 'Step ' + (s + 1) + ': ' + view.label;
    if (why) why.textContent = view.why;
    if (observe) observe.textContent = view.observe;
    if (action) action.textContent = view.action;
  }
  if (fill) fill.style.width = (done || m === 'free' ? 100 : Math.round((s / total) * 100)) + '%';
  if (slot) slot.innerHTML = statusHtml();
  if (prev) prev.style.display = s > 0 ? 'inline-flex' : 'none';
  const stopBtn = document.getElementById('stop-attack');
  if (stopBtn) stopBtn.style.display = a ? 'inline-flex' : 'none';
}

function addBlock(text, color) {
  if (!text) return;
  const line = document.createElement('div');
  if (color) line.style.color = color;
  line.textContent = text;
  o.appendChild(line);
}

function appendInput() {
  const line = document.createElement('div');
  line.className = 'input-line';
  const pr = document.createElement('span');
  pr.className = 'pr';
  pr.textContent = promptText();
  const input = document.createElement('input');
  input.className = 'in';
  input.type = 'text';
  input.setAttribute('autocomplete', 'off');
  input.setAttribute('autocapitalize', 'off');
  input.spellcheck = false;
  input.setAttribute('aria-label', 'Command');
  line.appendChild(pr);
  line.appendChild(input);
  o.appendChild(line);
  input.focus();
  o.scrollTop = o.scrollHeight;
  return input;
}

function paintEntry(entry) {
  const line = document.createElement('div');
  const pr = document.createElement('span');
  pr.className = 'pr';
  pr.textContent = entry.prompt || promptText();
  const cmd = document.createElement('span');
  cmd.textContent = ' ' + entry.command;
  line.appendChild(pr);
  line.appendChild(cmd);
  o.appendChild(line);
  addBlock(entry.output, '');
  addBlock(entry.note, '#fbbf24');
  addBlock(entry.error, '#ff5555');
}

function paint() {
  o.textContent = '';
  if (!transcript.length) {
    const welcome = document.createElement('div');
    welcome.style.color = '#888';
    welcome.textContent = WELCOME[st] || WELCOME.bash;
    o.appendChild(welcome);
  }
  transcript.forEach(paintEntry);
  appendInput();
}

function resetSession() {
  if (confirm('Reset this lab session? All command history and progress will be cleared.')) {
    localStorage.removeItem(storageKey());
    window.location.href = appPath('/labs/' + lid);
  }
}

function setMode(mode) {
  m = mode;
  saveSession();
  window.location.href = appPath('/labs/' + lid) + labQuery();
}

function setShellType(shell) {
  st = shell;
  saveSession();
  window.location.href = appPath('/labs/' + lid) + labQuery();
}

function prevStep() {
  s = Math.max(0, s - 1);
  saveSession();
  window.location.href = appPath('/labs/' + lid) + labQuery();
}

async function stopAttack() {
  if (!a) return;
  const input = o && o.querySelector('input.in');
  if (!input) return;
  input.value = 'stop-attack';
  await exec(input);
}

async function exec(input) {
  if (input.disabled) return;
  const c = normalize(input.value);
  if (!c) return;
  input.disabled = true;
  browse = -1;

  const usedPrompt = promptText();
  const line = input.parentElement;
  line.textContent = '';
  const pr = document.createElement('span');
  pr.className = 'pr';
  pr.textContent = usedPrompt;
  const cmd = document.createElement('span');
  cmd.textContent = ' ' + c;
  line.appendChild(pr);
  line.appendChild(cmd);

  let data = null;
  try {
    const r = await fetch(appPath('/api/labs/' + lid + '/command'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        command: c,
        currentStep: s,
        mode: m,
        shellType: st,
        attackActive: a,
        baselineEstablished: b,
        commandHistory: h,
        cwd: cwd,
        filesystem: filesystem,
      }),
    });
    data = await r.json();
    if (!r.ok) {
      addBlock((data && data.error) || 'Error talking to the lab. Try again.', '#ff5555');
      appendInput();
      return;
    }
  } catch (err) {
    addBlock('Error talking to the lab. Try again.', '#ff5555');
    appendInput();
    return;
  }

  if (data.clear) {
    transcript = [];
    h = [];
    if (typeof data.cwd === 'string') cwd = data.cwd;
    if (data.filesystem) filesystem = data.filesystem;
    saveSession();
    paint();
    return;
  }

  addBlock(data.output, '');
  addBlock(data.progressNote, '#fbbf24');
  addBlock(data.error, '#ff5555');

  transcript.push({
    command: c,
    prompt: usedPrompt,
    output: data.output || '',
    error: data.error || '',
    note: data.progressNote || '',
  });
  if (transcript.length > 200) transcript.shift();
  h = transcript.map(function (entry) { return entry.command; });

  if (typeof data.currentStep === 'number') s = data.currentStep;
  if (data.mode) m = data.mode;
  const nextShell = data.shellType || st;
  a = data.attackActive === true;
  b = data.baselineEstablished === true;
  if (typeof data.cwd === 'string') cwd = data.cwd;
  if (data.filesystem) filesystem = data.filesystem;
  saveSession();

  if (nextShell !== st) {
    st = nextShell;
    filesystem = null;
    cwd = '/home/blueteam-user';
    saveSession();
    window.location.href = appPath('/labs/' + lid) + labQuery();
    return;
  }

  syncUrl();
  updateSidebar();
  appendInput();
}

function boot() {
  const params = new URLSearchParams(location.search);
  const stored = readStore();
  const explicit = params.has('step') || params.has('mode') || params.has('shellType') || params.has('attack') || params.has('baseline');

  if (stored && !explicit) {
    if (stored.shellType === 'bash' || stored.shellType === 'powershell') st = stored.shellType;
    if (stored.mode === 'learning' || stored.mode === 'free') m = stored.mode;
    if (typeof stored.step === 'number') s = stored.step;
    if (typeof stored.attackActive === 'boolean') a = stored.attackActive;
    if (typeof stored.baselineEstablished === 'boolean') b = stored.baselineEstablished;
    if (typeof stored.cwd === 'string') cwd = stored.cwd;
    const drift = st !== BOOT.shellType || m !== BOOT.mode || s !== BOOT.step || a !== BOOT.attackActive || b !== BOOT.baselineEstablished;
    if (drift) {
      window.location.replace(appPath('/labs/' + lid) + labQuery());
      return;
    }
  }

  if (stored && (!stored.shellType || stored.shellType === st)) {
    if (Array.isArray(stored.transcript)) {
      transcript = stored.transcript.filter(function (entry) {
        return entry && typeof entry.command === 'string';
      });
    } else if (Array.isArray(stored.commandHistory)) {
      transcript = stored.commandHistory.filter(function (command) {
        return typeof command === 'string';
      }).map(function (command) {
        return { command: command, output: '', error: '', note: '', prompt: '' };
      });
    }
    h = transcript.map(function (entry) { return entry.command; });
    if (typeof stored.cwd === 'string') cwd = stored.cwd;
    if (stored.filesystem) filesystem = stored.filesystem;
  }

  updateSidebar();
  paint();
  syncUrl();
  loadObservations(stored);
  const notesEl = document.getElementById('obs-notes');
  if (notesEl) {
    notesEl.addEventListener('input', function () {
      window.__obsNotes = notesEl.value;
      saveSession();
    });
  }
}

if (o) {
  o.addEventListener('click', function (e) {
    if (e.target && e.target.classList && e.target.classList.contains('in')) return;
    const input = o.querySelector('input.in');
    if (input) input.focus();
  });
  o.addEventListener('keydown', function (e) {
    const input = e.target;
    if (!input || !input.classList || !input.classList.contains('in')) return;
    if ((e.ctrlKey || e.metaKey) && (e.key === 'l' || e.key === 'L')) {
      e.preventDefault();
      transcript = [];
      h = [];
      browse = -1;
      draft = '';
      saveSession();
      paint();
      return;
    }
    if (e.key === 'Tab') {
      e.preventDefault();
      autocomplete(input);
      return;
    }
    if (e.key === 'Enter') {
      e.preventDefault();
      draft = '';
      browse = -1;
      exec(input);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (!h.length) return;
      if (browse < 0) {
        draft = input.value;
        browse = h.length;
      }
      if (browse > 0) browse -= 1;
      setInputValue(input, h[browse] || '');
    } else if (e.key === 'ArrowDown') {
      if (browse < 0) return;
      e.preventDefault();
      browse += 1;
      if (browse >= h.length) {
        browse = -1;
        setInputValue(input, draft);
        draft = '';
      } else {
        setInputValue(input, h[browse] || '');
      }
    } else if (browse >= 0 && e.key !== 'Shift' && e.key !== 'Control' && e.key !== 'Alt' && e.key !== 'Meta') {
      // Leave history browse mode once the user edits the recalled command.
      if (e.key.length === 1 || e.key === 'Backspace' || e.key === 'Delete') {
        browse = -1;
        draft = '';
      }
    }
  });
}

boot();
`;

const shellHTML = (lab: Lab, state: ShellState, base = ''): string => {
  const { attackActive, baselineEstablished, shellType } = state;
  const step = state.currentStep;
  const steps = LEARNING_STEPS[shellType];
  const totalSteps = steps.length;
  const done = step >= totalSteps;
  const view = steps[Math.min(step, Math.max(totalSteps - 1, 0))];
  const progress = done ? 100 : Math.round((step / totalSteps) * 100);

  const modeTabs = (m: ShellMode) => ['learning','free'].map(x =>
    `<span class="tab" onclick="setMode('${x}')" style="padding:6px 12px;border-radius:999px;font-size:11px;font-weight:600;cursor:pointer;border:1px solid var(--border);${x===m?'background:var(--accent);color:#fff': 'background:var(--bg3);color:var(--text2)'}">${x}</span>`
  ).join('');

  const shellTabs = (s: ShellType) => ['bash','powershell'].map(x =>
    `<span class="tab" onclick="setShellType('${x}')" style="padding:6px 12px;border-radius:999px;font-size:11px;font-weight:600;cursor:pointer;border:1px solid var(--border);${x===s?'background:var(--accent);color:#fff': 'background:var(--bg3);color:var(--text2)'}">${x}</span>`
  ).join('');

  return `<!doctype html>
<html><head><meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>${lab.title}</title><style>
${baseStyles}
.lab { display: grid; grid-template-columns: 340px 1fr; gap: 20px; }
.sidebar { background: var(--bg); border: 1px solid var(--border); border-radius: var(--r); padding: 16px; max-height: calc(100vh - 140px); overflow-y: auto; }
.pb { height: 4px; background: var(--bg3); border-radius: 2px; overflow: hidden; margin-bottom: 8px; }
.pf { height: 100%; background: linear-gradient(90deg,var(--accent),var(--good)); width: 0; transition: width .3s; }
@media (max-width: 800px) { .lab { grid-template-columns: 1fr; } .sidebar { max-height: none; } }
.cs { background: var(--bg2); border: 1px solid var(--border); border-radius: var(--r2); padding: 12px; margin-top: 12px; }
.cst { font-size: 13px; font-weight: 700; color: var(--accent); margin: 0 0 8px; }
.csi { font-size: 12px; color: var(--text2); line-height: 1.5; margin: 0 0 10px; }
.cs-label { letter-spacing: .08em; text-transform: uppercase; color: var(--text3); font-size: 10px; font-weight: 700; margin: 0 0 4px; }
.cs-action { font-family: Consolas,monospace; font-size: 12px; color: var(--good); background: rgba(74,222,128,.08); border: 1px solid rgba(74,222,128,.25); border-radius: var(--r2); padding: 8px 10px; margin: 0; line-height: 1.45; white-space: pre-wrap; }
.ab-stop { background: rgba(248,113,113,.12); border-color: rgba(248,113,113,.45); color: var(--bad); }
.ab-stop:hover { border-color: var(--bad); color: #fff; background: rgba(248,113,113,.25); }
.obs { margin-top: 12px; }
.obs-box { width: 100%; min-height: 140px; resize: vertical; background: #0a0a0a; color: var(--text); border: 1px solid var(--border); border-radius: var(--r2); padding: 10px; font-family: Consolas,monospace; font-size: 12px; line-height: 1.45; }
.obs-box:focus { outline: 1px solid var(--accent); }
.shell { background: var(--bg); border: 1px solid var(--border); border-radius: var(--r); padding: 16px; display: flex; flex-direction: column; min-height: 500px; }
.sh { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; padding-bottom: 12px; border-bottom: 1px solid var(--border); flex-wrap: wrap; gap: 8px; }
.st2 { font-size: 14px; font-weight: 600; color: var(--text); }
.tab { transition: all .12s; }
.tab:hover { border-color: var(--text3); }
.out { flex: 1; background: #0a0a0a; border: 1px solid var(--border); border-radius: var(--r2); padding: 12px; font-family: Consolas,monospace; font-size: 12px; line-height: 1.5; color: #d4d4d4; overflow-y: auto; min-height: 300px; white-space: pre-wrap; }
#term { flex: 1; min-height: 320px; border: 1px solid var(--border); border-radius: var(--r2); overflow: hidden; background: #0a0a0a; padding: 4px; }
.desktop-link { margin-top: 8px; display: inline-flex; }
.ipc { display: flex; gap: 8px; margin-top: 12px; }
.pr { color: var(--accent); font-family: Consolas,monospace; font-size: 12px; white-space: nowrap; }
.in { background: transparent; border: none; padding: 0; margin: 0; font-family: Consolas,monospace; font-size: 12px; color: #fff; outline: none; flex: 1; min-width: 0; caret-color: #fff; }
.in:focus { outline: none; }
.input-line { display: flex; align-items: center; gap: 8px; width: 100%; white-space: nowrap; }
.sb { display: inline-flex; align-items: center; gap: 6px; padding: 4px 10px; border-radius: 999px; font-size: 11px; font-weight: 600; }
.sb-b { background: rgba(74,222,128,.15); color: var(--good); border: 1px solid rgba(74,222,128,.3); }
.sb-a { background: rgba(248,113,113,.15); color: var(--bad); border: 1px solid rgba(248,113,113,.3); animation: p 1s infinite; }
@keyframes p { 0%,100%{opacity:1}50%{opacity:.7} }
.ab { background: var(--bg2); border: 1px solid var(--border); border-radius: var(--r2); color: var(--text2); padding: 8px 12px; font-size: 12px; cursor: pointer; transition: all .12s; margin-top: 12px; display: inline-flex; align-items: center; gap: 6px; }
.ab:hover { border-color: var(--text3); color: var(--text); }
</style>
</head><body>
<div class="bar"><div class="brand"><div><h1 class="t">${lab.title}</h1><p class="st">${lab.category} • ${lab.difficulty}</p></div></div>
<div><a href="${appPath(base, '/labs')}" class="btn">All Labs</a></div></div>
<div class="container"><div class="main">
<a href="${appPath(base, '/labs')}" class="back">← All Labs</a>
<div class="lab">
<div class="sidebar">
<p class="kicker" id="mode-kicker">${state.mode === 'free' ? 'Free Mode' : 'Learning Mode'}</p><h3 style="margin:6px 0 2px;font-size:14px;font-weight:700">Progress</h3>
<div style="margin-bottom:12px"><div class="pb"><div class="pf" id="progress-fill" style="width:${progress}%"></div></div>
<p id="step-count" style="font-size:11px;color:var(--text3)">${done ? 'Lab complete' : `Step ${step + 1} of ${totalSteps}`}</p></div>
<div class="cs">
<p class="cst" id="step-title">${done ? 'Detect and document' : `Step ${step + 1}: ${esc(view.label)}`}</p>
<p class="cs-label">Why this matters</p>
<p class="csi" id="step-why">${done
  ? 'Guided path complete. You can keep investigating in Free mode, or restart the attack.'
  : esc(view.why)}</p>
<p class="cs-label">What to observe</p>
<p class="csi" id="step-observe">${done
  ? 'Your notepad should include the attacker IP 203.0.113.45 and how you found it.'
  : esc(view.observe)}</p>
<p class="cs-label">What to run</p>
<p class="cs-action" id="step-action">${done
  ? (attackActive ? 'Attack is still active.\nDo this now:\nstop-attack' : 'Optional: start-attack again, or switch to Free mode.')
  : esc(view.action)}</p>
</div>
<div class="obs">
<p class="cs-label">Observation notepad</p>
<p class="csi" style="margin-bottom:8px">Use this pad for host facts, baseline notes, and attack indicators as you work. It saves with your session.</p>
<textarea id="obs-notes" class="obs-box" placeholder="Hostname:&#10;User:&#10;Listening ports:&#10;Baseline notes:&#10;Attack indicators:"></textarea>
</div>
<div style="display:flex;gap:8px;margin-top:16px;flex-wrap:wrap">
<span id="status-slot">${attackActive ? '<span class="sb sb-a">ATTACK ACTIVE</span>' : baselineEstablished ? '<span class="sb sb-b">BASELINE OK</span>' : '<span class="tag">Establish Baseline</span>'}</span>
<span class="tag">${esc(lab.difficulty)}</span>
${lab.tags.map(t => `<span class="tag">${esc(t)}</span>`).join('')}
</div>
<button class="ab" id="prev" onclick="prevStep()" style="display:${step > 0 ? 'inline-flex' : 'none'}">← Previous</button>
<button class="ab ab-stop" id="stop-attack" onclick="stopAttack()" style="display:${attackActive ? 'inline-flex' : 'none'}; margin-top: 8px;">Stop attack</button>
<button class="ab" onclick="resetSession()" style="margin-top: 8px;">Reset session</button>
${lab.id === 'windows-server-2025' ? `<a class="ab desktop-link" href="${appPath(base, '/desktop/windows-server-2025')}">Open Windows desktop UI →</a>` : ''}
</div>
<div class="shell">
<div class="sh"><span class="st2" id="term-label">Terminal (${esc(shellType)}${shellType === 'bash' ? ' · just-bash' : ''})</span><div style="display:flex;gap:8px;">${modeTabs(state.mode)}</div><div style="margin-top:8px;">${shellTabs(shellType)}</div></div>
${shellType === 'bash' ? '<div id="term"></div>' : '<div class="out" id="out"></div>'}
</div></div></div></div>
${shellType === 'bash' ? `<script>window.__LAB_BOOT__=${JSON.stringify({
  base,
  labId: lab.id,
  step: state.currentStep,
  mode: state.mode,
  shellType: state.shellType,
  attackActive: state.attackActive,
  baselineEstablished: state.baselineEstablished,
  steps: LEARNING_STEPS.bash,
})};</script>
<script type="module" src="${appPath(base, '/emulation/linux-lab.js')}"></script>` : `<script>
${shellClientScript(lab, state, base)}
</script>`}
</body></html>`;
};

const dashboardHTML = (base = ''): string => `<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Cyberrange Dashboard</title>
  <style>${baseStyles}</style>
</head>
<body>
  <div class="bar">
    <div class="brand">
      <div>
        <h1 class="t">Cyberrange Dashboard</h1>
        <p class="st">Blue Team Training Platform</p>
      </div>
    </div>
    <div><a href="${appPath(base, '/labs')}" class="btn">Labs</a></div>
  </div>
  <div class="container">
    <div class="main">
      <div class="panel">
        <p class="kicker">Welcome</p>
        <h2 class="pt">Blue Team Training Platform</h2>
        <p class="cap">A cybersecurity training range built on Cloudflare Workers. Select a lab to begin.</p>
      </div>
      <div class="grid">
        <div class="panel">
          <p class="kicker">Quick Start</p>
          <h2 class="pt">New to Cyberrange?</h2>
          <p class="cap">Browse our available labs to start your blue team training journey.</p>
          <a href="${appPath(base, '/labs')}" class="btn" style="margin-top: 12px; display: inline-block;">Browse Labs</a>
        </div>
        <div class="panel">
          <p class="kicker">Features</p>
          <h2 class="pt">What You Get</h2>
          <ul class="list">
            <li class="li"><p class="lil">Simulated Terminal (bash/PowerShell)</p></li>
            <li class="li"><p class="lil">Learning Mode Guidance</p></li>
            <li class="li"><p class="lil">Baseline to Attack Flow</p></li>
            <li class="li"><p class="lil">Blue Team Scenarios</p></li>
          </ul>
        </div>
        <div class="panel">
          <p class="kicker">Environments</p>
          <h2 class="pt">Available Shells</h2>
          <ul class="list">
            <li class="li"><p class="lil">Linux (bash)</p></li>
            <li class="li"><p class="lil">Windows Server 2025 (PowerShell)</p></li>
          </ul>
          <p class="cap" style="margin-top: 12px;">Switch between shells in any lab using: <code style="background: var(--bg3); padding: 2px 6px; border-radius: 4px;">shell-type bash</code> or <code style="background: var(--bg3); padding: 2px 6px; border-radius: 4px;">shell-type powershell</code></p>
        </div>
      </div>
      <div class="panel" style="margin-top: 20px;">
        <p class="kicker">Resources</p>
        <h2 class="pt">Training Materials</h2>
        <ul class="list">
          <li class="li"><a href="${appPath(base, '/resources/cyberforce101.pdf.txt')}" class="lil" style="color: var(--accent);">Cyber Force 101 - Course notes</a></li>
          <li class="li"><a href="${appPath(base, '/desktop/windows-server-2025')}" class="lil" style="color: var(--accent);">Windows Server 2025 Desktop UI</a></li>
          <li class="li"><a href="${appPath(base, '/resources/powershell-reference.txt')}" class="lil" style="color: var(--accent);">PowerShell Command Reference</a></li>
          <li class="li"><p class="lil">Blue Team Playbooks</p></li>
        </ul>
      </div>
    </div>
  </div>
</body>
</html>`;

const windowsDesktopHTML = (base = ''): string => `<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Windows Server 2025 Desktop — Cyberrange</title>
</head>
<body>
  <div id="desktop-root"></div>
  <script type="module" src="${appPath(base, '/emulation/windows-lab.js')}"></script>
</body>
</html>`;

// ============================================
// Request Handler
// ============================================

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const headerBase = request.headers.get('X-Base-Path');
    const base = headerBase === '/range' ? '/range' : getBasePath(url.pathname);
    const path =
      headerBase === '/range'
        ? url.pathname || '/'
        : stripBasePath(url.pathname, base);

    // Static emulation bundles (Vite → public/emulation)
    if (path.startsWith('/emulation/')) {
      if (env.ASSETS) {
        const assetUrl = new URL(request.url);
        assetUrl.pathname = path;
        return env.ASSETS.fetch(new Request(assetUrl.toString(), request));
      }
    }

    // Dashboard
    if (path === '/') {
      return new Response(dashboardHTML(base), {
        headers: { 'Content-Type': 'text/html;charset=UTF-8' },
      });
    }

    // Windows desktop UI
    if (path === '/desktop/windows-server-2025') {
      return new Response(windowsDesktopHTML(base), {
        headers: { 'Content-Type': 'text/html;charset=UTF-8' },
      });
    }

    // Labs index
    if (path === '/labs') {
      return new Response(labsIndexHTML(base), {
        headers: { 'Content-Type': 'text/html;charset=UTF-8' },
      });
    }

    // Lab shell
    const labMatch = path.match(/^\/labs\/([a-z0-9-]+)$/);
    if (labMatch) {
      const labId = labMatch[1];
      const lab = LABS.find(l => l.id === labId);
      if (!lab) {
        return new Response('Lab not found', { status: 404 });
      }

      // Parse query params
      const params = new URLSearchParams(url.search);
      const mode = parseMode(params.get('mode'));
      const requestedShell = params.get('shellType');
      const shellType = requestedShell
        ? parseShellType(requestedShell)
        : (lab.id === 'windows-server-2025' ? 'powershell' : 'bash');
      const currentStep = clampStep(shellType, Number.parseInt(params.get('step') || '0', 10));
      const attackActive = params.get('attack') === 'true';
      const baselineEstablished = params.get('baseline') === 'true';

      const state: ShellState = {
        commandHistory: [],
        currentStep,
        mode,
        shellType,
        attackActive,
        baselineEstablished,
        cwd: '/home/blueteam-user',
        filesystem: null,
      };

      return new Response(shellHTML(lab, state, base), {
        headers: { 'Content-Type': 'text/html;charset=UTF-8' },
      });
    }

    // API: Lab command execution
    const commandMatch = path.match(/^\/api\/labs\/([a-z0-9-]+)\/command$/);
    if (commandMatch) {
      const labId = commandMatch[1];
      const lab = LABS.find(l => l.id === labId);
      if (!lab) {
        return new Response(JSON.stringify({ error: 'Lab not found' }), {
          status: 404,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      if (request.method !== 'POST') {
        return new Response(JSON.stringify({ error: 'Method not allowed' }), {
          status: 405,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      try {
        const body = await request.json<ExecInput>();

        if (!body || typeof body !== 'object' || !body.command || !normalizeCommand(body.command)) {
          return new Response(JSON.stringify({ error: 'No command provided' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' },
          });
        }

        return new Response(JSON.stringify(executeCommand(body)), {
          headers: { 'Content-Type': 'application/json' },
        });
      } catch (err) {
        return new Response(JSON.stringify({ error: 'Invalid request body' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' },
        });
      }
    }

    // Health check
    if (path === '/health') {
      return new Response(JSON.stringify({ status: 'ok', timestamp: Date.now() }), {
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // API root
    if (path === '/api') {
      return new Response(
        JSON.stringify({
          name: 'Cyberrange API',
          version: '1.0.0',
          endpoints: {
            health: appPath(base, '/health'),
            labs: appPath(base, '/labs'),
          },
        }),
        { headers: { 'Content-Type': 'application/json' } }
      );
    }

    // Serve resources
    if (path.startsWith('/resources/')) {
      const resourceName = path.split('/').pop();
      
      // Serve actual resource files
      if (resourceName === 'cyberforce101.pdf.txt' || resourceName === 'cyberforce101.pdf') {
        const content = `CYBERRANGE BLUE TEAM TRAINING - COURSE MATERIALS
==================================================

Module 1: Introduction to Blue Team Operations
-----------------------------------------------
- Understanding the Blue Team role in cybersecurity
- Incident detection and response frameworks
- Security monitoring fundamentals
- Threat intelligence basics

Module 2: System Baseline Establishment
----------------------------------------
1. Document normal system state
2. Identify critical processes and services
3. Record network connections
4. Establish performance benchmarks

Key Commands (Linux):
- ps aux - List all running processes
- netstat -tuln - Show listening ports
- top - View system resource usage
- tail -n 20 /var/log/auth.log - Check authentication logs

Key Commands (Windows):
- Get-Process - List all running processes
- Get-NetTCPConnection -State Listen - Show listening ports
- Get-Service | Where-Object { $_.Status -eq "Running" } - List running services
- Get-WinEvent -LogName Security -MaxEvents 5 - View security logs

Module 3: Attack Detection
--------------------------
- Identifying brute force attacks
- SSH attack patterns
- RDP attack patterns
- Log analysis techniques

Module 4: Response Procedures
-----------------------------
- Isolating affected systems
- Preserving evidence
- Incident documentation
- Escalation protocols

PRACTICAL EXERCISES:
1. Network Intrusion Detection Lab
   - Establish baseline on Linux system
   - Detect SSH brute force attack
   - Respond with appropriate countermeasures

2. Windows Server 2025 Hardening Lab
   - Document Windows Server baseline
   - Detect RDP brute force attack
   - Apply security hardening techniques

3. Web Application Attack Detection Lab
   - Monitor web application logs
   - Detect SQL injection attempts
   - Detect XSS attacks

RECOMMENDED TOOLS:
- Wireshark (Network analysis)
- Sysmon (Windows system monitoring)
- Auditd (Linux audit framework)
- Fail2ban (Intrusion prevention)
- ELK Stack (Log analysis)

This material supports hands-on cyber range training for blue team operators.`;
        return new Response(content, {
          headers: { 'Content-Type': 'text/plain;charset=UTF-8' },
        });
      }
      
      if (resourceName === 'powershell-reference.txt') {
        const psRef = `POWERSHELL COMMAND REFERENCE - CYBERRANGE BLUE TEAM TRAINING
==============================================================

SYSTEM INFORMATION COMMANDS:
----------------------------
whoami                    - Show current user
hostname                  - Show computer name
Get-Date                 - Show current date/time
Get-Location             - Show current directory (pwd)
Get-ChildItem            - List files/directories

PROCESS MANAGEMENT:
-------------------
Get-Process              - List all running processes
Get-Service | Where-Object { $_.Status -eq "Running" } - List running services

NETWORK COMMANDS:
-----------------
Get-NetTCPConnection     - Show all TCP connections
Get-NetTCPConnection -State Listen - Show listening ports

LOG AND EVENT VIEWING:
-----------------------
Get-WinEvent -LogName Security -MaxEvents 10 - View security logs
Get-WinEvent -FilterHashtable @{LogName="Security"; ID=4625} - Filter for failed logins

SYSTEM MONITORING:
------------------
Get-WmiObject Win32_Processor - Get CPU information
Get-Counter "\\Processor(_Total)\% Processor Time" - Get CPU usage

CYBERRANGE-SPECIFIC COMMANDS:
-------------------------------
baseline           - Establish system baseline
start-attack       - Begin attack simulation
shell-type bash    - Switch to bash shell
shell-type powershell - Switch to PowerShell shell
help              - Show available commands
lab-info          - Show lab information`;
        return new Response(psRef, {
          headers: { 'Content-Type': 'text/plain;charset=UTF-8' },
        });
      }
      
      if (resourceName === 'windows-server-2025-gui.html') {
        // Return the Windows GUI simulation HTML
        const winGuiHtml = `<!doctype html>
<html lang="en">
<head><meta charset="UTF-8" /><meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>Windows Server 2025 GUI Simulation - Cyberrange</title>
<style>
  :root { --win-bg: #0a0a0a; --win-dark: #1a1a1a; --win-darker: #000000; --win-light: #ffffff; --win-gray: #808080; --win-blue: #0078d4; --win-text: #e0e0e0; }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: var(--win-bg); color: var(--win-light); min-height: 100vh; overflow: hidden; }
  .desktop { display: grid; grid-template-areas: "desktop" "taskbar"; grid-template-rows: 1fr auto; height: 100vh; }
  .desktop-icons { grid-area: desktop; padding: 20px; display: grid; grid-template-columns: repeat(auto-fill, 80px); gap: 20px; align-content: start; }
  .icon { width: 80px; text-align: center; cursor: pointer; }
  .icon img { width: 48px; height: 48px; margin-bottom: 4px; }
  .icon span { font-size: 11px; color: var(--win-text); background: var(--win-bg); padding: 2px; display: block; }
  .window { position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); width: 600px; height: 400px; background: var(--win-dark); border: 1px solid var(--win-gray); border-radius: 4px; box-shadow: 0 0 20px rgba(0, 120, 212, 0.3); display: none; }
  .window.active { display: block; }
  .window-header { background: linear-gradient(90deg, var(--win-blue), #005a9e); padding: 6px 10px; display: flex; align-items: center; justify-content: space-between; cursor: move; }
  .window-title { font-size: 12px; color: var(--win-light); font-weight: bold; }
  .window-controls { display: flex; gap: 4px; }
  .window-control { width: 24px; height: 18px; display: flex; align-items: center; justify-content: center; font-size: 10px; font-weight: bold; color: var(--win-light); cursor: pointer; }
  .window-control.close { background: #ff5f56; }
  .window-control.min { background: #ffbd2e; }
  .window-control.max { background: #2dca30; }
  .window-content { padding: 10px; height: calc(100% - 28px); overflow: auto; }
  .taskbar { grid-area: taskbar; background: #000000; border-top: 2px solid #404040; padding: 4px; display: flex; align-items: center; gap: 10px; }
  .start-button { background: var(--win-dark); border: 2px solid; border-color: #404040 #ffffff #ffffff #404040; padding: 4px 8px; font-size: 12px; color: var(--win-light); cursor: pointer; }
  .taskbar-item { padding: 4px 8px; font-size: 12px; color: var(--win-text); cursor: pointer; }
  .taskbar-item:hover { background: rgba(255, 255, 255, 0.1); }
  .server-info { background: var(--win-dark); border: 1px solid var(--win-gray); padding: 15px; font-family: Consolas, monospace; font-size: 12px; line-height: 1.5; }
  .server-info h3 { color: var(--win-blue); margin-bottom: 10px; }
  .event-viewer { background: var(--win-dark); border: 1px solid var(--win-gray); padding: 10px; }
  .event-viewer table { width: 100%; border-collapse: collapse; font-size: 11px; }
  .event-viewer th { background: var(--win-blue); color: var(--win-light); padding: 4px; text-align: left; }
  .event-viewer td { padding: 3px; border-bottom: 1px solid var(--win-gray); }
  .event-viewer tr:nth-child(even) { background: rgba(255, 255, 255, 0.05); }
  .command-prompt { background: var(--win-dark); border: 1px solid var(--win-gray); padding: 10px; font-family: Consolas, monospace; font-size: 12px; }
  .command-prompt input { background: transparent; border: none; color: var(--win-light); font-family: Consolas, monospace; font-size: 12px; width: 100%; margin-top: 5px; outline: none; }
  .command-prompt input:focus { outline: 1px solid var(--win-blue); }
  .command-output { color: var(--win-text); margin-top: 5px; white-space: pre-wrap; }
</style>
</head><body>
<div class="desktop">
  <div class="desktop-icons">
    <div class="icon" onclick="showWindow('server-info')">
      <div style="width: 48px; height: 48px; background: #0078d4; border-radius: 4px; display: flex; align-items: center; justify-content: center; color: white; font-weight: bold; font-size: 10px;">SRV</div>
      <span>Server Manager</span>
    </div>
    <div class="icon" onclick="showWindow('event-viewer')">
      <div style="width: 48px; height: 48px; background: #0078d4; border-radius: 4px; display: flex; align-items: center; justify-content: center; color: white; font-weight: bold; font-size: 10px;">EVT</div>
      <span>Event Viewer</span>
    </div>
    <div class="icon" onclick="showWindow('powershell')">
      <div style="width: 48px; height: 48px; background: #0078d4; border-radius: 4px; display: flex; align-items: center; justify-content: center; color: white; font-weight: bold; font-size: 10px;">PS</div>
      <span>PowerShell</span>
    </div>
    <div class="icon" onclick="showWindow('services')">
      <div style="width: 48px; height: 48px; background: #0078d4; border-radius: 4px; display: flex; align-items: center; justify-content: center; color: white; font-weight: bold; font-size: 10px;">SVC</div>
      <span>Services</span>
    </div>
  </div>
  <div class="taskbar">
    <div class="start-button" onclick="alert('Windows Start Menu - Cyberrange Simulation. Available: Server Manager, Event Viewer, PowerShell, Services')">Windows</div>
    <div class="taskbar-item" onclick="showWindow('powershell')">PowerShell - Terminal</div>
    <div style="margin-left: auto; padding: 0 10px; font-size: 11px; color: var(--win-text);">Windows Server 2025 &bull; ${new Date().toLocaleTimeString()}</div>
  </div>
  <div id="server-info-window" class="window">
    <div class="window-header"><span class="window-title">Server Manager - WIN-SRV-2025-01</span>
      <div class="window-controls"><div class="window-control min">_</div><div class="window-control max">□</div><div class="window-control close" onclick="hideWindow('server-info')">X</div></div>
    </div>
    <div class="window-content">
      <div class="server-info">
        <h3>Windows Server 2025 Standard</h3>
        <p><strong>Computer Name:</strong> WIN-SRV-2025-01</p>
        <p><strong>Domain:</strong> CYBERRANGE.local</p>
        <p><strong>IP Address:</strong> 192.168.1.10</p>
        <p><strong>Running Services:</strong> 45</p>
        <p><strong>Active Connections:</strong> 12</p>
      </div>
    </div>
  </div>
  <div id="event-viewer-window" class="window">
    <div class="window-header"><span class="window-title">Event Viewer - Security Log</span>
      <div class="window-controls"><div class="window-control min">_</div><div class="window-control max">□</div><div class="window-control close" onclick="hideWindow('event-viewer')">X</div></div>
    </div>
    <div class="window-content">
      <div class="event-viewer">
        <p style="color: #ff5f56; font-weight: bold;">[ALERT] Multiple failed login attempts detected - Possible brute force attack from 203.0.113.45!</p>
        <table><thead><tr><th>Time</th><th>Event ID</th><th>Message</th></tr></thead><tbody>
          <tr><td>2026-09-23 14:46:01</td><td>4625</td><td>Failed login from 203.0.113.45</td></tr>
          <tr><td>2026-09-23 14:46:02</td><td>4625</td><td>Failed login from 203.0.113.45</td></tr>
          <tr><td>2026-09-23 14:46:03</td><td>4625</td><td>Failed login from 203.0.113.45</td></tr>
        </tbody></table>
      </div>
    </div>
  </div>
  <div id="powershell-window" class="window">
    <div class="window-header"><span class="window-title">Windows PowerShell</span>
      <div class="window-controls"><div class="window-control min">_</div><div class="window-control max">□</div><div class="window-control close" onclick="hideWindow('powershell')">X</div></div>
    </div>
    <div class="window-content">
      <div class="command-prompt">
        <p>PS C:\\Users\\blueteam-user></p>
        <div id="ps-output" class="command-output"></div>
        <input type="text" id="ps-input" placeholder="Type command..." />
      </div>
    </div>
  </div>
  <div id="services-window" class="window">
    <div class="window-header"><span class="window-title">Services</span>
      <div class="window-controls"><div class="window-control min">_</div><div class="window-control max">□</div><div class="window-control close" onclick="hideWindow('services')">X</div></div>
    </div>
    <div class="window-content">
      <table style="width:100%;border-collapse:collapse;font-size:11px;">
        <thead><tr><th style="background:#0078d4;color:white;padding:4px;text-align:left;">Name</th><th style="background:#0078d4;color:white;padding:4px;text-align:left;">Status</th></tr></thead>
        <tbody>
          <tr><td>WinRM</td><td>Running</td></tr>
          <tr><td>lanmanserver</td><td>Running</td></tr>
          <tr><td>RdpSvc</td><td>Running</td></tr>
          <tr><td>EventLog</td><td>Running</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</div>
<script>
function showWindow(id) { document.querySelectorAll('.window').forEach(w=>w.classList.remove('active')); document.getElementById(id+'-window')?.classList.add('active'); if(id==='powershell')document.getElementById('ps-input')?.focus(); }
function hideWindow(id) { document.getElementById(id+'-window')?.classList.remove('active'); }
const cmds = { whoami:'CYBERRANGE\\\\blueteam-user', hostname:'WIN-SRV-2025-01', 'Get-Process':'Processes running', baseline:'=== BASELINE ESTABLISHED ===\nWindows Server 2025', 'start-attack':'=== ATTACK STARTED ===\nRDP Brute Force detected' };
document.getElementById('ps-input')?.addEventListener('keydown',e=>{ if(e.key!=='Enter')return; const i=document.getElementById('ps-input'),o=document.getElementById('ps-output'),c=i&&i.value.trim(); if(!c||!o)return; const cmd=document.createElement('p'); cmd.textContent='> '+c; const out=document.createElement('p'); out.textContent=cmds[c]||'Unknown command'; o.appendChild(cmd); o.appendChild(out); i.value=''; o.scrollTop=o.scrollHeight; });
</script>
</body></html>`;
        return new Response(winGuiHtml, {
          headers: { 'Content-Type': 'text/html;charset=UTF-8' },
        });
      }
      
      return new Response('Resource not found: ' + resourceName + '\nAvailable resources: cyberforce101.pdf.txt, powershell-reference.txt, windows-server-2025-gui.html', {
        headers: { 'Content-Type': 'text/plain' },
        status: 404,
      });
    }

    // 404
    return new Response('Not Found', { status: 404 });
  },
};
