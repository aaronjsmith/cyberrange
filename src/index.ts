/**
 * Cyberrange Cloudflare Worker
 * Blue Team Training Platform with Simulated Shell
 * Supports bash (Linux) and PowerShell (Windows Server 2025)
 */

export interface Env {
  CYBERRANGE_ENV?: string;
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

// Helper to escape HTML
const esc = (t: string): string => {
  return t
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
};

// Command definitions - will be set per-shell-type in handler
const COMMANDS: Record<ShellType, Record<string, { output: string; baseline?: boolean; triggersAttack?: boolean }>> = {
  bash: {
    'whoami': { output: 'blueteam-user' },
    'hostname': { output: 'cyberrange-training-01' },
    'date': { output: new Date().toLocaleString() },
    'pwd': { output: '/home/blueteam-user' },
    'ps aux': { output: 'USER   PID %CPU %MEM   VSZ   RSS TTY   STAT\nroot     1  0.0  0.1 16948 3120 ?     Ss\nsshd   123  0.0  0.2 54320 4560 ?     S\nblueteam 1234  0.0  0.3 34567 6789 pts/0 Ss', baseline: true },
    'netstat -tuln': { output: 'Proto Recv-Q Send-Q Local Address   Foreign Address  State\nTCP    0      0 0.0.0.0:22       0.0.0.0:*        LISTEN\nTCP    0      0 127.0.0.1:3306   0.0.0.0:*        LISTEN', baseline: true },
    'top': { output: 'Tasks: 123 total, 1 running. %Cpu(s): 2.3us. Mem: 3456MB used', baseline: true },
    'tail -n 20 /var/log/auth.log': { output: 'Sep 23 19:45 sshd[12345]: Accepted password for blueteam-user from 192.168.1.100\n[NORMAL] No failed attempts', baseline: true },
    'grep Failed /var/log/auth.log': { output: 'No failed logins' },
    'help': { output: 'Available: whoami, hostname, date, pwd, ps aux, netstat -tuln, top, tail -n 20 /var/log/auth.log, baseline, start-attack, shell-type bash|powershell, lab-info' },
    'lab-info': { output: 'BLUE TEAM LAB: Network Intrusion\nPhase 1: Run baseline commands\nPhase 2: Type baseline\nPhase 3: Type start-attack\nPhase 4: Detect and respond' },
    'baseline': { output: '=== BASELINE ESTABLISHED ===\nNormal: 123 processes, ports 22/3306 open\nBaseline saved\nNEXT: Type start-attack to begin', baseline: true },
    'start-attack': { output: '=== ATTACK STARTED ===\nBrute Force SSH from 203.0.113.45\nMonitor: tail -n 20 /var/log/auth.log\nMonitor: grep Failed /var/log/auth.log', triggersAttack: true },
    'shell-type bash': { output: 'Switched to bash shell. Use Linux commands.' },
    'shell-type powershell': { output: 'Switched to PowerShell shell. Use Windows commands.' },
    'grep Failed /var/log/auth.log attack': { output: 'Sep 23 19:46 sshd[54321]: Failed password for blueteam-user from 203.0.113.45\n[ALERT] Brute Force Attack from 203.0.113.45!' },
  },
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
    'help': { output: 'Available: whoami, hostname, Get-Date, pwd, Get-Process, Get-NetTCPConnection, Get-Service, Get-WinEvent, baseline, start-attack, shell-type bash|powershell, lab-info' },
    'lab-info': { output: 'BLUE TEAM LAB: Windows Server 2025\nPhase 1: Document system state\nPhase 2: Type baseline\nPhase 3: Type start-attack\nPhase 4: Detect and respond' },
    'baseline': { output: '=== BASELINE ESTABLISHED ===\nWindows Server 2025 Standard\nServices: 45 running\nPorts: 22, 80, 443, 3389\nBaseline saved\nNEXT: Type start-attack to begin', baseline: true },
    'start-attack': { output: '=== ATTACK STARTED ===\nRDP Brute Force from 203.0.113.45\nMonitor: Get-WinEvent -FilterHashtable @{LogName=\"Security\"}\nMonitor: Get-NetTCPConnection -State Established', triggersAttack: true },
    'shell-type bash': { output: 'Switched to bash shell. Use Linux commands.' },
    'shell-type powershell': { output: 'Switched to PowerShell shell. Use Windows commands.' },
    'Get-WinEvent -FilterHashtable @{LogName="Security"} attack': { output: 'TimeCreated           Id  Message\n9/23/2026 7:46:01  4625  Failed login from 203.0.113.45\n[ALERT] Brute Force detected!' },
  }
};

// Learning steps per shell type
const LEARNING_STEPS: Record<ShellType, string[]> = {
  bash: [
    'Run: hostname, whoami, date',
    'Run: ps aux to check processes',
    'Run: netstat -tuln to check ports',
    'Run: top to check resources',
    'Run: tail -n 20 /var/log/auth.log',
    'Type: baseline to document normal state',
    'Type: start-attack to begin simulation'
  ],
  powershell: [
    'Run: hostname, whoami, Get-Date',
    'Run: Get-Process to check processes',
    'Run: Get-NetTCPConnection -State Listen',
    'Run: Get-Service | Where-Object { $_.Status -eq "Running" }',
    'Run: Get-WinEvent -LogName Security -MaxEvents 5',
    'Type: baseline to document normal state',
    'Type: start-attack to begin simulation'
  ]
};

const getStepHint = (shellType: ShellType, step: number): string => {
  const hints = LEARNING_STEPS[shellType];
  return hints[Math.min(step, hints.length - 1)] || 'Complete all steps!';
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

const getShellPrompt = (shellType: ShellType): string => {
  if (shellType === 'powershell') {
    return 'PS C:\Users\blueteam-user>';
  }
  return 'blueteam@cyberrange:~$';
};

const getWelcomeMessage = (shellType: ShellType): string => {
  if (shellType === 'powershell') {
    return 'Windows Server 2025 PowerShell Terminal. Type help for commands.';
  }
  return 'Linux Terminal. Type help for commands.';
};

const labsIndexHTML = (): string => {
  const cards = LABS.map(l => {
    const c = { Beginner: '#4ade80', Intermediate: '#fbbf24', Advanced: '#f87171' }[l.difficulty];
    return `
<a href="/labs/${l.id}" class="panel" style="text-decoration:none;color:inherit">
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
<div><a href="/" class="btn">Dashboard</a></div></div>
<div class="container"><div class="main">
<a href="/" class="back">← Back</a>
<div class="panel"><p class="kicker">Blue Team</p><h2 class="pt">Available Labs</h2>
<p class="cap">Select a lab. Each includes learning mode with baseline → attack simulation.</p></div>
<div class="grid">${cards}</div>
<div class="panel" style="margin-top: 20px;">
  <p class="kicker">Resources</p>
  <h2 class="pt">Training Materials</h2>
  <ul class="list">
    <li class="li"><a href="/resources/cyberforce101.pdf" class="lil" style="color: var(--accent);">Cyber Force 101 - Course PDF</a></li>
    <li class="li"><p class="lil">Windows Server 2025 GUI Simulation</p></li>
    <li class="li"><p class="lil">PowerShell Command Reference</p></li>
    <li class="li"><p class="lil">Blue Team Playbooks</p></li>
  </ul>
</div>
</div></div>
</body></html>`;
};

const shellHTML = (lab: Lab, state: ShellState): string => {
  const { commandHistory, attackActive, baselineEstablished, shellType } = state;
  const step = state.currentStep;
  const totalSteps = LEARNING_STEPS[shellType].length;
  const progress = Math.round(((step + 1) / totalSteps) * 100);
  
  const prompt = getShellPrompt(shellType);
  const welcome = getWelcomeMessage(shellType);
  
  const history = commandHistory.length > 0
    ? commandHistory.map(c => 
        `<div><span style="color:var(--accent)">${prompt}</span> <span style="color:#fff">${esc(c)}</span></div>`
      ).join('')
    : `<div style="color:#888">${welcome}</div>`;

  const modeTabs = (m: ShellMode) => ['learning','free'].map(x =>
    `<span class="tab" onclick="setMode('${x}')" style="padding:6px 12px;border-radius:999px;font-size:11px;font-weight:600;cursor:pointer;border:1px solid var(--border);${x===m?'background:var(--accent);color:#fff': 'background:var(--bg3);color:var(--text2)'}">${x}</span>`
  ).join('');

  const shellTabs = (s: ShellType) => ['bash','powershell'].map(x =>
    `<span class="tab" onclick="setShellType('${x}')" style="padding:6px 12px;border-radius:999px;font-size:11px;font-weight:600;cursor:pointer;border:1px solid var(--border);${x===s?'background:var(--accent);color:#fff': 'background:var(--bg3);color:var(--text2)'}">${x}</span>`
  ).join('');

  const steps = LEARNING_STEPS[shellType];

  return `<!doctype html>
<html><head><meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>${lab.title}</title><style>
${baseStyles}
.lab { display: grid; grid-template-columns: 280px 1fr; gap: 20px; }
.sidebar { background: var(--bg); border: 1px solid var(--border); border-radius: var(--r); padding: 16px; }
.pb { height: 4px; background: var(--bg3); border-radius: 2px; overflow: hidden; margin-bottom: 8px; }
.pf { height: 100%; background: linear-gradient(90deg,var(--accent),var(--good)); width: ${progress}%; transition: width .3s; }
.cs { background: var(--bg2); border: 1px solid var(--border); border-radius: var(--r2); padding: 12px; margin-top: 12px; }
.cst { font-size: 13px; font-weight: 700; color: var(--accent); margin: 0 0 4px; }
.csi { font-size: 12px; color: var(--text2); line-height: 1.45; margin: 0; }
.shell { background: var(--bg); border: 1px solid var(--border); border-radius: var(--r); padding: 16px; display: flex; flex-direction: column; min-height: 500px; }
.sh { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; padding-bottom: 12px; border-bottom: 1px solid var(--border); flex-wrap: wrap; gap: 8px; }
.st2 { font-size: 14px; font-weight: 600; color: var(--text); }
.tab { transition: all .12s; }
.tab:hover { border-color: var(--text3); }
.out { flex: 1; background: #0a0a0a; border: 1px solid var(--border); border-radius: var(--r2); padding: 12px; font-family: Consolas,monospace; font-size: 12px; line-height: 1.5; color: #d4d4d4; overflow-y: auto; min-height: 300px; white-space: pre-wrap; }
.ipc { display: flex; gap: 8px; margin-top: 12px; }
.pr { color: var(--accent); font-family: Consolas,monospace; font-size: 12px; white-space: nowrap; }
.in { background: transparent; border: none; padding: 0; margin: 0; font-family: Consolas,monospace; font-size: 12px; color: var(--text); outline: none; display: inline; }
.in:focus { outline: none; }
.input-line { display: flex; align-items: center; gap: 8px; }
.sb { display: inline-flex; align-items: center; gap: 6px; padding: 4px 10px; border-radius: 999px; font-size: 11px; font-weight: 600; }
.sb-b { background: rgba(74,222,128,.15); color: var(--good); border: 1px solid rgba(74,222,128,.3); }
.sb-a { background: rgba(248,113,113,.15); color: var(--bad); border: 1px solid rgba(248,113,113,.3); animation: p 1s infinite; }
@keyframes p { 0%,100%{opacity:1}50%{opacity:.7} }
.ab { background: var(--bg2); border: 1px solid var(--border); border-radius: var(--r2); color: var(--text2); padding: 8px 12px; font-size: 12px; cursor: pointer; transition: all .12s; margin-top: 12px; display: inline-flex; align-items: center; gap: 6px; }
.ab:hover { border-color: var(--text3); color: var(--text); }
</style>
</head><body>
<div class="bar"><div class="brand"><div><h1 class="t">${lab.title}</h1><p class="st">${lab.category} • ${lab.difficulty}</p></div></div>
<div><a href="/labs" class="btn">All Labs</a></div></div>
<div class="container"><div class="main">
<a href="/labs" class="back">← All Labs</a>
<div class="lab">
<div class="sidebar">
<p class="kicker">Learning Mode</p><h3 style="margin:6px 0 2px;font-size:14px;font-weight:700">Progress</h3>
<div style="margin-bottom:12px"><div class="pb"><div class="pf"></div></div>
<p style="font-size:11px;color:var(--text3)">Step ${step+1} of ${totalSteps}</p></div>
<div class="cs"><p class="cst">Step ${step+1}: ${steps[Math.min(step, steps.length - 1)]}</p>
<p class="csi">${getStepHint(shellType, step)}</p></div>
<div style="display:flex;gap:8px;margin-top:16px;flex-wrap:wrap">
${attackActive ? '<span class="sb sb-a">ATTACK ACTIVE</span>' : baselineEstablished ? '<span class="sb sb-b">BASELINE OK</span>' : '<span class="tag">Establish Baseline</span>'}
<span class="tag">${lab.difficulty}</span>
${lab.tags.map(t=>`<span class="tag">${t}</span>`).join('')}
</div>
${step>0 ? '<button class="ab" onclick="prevStep()">← Previous</button>' : ''}
      <button class="ab" onclick="resetSession()" style="margin-top: 8px;">🔄 Reset Session</button>
</div>
<div class="shell">
<div class="sh"><span class="st2">Terminal (${shellType})</span><div style="display:flex;gap:8px;">${modeTabs(state.mode)}</div><div style="margin-top:8px;">${shellTabs(shellType)}</div></div>
<div class="out" id="out">${history}<span class="input-line"><span class="pr" id="prompt">${prompt}</span><span class="in" id="in" contenteditable="true" autocomplete="off"></span></span></div>
</div></div></div></div>
<script>
const lid='${lab.id}';
let i=document.getElementById('in');
const o=document.getElementById('out');
const pr=document.getElementById('prompt');

// Focus input when clicking anywhere in the shell output
if(o) o.addEventListener('click', () => { 
  const activeInput = o.querySelector('.in');
  if(activeInput) { 
    activeInput.focus();
    const range = document.createRange();
    const sel = window.getSelection();
    range.selectNodeContents(activeInput);
    range.collapse(false);
    sel.removeAllRanges();
    sel.addRange(range);
  }
});

// Use event delegation - listen for keydown on .out, but only handle .in elements
if(o) {
  o.addEventListener('keydown', function(e) {
    const target = e.target;
    // Only handle if the keydown is on a .in span
    if(target && target.classList && target.classList.contains('in')) {
      if(e.key=='ArrowUp'&&h[0]){
        e.preventDefault();
        target.textContent=h[h.length-1];
        const range = document.createRange();
        const sel = window.getSelection();
        range.selectNodeContents(target);
        range.collapse(false);
        sel.removeAllRanges();
        sel.addRange(range);
      }
      if(e.key=='Enter'){
        e.preventDefault();
        // Store reference to current input before exec
        const currentInput = target;
        exec(e, currentInput);
      }
    }
  });
}

// Initial focus
if(i) i.focus();

let h=${JSON.stringify(commandHistory)};
let s=${step};
let m='${state.mode}';
let st='${shellType}';
let a=${attackActive};
let b=${baselineEstablished};

// Load session from localStorage
const stored = localStorage.getItem('cyberrange-session-' + lid);
if(stored) {
  try {
    const storedData = JSON.parse(stored);
    if(storedData.commandHistory) h = storedData.commandHistory;
    if(storedData.step !== undefined) s = storedData.step;
    if(storedData.mode) m = storedData.mode;
    if(storedData.shellType) st = storedData.shellType;
    if(storedData.attackActive !== undefined) a = storedData.attackActive;
    if(storedData.baselineEstablished !== undefined) b = storedData.baselineEstablished;
  } catch(e) {}
}

// Save session to localStorage
function saveSession() {
  const data = { commandHistory: h, step: s, mode: m, shellType: st, attackActive: a, baselineEstablished: b };
  localStorage.setItem('cyberrange-session-' + lid, JSON.stringify(data));
}

// Reset session
function resetSession() {
  if(confirm('Reset this lab session? All command history and progress will be cleared.')) {
    localStorage.removeItem('cyberrange-session-' + lid);
    window.location.reload();
  }
}


async function exec(e, currentInput){
  e.preventDefault();
  const c=currentInput.textContent.trim();
  if(!c)return;
  
  // Move cursor to end of input so user can see what they typed
  const range = document.createRange();
  const sel = window.getSelection();
  range.selectNodeContents(currentInput);
  range.collapse(false);
  sel.removeAllRanges();
  sel.addRange(range);
  
  try{
    const r=await fetch('/api/labs/'+lid+'/command',{
      method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({command:c,currentStep:s,mode:m,shellType:st,attackActive:a,baselineEstablished:b})
    });
    const d=await r.json();
    
    // Add output
    if(d.output){const e=document.createElement('div');e.textContent=d.output;o.appendChild(e);}
    if(d.error){const e=document.createElement('div');e.innerHTML='<span style="color:#ff5555">'+esc(d.error)+'</span>';o.appendChild(e);}
    
    // Create new input line for next command
    const newLine=document.createElement('span');
    newLine.className='input-line';
    newLine.innerHTML='<span class="pr">'+pr.textContent+'</span><span class="in" contenteditable="true"></span>';
    o.appendChild(newLine);
    
    // Update i to the new input
    i=newLine.querySelector('.in');
    
    // Update h (command history)
    h=d.commandHistory||[...h,c];
    s=d.currentStep!==undefined?d.currentStep:s;
    m=d.mode||m;
    st=d.shellType||st;
    a=d.attackActive!==undefined?d.attackActive:a;
    b=d.baselineEstablished!==undefined?d.baselineEstablished:b;
    saveSession();
    
    o.scrollTop=o.scrollHeight;
    if(d.stepChanged!==undefined&&d.stepChanged)window.location.reload();
    else if(st!==pr.textContent.split(' ')[0])window.location.reload();
    
    i.focus();
  }catch(err){const e=document.createElement('div');e.innerHTML='<span style="color:#ff5555">Error</span>';o.appendChild(e);}
}
function setMode(x){saveSession();window.location.href='/labs/'+lid+'?mode='+x+'&step='+s+'&shellType='+st+'&attack='+a+'&baseline='+b;}
function setShellType(x){saveSession();window.location.href='/labs/'+lid+'?mode='+m+'&step='+s+'&shellType='+x+'&attack='+a+'&baseline='+b;}
function prevStep(){saveSession();window.location.href='/labs/'+lid+'?mode='+m+'&step='+Math.max(0,s-1)+'&shellType='+st+'&attack='+a+'&baseline='+b;}
</script>
</body></html>`;
};

const DASHBOARD_HTML = `<!doctype html>
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
    <div><a href="/labs" class="btn">Labs</a></div>
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
          <a href="/labs" class="btn" style="margin-top: 12px; display: inline-block;">Browse Labs</a>
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
          <li class="li"><a href="/resources/cyberforce101.pdf" class="lil" style="color: var(--accent);">Cyber Force 101 - Course PDF</a></li>
          <li class="li"><p class="lil">Windows Server 2025 GUI Simulation</p></li>
          <li class="li"><p class="lil">PowerShell Command Reference</p></li>
          <li class="li"><p class="lil">Blue Team Playbooks</p></li>
        </ul>
      </div>
    </div>
  </div>
</body>
</html>`;

// ============================================
// Request Handler
// ============================================

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    // Dashboard
    if (path === '/') {
      return new Response(DASHBOARD_HTML, {
        headers: { 'Content-Type': 'text/html;charset=UTF-8' },
      });
    }

    // Labs index
    if (path === '/labs') {
      return new Response(labsIndexHTML(), {
        headers: { 'Content-Type': 'text/html;charset=UTF-8' },
      });
    }

    // Lab shell
    const labMatch = path.match(/^\/labs\/([a-z-]+)$/);
    if (labMatch) {
      const labId = labMatch[1];
      const lab = LABS.find(l => l.id === labId);
      if (!lab) {
        return new Response('Lab not found', { status: 404 });
      }

      // Parse query params
      const params = new URLSearchParams(url.search);
      const mode = (params.get('mode') as ShellMode) || 'learning';
      const currentStep = parseInt(params.get('step') || '0');
      const shellType = (params.get('shellType') as ShellType) || 'bash';
      const attackActive = params.get('attack') === 'true';
      const baselineEstablished = params.get('baseline') === 'true';

      const state: ShellState = {
        commandHistory: [],
        currentStep,
        mode,
        shellType,
        attackActive,
        baselineEstablished,
      };

      return new Response(shellHTML(lab, state), {
        headers: { 'Content-Type': 'text/html;charset=UTF-8' },
      });
    }

    // API: Lab command execution
    const commandMatch = path.match(/^\/api\/labs\/([a-z-]+)\/command$/);
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
        const body = await request.json<{
          command?: string;
          currentStep?: number;
          mode?: ShellMode;
          shellType?: ShellType;
          attackActive?: boolean;
          baselineEstablished?: boolean;
        }>();
        const { command, currentStep, mode, shellType, attackActive, baselineEstablished } = body;

        if (!command) {
          return new Response(JSON.stringify({ error: 'No command provided' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' },
          });
        }

        const st: ShellType = shellType ?? 'bash';
        const m: ShellMode = mode ?? 'learning';

        let state: ShellState = {
          commandHistory: [],
          currentStep: currentStep ?? 0,
          mode: m,
          shellType: st,
          attackActive: attackActive ?? false,
          baselineEstablished: baselineEstablished ?? false,
        };

        // Process command
        const cmd = command.trim();
        let output: string | null = null;
        let error: string | null = null;
        let stepChanged = false;

        const commands = COMMANDS[st];

        // Handle special commands
        if (cmd === 'baseline') {
          output = commands['baseline'].output;
          state.baselineEstablished = true;
          if (m === 'learning' && state.currentStep < 5) {
            state.currentStep = 5;
            stepChanged = true;
          }
        } else if (cmd === 'start-attack') {
          if (state.baselineEstablished) {
            output = commands['start-attack'].output;
            state.attackActive = true;
            if (m === 'learning' && state.currentStep < 6) {
              state.currentStep = 6;
              stepChanged = true;
            }
          } else {
            error = 'Cannot start attack: Baseline not established. Type "baseline" first.';
          }
        } else if (cmd.startsWith('shell-type ')) {
          const newType = cmd.split(' ')[1];
          if (newType === 'bash' || newType === 'powershell') {
            state.shellType = newType as ShellType;
            output = `Shell switched to ${newType}. Use ${newType} commands.`;
          } else {
            error = `Unknown shell type: ${newType}. Use 'bash' or 'powershell'.`;
          }
        } else {
          // Regular commands
          const cmdKey = cmd in commands ? cmd : (state.attackActive ? `${cmd} attack` : cmd);
          
          if (cmdKey in commands) {
            output = commands[cmdKey].output;
          } else {
            error = `Command not found: ${cmd}. Type 'help' for available commands.`;
          }
        }

        // In learning mode, check if command matches expected action
        if (m === 'learning' && !stepChanged && output) {
          const expected = LEARNING_STEPS[st];
          if (state.currentStep < expected.length && cmd === expected[state.currentStep]) {
            state.currentStep = Math.min(state.currentStep + 1, expected.length - 1);
            stepChanged = true;
          }
        }

        // Update command history
        state.commandHistory = [...(state.commandHistory || []), cmd];

        return new Response(JSON.stringify({
          output,
          error,
          commandHistory: state.commandHistory,
          currentStep: state.currentStep,
          mode: state.mode,
          shellType: state.shellType,
          attackActive: state.attackActive,
          baselineEstablished: state.baselineEstablished,
          stepChanged,
        }), {
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
            health: '/health',
            labs: '/labs',
          },
        }),
        { headers: { 'Content-Type': 'application/json' } }
      );
    }

    // Serve resources
    if (path.startsWith('/resources/')) {
      const resourceName = path.split('/').pop();
      
      // Serve actual resource files
      if (resourceName === 'cyberforce101.pdf.txt') {
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
document.getElementById('ps-input')?.addEventListener('keydown',e=>{ if(e.key==='Enter'){ const i=document.getElementById('ps-input'),o=document.getElementById('ps-output'),c=i?.value.trim(); if(c&&i&&o){ o.innerHTML+='<p>> '+c+'</p>'; o.innerHTML+='<p>'+(cmds[c]||'Unknown command')+'</p>'; i.value=''; o.scrollTop=o.scrollHeight; } } });
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
