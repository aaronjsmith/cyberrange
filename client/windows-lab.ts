import WinBox from 'winbox/src/js/winbox.js';
import winboxCss from 'winbox/dist/css/winbox.min.css?inline';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import xtermCss from '@xterm/xterm/css/xterm.css?inline';

function injectCss(css: string): void {
  const style = document.createElement('style');
  style.textContent = css;
  document.head.appendChild(style);
}

injectCss(winboxCss);
injectCss(xtermCss);

import { normalizeCommand } from './lab-session';
import {
  SECURITY_EVENTS_ATTACK,
  SECURITY_EVENTS_QUIET,
  lookupPowerShell,
} from './scenario/powershell';

interface DesktopState {
  attackActive: boolean;
  baselineEstablished: boolean;
  history: string[];
}

function detectBase(): string {
  const path = location.pathname;
  if (path === '/range' || path.startsWith('/range/')) return '/range';
  return '';
}

function clock(): string {
  return new Date().toLocaleTimeString();
}

function renderEventTable(attackActive: boolean): string {
  const rows = attackActive ? SECURITY_EVENTS_ATTACK : SECURITY_EVENTS_QUIET;
  return `
    <div class="evt-wrap">
      <h3>Windows Logs → Security</h3>
      <table>
        <thead><tr><th>Time</th><th>Id</th><th>Level</th><th>Message</th></tr></thead>
        <tbody>
          ${rows
            .map(
              (r) =>
                `<tr class="${r.level === 'Failure' ? 'fail' : ''}"><td>${r.time}</td><td>${r.id}</td><td>${r.level}</td><td>${r.message}</td></tr>`,
            )
            .join('')}
        </tbody>
      </table>
    </div>`;
}

function serverManagerHtml(): string {
  return `
    <div class="srv-wrap">
      <h3>Windows Server 2025 Standard</h3>
      <p><strong>Computer Name:</strong> WIN-SRV-2025-01</p>
      <p><strong>Domain:</strong> CYBERRANGE.local</p>
      <p><strong>OS:</strong> Windows Server 2025 Datacenter</p>
      <p><strong>Roles:</strong> Remote Desktop Services, File Services</p>
      <p><strong>Listening:</strong> 3389 (RDP), 445 (SMB), 5985 (WinRM)</p>
    </div>`;
}

function servicesHtml(): string {
  return `
    <div class="srv-wrap">
      <h3>Services</h3>
      <ul>
        <li>Running — EventLog (Windows Event Log)</li>
        <li>Running — TermService (Remote Desktop Services)</li>
        <li>Running — WinRM</li>
        <li>Running — wuauserv (Windows Update)</li>
      </ul>
    </div>`;
}

function mountPowerShell(container: HTMLElement, state: DesktopState, onState: () => void): void {
  const term = new Terminal({
    cursorBlink: true,
    fontFamily: 'Consolas, monospace',
    fontSize: 13,
    theme: { background: '#012456', foreground: '#f3f3f3', cursor: '#f3f3f3' },
  });
  const fit = new FitAddon();
  term.loadAddon(fit);
  term.open(container);
  fit.fit();

  let line = '';
  const prompt = 'PS C:\\Users\\blueteam-user> ';

  const showPrompt = () => term.write(`\r\n${prompt}`);
  term.writeln('Windows PowerShell — Cyberrange simulation');
  term.writeln('Type help for commands. Use baseline / start-attack / stop-attack.');
  showPrompt();

  const run = (raw: string) => {
    const cmd = normalizeCommand(raw);
    if (!cmd) {
      showPrompt();
      return;
    }
    state.history.push(cmd);

    if (cmd === 'Clear-Host' || cmd === 'cls' || cmd === 'clear') {
      term.clear();
      showPrompt();
      return;
    }

    if (cmd === 'baseline') {
      state.baselineEstablished = true;
      term.writeln(lookupPowerShell('baseline', false) || '');
      onState();
      showPrompt();
      return;
    }
    if (cmd === 'start-attack') {
      if (!state.baselineEstablished) {
        term.writeln('Establish a baseline first (type: baseline).');
        showPrompt();
        return;
      }
      state.attackActive = true;
      term.writeln(lookupPowerShell('start-attack', true) || '');
      onState();
      showPrompt();
      return;
    }
    if (cmd === 'stop-attack') {
      state.attackActive = false;
      term.writeln(lookupPowerShell('stop-attack', false) || '');
      onState();
      showPrompt();
      return;
    }

    const out = lookupPowerShell(cmd, state.attackActive);
    if (out == null) {
      term.writeln(
        `Command not recognized in this simulation: ${cmd}\nType help for available commands.`,
      );
    } else {
      for (const row of out.split('\n')) term.writeln(row);
    }
    showPrompt();
  };

  term.onData((data) => {
    if (data === '\r') {
      term.write('\r\n');
      const current = line;
      line = '';
      run(current);
      return;
    }
    if (data === '\u007f') {
      if (line.length) {
        line = line.slice(0, -1);
        term.write('\b \b');
      }
      return;
    }
    if (data >= ' ' || data === '\t') {
      line += data;
      term.write(data);
    }
  });

  window.addEventListener('resize', () => fit.fit());
}

function main(): void {
  const base = detectBase();
  const root = document.getElementById('desktop-root');
  if (!root) throw new Error('#desktop-root missing');

  const state: DesktopState = {
    attackActive: false,
    baselineEstablished: false,
    history: [],
  };

  root.innerHTML = `
    <div class="desk">
      <div class="desk-icons">
        <button type="button" data-open="server" class="desk-icon"><span class="ico">SRV</span><span>Server Manager</span></button>
        <button type="button" data-open="events" class="desk-icon"><span class="ico">EVT</span><span>Event Viewer</span></button>
        <button type="button" data-open="services" class="desk-icon"><span class="ico">SVC</span><span>Services</span></button>
        <button type="button" data-open="ps" class="desk-icon"><span class="ico">PS</span><span>PowerShell</span></button>
      </div>
      <div class="status-pill" id="desk-status">Establish baseline in PowerShell</div>
      <div class="taskbar">
        <button type="button" class="start" id="start-btn">Start</button>
        <button type="button" data-open="ps" class="tb">PowerShell</button>
        <button type="button" data-open="events" class="tb">Event Viewer</button>
        <a class="tb link" href="${base}/labs/windows-server-2025">← Back to lab</a>
        <span class="clock" id="clock">${clock()}</span>
      </div>
    </div>
  `;

  const style = document.createElement('style');
  style.textContent = `
    html, body { margin: 0; height: 100%; overflow: hidden; font-family: "Segoe UI", sans-serif; }
    #desktop-root, .desk { height: 100%; }
    .desk {
      display: grid; grid-template-rows: 1fr auto; height: 100%;
      background: linear-gradient(160deg, #0b1c33 0%, #123a5c 45%, #0a1524 100%);
      color: #e8eef6;
    }
    .desk-icons { padding: 1.25rem; display: flex; flex-wrap: wrap; gap: 1rem; align-content: start; }
    .desk-icon {
      width: 88px; background: transparent; border: 0; color: inherit; cursor: pointer;
      display: flex; flex-direction: column; align-items: center; gap: .35rem; font-size: .75rem;
    }
    .desk-icon .ico {
      width: 48px; height: 48px; border-radius: 8px; background: #0078d4;
      display: grid; place-items: center; font-weight: 700; font-size: .7rem;
      box-shadow: 0 8px 20px rgba(0,0,0,.35);
    }
    .status-pill {
      position: absolute; top: 1rem; right: 1rem; padding: .45rem .75rem;
      border-radius: 999px; background: rgba(0,0,0,.45); border: 1px solid rgba(255,255,255,.2);
      font-size: .78rem;
    }
    .taskbar {
      display: flex; align-items: center; gap: .5rem; padding: .35rem .6rem;
      background: rgba(0,0,0,.82); border-top: 1px solid rgba(255,255,255,.12);
    }
    .start, .tb {
      background: #1f1f1f; color: #eee; border: 1px solid #444; padding: .35rem .65rem;
      cursor: pointer; font: inherit; text-decoration: none;
    }
    .start { background: #0078d4; border-color: #0078d4; }
    .clock { margin-left: auto; font-size: .8rem; opacity: .85; }
    .srv-wrap, .evt-wrap { padding: .85rem 1rem; color: #1a1a1a; font-size: .9rem; }
    .evt-wrap table { width: 100%; border-collapse: collapse; font-size: .78rem; }
    .evt-wrap th, .evt-wrap td { border-bottom: 1px solid #ddd; padding: .35rem; text-align: left; }
    .evt-wrap tr.fail td { color: #a61f24; font-weight: 600; }
    .ps-term { height: 100%; background: #012456; }
  `;
  document.head.appendChild(style);

  let eventBox: WinBox | null = null;

  const refreshStatus = () => {
    const el = document.getElementById('desk-status');
    if (!el) return;
    if (state.attackActive) el.textContent = 'ATTACK ACTIVE — check Event Viewer';
    else if (state.baselineEstablished) el.textContent = 'BASELINE OK';
    else el.textContent = 'Establish baseline in PowerShell';
    if (eventBox) {
      const mount = eventBox.body.querySelector('.evt-host') as HTMLElement | null;
      if (mount) mount.innerHTML = renderEventTable(state.attackActive);
    }
  };

  const openWindow = (kind: string) => {
    if (kind === 'server') {
      new WinBox({
        title: 'Server Manager - WIN-SRV-2025-01',
        width: '560px',
        height: '360px',
        x: 'center',
        y: 'center',
        background: '#0078d4',
        html: serverManagerHtml(),
      });
      return;
    }
    if (kind === 'services') {
      new WinBox({
        title: 'Services',
        width: '480px',
        height: '320px',
        x: 80,
        y: 80,
        background: '#0078d4',
        html: servicesHtml(),
      });
      return;
    }
    if (kind === 'events') {
      eventBox = new WinBox({
        title: 'Event Viewer',
        width: '720px',
        height: '420px',
        x: 'center',
        y: 60,
        background: '#0078d4',
        html: `<div class="evt-host">${renderEventTable(state.attackActive)}</div>`,
      });
      return;
    }
    if (kind === 'ps') {
      const box = new WinBox({
        title: 'Administrator: Windows PowerShell',
        width: '720px',
        height: '440px',
        x: 'center',
        y: 'center',
        background: '#012456',
        class: ['no-full'],
      });
      const host = document.createElement('div');
      host.className = 'ps-term';
      host.style.height = '100%';
      box.mount(host);
      mountPowerShell(host, state, refreshStatus);
    }
  };

  root.querySelectorAll('[data-open]').forEach((el) => {
    el.addEventListener('click', () => openWindow((el as HTMLElement).dataset.open || ''));
  });

  document.getElementById('start-btn')?.addEventListener('click', () => {
    openWindow('ps');
  });

  setInterval(() => {
    const el = document.getElementById('clock');
    if (el) el.textContent = clock();
  }, 1000);

  refreshStatus();
  openWindow('ps');
}

try {
  main();
} catch (err) {
  const root = document.getElementById('desktop-root') || document.body;
  const msg = err instanceof Error ? err.message : String(err);
  root.innerHTML = `<pre style="padding:1rem;color:#fff;background:#5a1a1a;white-space:pre-wrap">Windows desktop failed to load:\n${msg}</pre>`;
  console.error(err);
}
