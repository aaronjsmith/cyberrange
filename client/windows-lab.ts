import w11Css from './vendor/w11css/style.css?inline';
import wallpaper from './vendor/w11css/images/bloom.jpg';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import xtermCss from '@xterm/xterm/css/xterm.css?inline';

import { normalizeCommand } from './lab-session';
import {
  SECURITY_EVENTS_ATTACK,
  SECURITY_EVENTS_QUIET,
  lookupPowerShell,
} from './scenario/powershell';

function detectBase(): string {
  const path = location.pathname;
  if (path === '/range' || path.startsWith('/range/')) return '/range';
  return '';
}

/** Vite emits /assets/… but Workers serve them under /emulation/assets/… (and /range when proxied). */
function emulationAsset(vitePath: string): string {
  const file = vitePath.replace(/^.*\//, '');
  return `${detectBase()}/emulation/assets/${file}`;
}

function injectCss(css: string): void {
  const style = document.createElement('style');
  style.textContent = css;
  document.head.appendChild(style);
}

const wallpaperUrl = emulationAsset(wallpaper);

injectCss(
  w11Css.replace(/url\(\s*\.?\/?images\/[^)]+\)/gi, `url(${wallpaperUrl})`),
);
injectCss(xtermCss);

interface DesktopState {
  attackActive: boolean;
  baselineEstablished: boolean;
  history: string[];
}

type WinKind = 'server' | 'events' | 'services' | 'ps';

function pad(n: number): string {
  return n < 10 ? `0${n}` : String(n);
}

function clockParts(): { time: string; date: string } {
  const d = new Date();
  return {
    time: `${pad(d.getHours())}:${pad(d.getMinutes())}`,
    date: `${pad(d.getDate())}/${pad(d.getMonth() + 1)}/${d.getFullYear()}`,
  };
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

const CLOSE_SVG = `<svg aria-hidden="true" viewBox="0 0 320 512"><path fill="currentColor" d="M310.6 361.4c12.5 12.5 12.5 32.75 0 45.25C304.4 412.9 296.2 416 288 416s-16.38-3.125-22.62-9.375L160 301.3L54.63 406.6C48.38 412.9 40.19 416 32 416S15.63 412.9 9.375 406.6c-12.5-12.5-12.5-32.75 0-45.25l105.4-105.4L9.375 150.6c-12.5-12.5-12.5-32.75 0-45.25s32.75-12.5 45.25 0L160 210.8l105.4-105.4c12.5-12.5 32.75-12.5 45.25 0s12.5 32.75 0 45.25l-105.4 105.4L310.6 361.4z"/></svg>`;
const MAX_SVG = `<svg aria-hidden="true" viewBox="0 0 448 512"><path fill="currentColor" d="M384 32H64C28.65 32 0 60.65 0 96v320c0 35.35 28.65 64 64 64h320c35.35 0 64-28.65 64-64V96C448 60.65 419.3 32 384 32zM400 416c0 8.822-7.178 16-16 16H64c-8.822 0-16-7.178-16-16V96c0-8.822 7.178-16 16-16h320c8.822 0 16 7.178 16 16V416z"/></svg>`;
const MIN_SVG = `<svg aria-hidden="true" viewBox="0 0 448 512"><path fill="currentColor" d="M400 288h-352c-17.69 0-32-14.32-32-32.01s14.31-31.99 32-31.99h352c17.69 0 32 14.3 32 31.99S417.7 288 400 288z"/></svg>`;
const WIN_LOGO = `<svg id="windows-logo" xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 48.745 48.747"><g fill="#0078d4"><rect y="0" width="23.105" height="23.105"/><rect x="25.64" y="0" width="23.105" height="23.105"/><rect y="25.642" width="23.105" height="23.105"/><rect x="25.64" y="25.642" width="23.105" height="23.105"/></g></svg>`;

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
  requestAnimationFrame(() => fit.fit());

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

  const { time, date } = clockParts();

  root.innerHTML = `
    <div class="w11-desk" id="w11-desk">
      <div class="desk-icons">
        <button type="button" class="desk-icon" data-open="server"><span class="ico">SRV</span><span>Server Manager</span></button>
        <button type="button" class="desk-icon" data-open="events"><span class="ico">EVT</span><span>Event Viewer</span></button>
        <button type="button" class="desk-icon" data-open="services"><span class="ico">SVC</span><span>Services</span></button>
        <button type="button" class="desk-icon" data-open="ps"><span class="ico">PS</span><span>PowerShell</span></button>
      </div>
      <div class="status-pill" id="desk-status">Establish baseline in PowerShell</div>
      <div id="window-layer"></div>
      <div id="w11-start-section">
        <div class="padding-start">
          <div class="app-container-header"><span>Pinned</span></div>
          <div id="second-app-container">
            <div data-open="ps"><span class="start-ico">PS</span><span>PowerShell</span></div>
            <div data-open="events"><span class="start-ico">EVT</span><span>Event Viewer</span></div>
            <div data-open="server"><span class="start-ico">SRV</span><span>Server Manager</span></div>
            <div data-open="services"><span class="start-ico">SVC</span><span>Services</span></div>
          </div>
        </div>
        <div id="footer-start-section">
          <div class="nome-utente-start-section"><span>blueteam-user</span></div>
          <a class="spegni-pc-start-section" href="${base}/labs/windows-server-2025">← Back to lab</a>
        </div>
      </div>
      <nav>
        <div id="nav-container">
          <div id="first-container">
            <div id="windows-div" title="Start">${WIN_LOGO}</div>
            <div data-open="ps" title="PowerShell"><span class="tb-label">PS</span></div>
            <div data-open="events" title="Event Viewer"><span class="tb-label">EVT</span></div>
          </div>
          <div id="second-container">
            <div id="sistema-data" title="Clock">
              <span id="orario-data">${time}</span>
              <span id="calendario-data">${date}</span>
            </div>
          </div>
        </div>
      </nav>
    </div>
  `;

  const style = document.createElement('style');
  style.textContent = `
    html, body { margin: 0; height: 100%; overflow: hidden; }
    #desktop-root, .w11-desk { height: 100%; width: 100%; position: relative; }
    body {
      display: block !important;
      background-image: url(${wallpaperUrl}) !important;
      background-repeat: no-repeat !important;
      background-position: center !important;
      background-size: cover !important;
      background-attachment: fixed !important;
    }
    #not-mobile-friendly { display: none !important; }
    .desk-icons {
      position: absolute; inset: 1.25rem auto auto 1.25rem; z-index: 2;
      display: flex; flex-direction: column; gap: .85rem;
    }
    .desk-icon {
      width: 88px; background: transparent; border: 0; color: #fff; cursor: pointer;
      display: flex; flex-direction: column; align-items: center; gap: .35rem; font-size: .72rem;
      text-shadow: 0 1px 3px rgba(0,0,0,.8);
    }
    .desk-icon .ico, .start-ico {
      width: 48px; height: 48px; border-radius: 10px; background: #0078d4;
      display: grid; place-items: center; font-weight: 700; font-size: .7rem;
      box-shadow: 0 8px 20px rgba(0,0,0,.35); color: #fff;
    }
    .start-ico { width: 2.5rem; height: 2.5rem; margin-bottom: .2rem; }
    .status-pill {
      position: absolute; top: 1rem; right: 1rem; z-index: 3; padding: .45rem .75rem;
      border-radius: 999px; background: rgba(0,0,0,.45); border: 1px solid rgba(255,255,255,.2);
      font-size: .78rem; color: #fff;
    }
    #window-layer { position: absolute; inset: 0 0 var(--nav-height) 0; z-index: 4; pointer-events: none; }
    #window-layer .windows-tab { pointer-events: auto; display: grid; z-index: 5; }
    .windows-tab .tab-body { height: calc(100% - 2em); overflow: auto; background: rgba(32,32,32,.92); color: #eee; }
    .windows-tab .tab-body.ps-body { background: #012456; overflow: hidden; }
    .ps-term { height: 100%; }
    .srv-wrap, .evt-wrap { padding: .85rem 1rem; font-size: .9rem; }
    .evt-wrap table { width: 100%; border-collapse: collapse; font-size: .78rem; }
    .evt-wrap th, .evt-wrap td { border-bottom: 1px solid #444; padding: .35rem; text-align: left; }
    .evt-wrap tr.fail td { color: #ff8a8a; font-weight: 600; }
    .tb-label { color: #fff; font-size: .7rem; font-weight: 700; }
    #w11-start-section {
      background: rgba(32, 32, 48, 0.72);
      z-index: 6;
    }
    #footer-start-section a { color: #fff; text-decoration: none; }
    .nome-tab { padding-left: .75rem; justify-self: start; font-size: .85rem; }
  `;
  document.head.appendChild(style);

  const layer = document.getElementById('window-layer')!;
  const startSection = document.getElementById('w11-start-section')!;
  let z = 10;
  let eventHost: HTMLElement | null = null;
  const openTabs = new Map<WinKind, HTMLElement>();

  const refreshStatus = () => {
    const el = document.getElementById('desk-status');
    if (!el) return;
    if (state.attackActive) el.textContent = 'ATTACK ACTIVE — check Event Viewer';
    else if (state.baselineEstablished) el.textContent = 'BASELINE OK';
    else el.textContent = 'Establish baseline in PowerShell';
    if (eventHost) eventHost.innerHTML = renderEventTable(state.attackActive);
  };

  const focusTab = (tab: HTMLElement) => {
    z += 1;
    tab.style.zIndex = String(z);
  };

  const openWindow = (kind: WinKind) => {
    startSection.classList.remove('on-visible-start');
    const existing = openTabs.get(kind);
    if (existing) {
      existing.style.display = 'grid';
      focusTab(existing);
      return;
    }

    const titles: Record<WinKind, string> = {
      server: 'Server Manager - WIN-SRV-2025-01',
      events: 'Event Viewer',
      services: 'Services',
      ps: 'Administrator: Windows PowerShell',
    };

    const tab = document.createElement('div');
    tab.className = 'windows-tab';
    tab.style.width = kind === 'ps' || kind === 'events' ? '720px' : '560px';
    tab.style.height = kind === 'ps' || kind === 'events' ? '440px' : '360px';
    tab.style.left = `${80 + openTabs.size * 28}px`;
    tab.style.top = `${48 + openTabs.size * 24}px`;
    tab.innerHTML = `
      <div class="tab-content" style="display:grid;grid-template-rows:2em 1fr;height:100%;">
        <div class="topnavbar-tab">
          <div class="nome-tab">${titles[kind]}</div>
          <div class="top-left-menu-tab">
            <div data-act="min" title="Minimize">${MIN_SVG}</div>
            <div data-act="max" title="Maximize">${MAX_SVG}</div>
            <div data-act="close" title="Close">${CLOSE_SVG}</div>
          </div>
        </div>
        <div class="tab-body ${kind === 'ps' ? 'ps-body' : ''}"></div>
      </div>
    `;

    const body = tab.querySelector('.tab-body') as HTMLElement;
    const titleBar = tab.querySelector('.topnavbar-tab') as HTMLElement;

    if (kind === 'server') body.innerHTML = serverManagerHtml();
    else if (kind === 'services') body.innerHTML = servicesHtml();
    else if (kind === 'events') {
      eventHost = document.createElement('div');
      eventHost.className = 'evt-host';
      eventHost.innerHTML = renderEventTable(state.attackActive);
      body.appendChild(eventHost);
    } else {
      const host = document.createElement('div');
      host.className = 'ps-term';
      body.appendChild(host);
      mountPowerShell(host, state, refreshStatus);
    }

    titleBar.addEventListener('mousedown', (e) => {
      if ((e.target as HTMLElement).closest('[data-act]')) return;
      focusTab(tab);
      const startX = e.clientX;
      const startY = e.clientY;
      const origLeft = tab.offsetLeft;
      const origTop = tab.offsetTop;
      const onMove = (ev: MouseEvent) => {
        tab.style.left = `${origLeft + ev.clientX - startX}px`;
        tab.style.top = `${Math.max(0, origTop + ev.clientY - startY)}px`;
        tab.style.transitionDuration = '0s';
      };
      const onUp = () => {
        document.removeEventListener('mousemove', onMove);
        document.removeEventListener('mouseup', onUp);
      };
      document.addEventListener('mousemove', onMove);
      document.addEventListener('mouseup', onUp);
    });

    tab.querySelector('[data-act="close"]')?.addEventListener('click', () => {
      tab.remove();
      openTabs.delete(kind);
      if (kind === 'events') eventHost = null;
    });
    tab.querySelector('[data-act="min"]')?.addEventListener('click', () => {
      tab.style.display = 'none';
    });
    tab.querySelector('[data-act="max"]')?.addEventListener('click', () => {
      tab.style.left = '0';
      tab.style.top = '0';
      tab.style.width = '100%';
      tab.style.height = 'calc(100vh - var(--nav-height))';
      tab.style.transitionDuration = '0.35s';
    });

    tab.addEventListener('mousedown', () => focusTab(tab));
    layer.appendChild(tab);
    openTabs.set(kind, tab);
    focusTab(tab);
  };

  root.querySelectorAll('[data-open]').forEach((el) => {
    el.addEventListener('click', () => openWindow(((el as HTMLElement).dataset.open || 'ps') as WinKind));
  });

  document.getElementById('windows-div')?.addEventListener('click', () => {
    startSection.classList.toggle('on-visible-start');
  });

  setInterval(() => {
    const parts = clockParts();
    const t = document.getElementById('orario-data');
    const d = document.getElementById('calendario-data');
    if (t) t.textContent = parts.time;
    if (d) d.textContent = parts.date;
  }, 30_000);

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
