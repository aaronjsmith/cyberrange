import w11Css from './vendor/w11css/style.css?inline';
import wallpaper from './vendor/w11css/images/bloom.jpg';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import xtermCss from '@xterm/xterm/css/xterm.css?inline';

import serverIcon from '@fluentui/svg-icons/icons/server_24_filled.svg?raw';
import eventsIcon from '@fluentui/svg-icons/icons/clipboard_error_24_filled.svg?raw';
import servicesIcon from '@fluentui/svg-icons/icons/wrench_screwdriver_24_filled.svg?raw';
import psIcon from '@fluentui/svg-icons/icons/window_console_20_filled.svg?raw';
import minIcon from '@fluentui/svg-icons/icons/subtract_24_filled.svg?raw';
import maxIcon from '@fluentui/svg-icons/icons/maximize_24_filled.svg?raw';
import closeIcon from '@fluentui/svg-icons/icons/dismiss_24_filled.svg?raw';
import appsIcon from '@fluentui/svg-icons/icons/apps_24_filled.svg?raw';

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

function levelIcon(level: string): string {
  if (level === 'Failure' || level === 'Error') return '●';
  if (level === 'Warning') return '▲';
  return 'ℹ';
}

function renderEventViewerMmc(attackActive: boolean): string {
  const rows = attackActive ? SECURITY_EVENTS_ATTACK : SECURITY_EVENTS_QUIET;
  const first = rows[0];
  return `
    <div class="mmc">
      <div class="mmc-menubar">
        <span>File</span><span>Action</span><span>View</span><span>Help</span>
      </div>
      <div class="mmc-toolbar">
        <button type="button" disabled>Back</button>
        <button type="button" disabled>Forward</button>
        <span class="mmc-sep"></span>
        <button type="button">Refresh</button>
        <button type="button">Properties</button>
        <button type="button">Help</button>
      </div>
      <div class="mmc-path">Event Viewer (Local) \\ Windows Logs \\ Security</div>
      <div class="mmc-body">
        <aside class="mmc-tree">
          <div class="mmc-tree-root open">Event Viewer (Local)</div>
          <div class="mmc-tree-group open">
            <div class="mmc-tree-label">Custom Views</div>
            <div class="mmc-tree-item">Administrative Events</div>
          </div>
          <div class="mmc-tree-group open">
            <div class="mmc-tree-label">Windows Logs</div>
            <div class="mmc-tree-item">Application</div>
            <div class="mmc-tree-item active" data-log="Security">Security</div>
            <div class="mmc-tree-item">Setup</div>
            <div class="mmc-tree-item">System</div>
            <div class="mmc-tree-item">Forwarded Events</div>
          </div>
          <div class="mmc-tree-group">
            <div class="mmc-tree-label">Applications and Services Logs</div>
          </div>
          <div class="mmc-tree-item">Subscriptions</div>
        </aside>
        <section class="mmc-main">
          <div class="mmc-list-pane">
            <div class="mmc-list-title">Security</div>
            <table class="mmc-table">
              <thead>
                <tr>
                  <th>Level</th>
                  <th>Date and Time</th>
                  <th>Source</th>
                  <th>Event ID</th>
                  <th>Task Category</th>
                </tr>
              </thead>
              <tbody>
                ${rows
                  .map(
                    (r, i) => `
                  <tr class="mmc-row ${r.level === 'Failure' ? 'fail' : ''} ${i === 0 ? 'selected' : ''}"
                      data-idx="${i}"
                      data-level="${r.level}"
                      data-time="${r.time}"
                      data-id="${r.id}"
                      data-source="${r.source}"
                      data-task="${r.task}"
                      data-message="${r.message.replace(/"/g, '&quot;')}">
                    <td><span class="lvl">${levelIcon(r.level)}</span> ${r.level === 'Failure' ? 'Audit Failure' : 'Audit Success'}</td>
                    <td>${r.time}</td>
                    <td>${r.source}</td>
                    <td>${r.id}</td>
                    <td>${r.task}</td>
                  </tr>`,
                  )
                  .join('')}
              </tbody>
            </table>
          </div>
          <div class="mmc-preview" id="mmc-preview">
            <div class="mmc-preview-title">General</div>
            <div class="mmc-preview-meta">
              <div><span>Log Name:</span> Security</div>
              <div><span>Source:</span> <em data-f="source">${first?.source || ''}</em></div>
              <div><span>Event ID:</span> <em data-f="id">${first?.id || ''}</em></div>
              <div><span>Level:</span> <em data-f="level">${first?.level === 'Failure' ? 'Audit Failure' : 'Audit Success'}</em></div>
              <div><span>User:</span> N/A</div>
              <div><span>OpCode:</span> Info</div>
              <div><span>Logged:</span> <em data-f="time">${first?.time || ''}</em></div>
              <div><span>Task Category:</span> <em data-f="task">${first?.task || ''}</em></div>
              <div><span>Keywords:</span> Audit Success, Audit Failure</div>
              <div><span>Computer:</span> WIN-SRV-2025-01.CYBERRANGE.local</div>
            </div>
            <pre class="mmc-preview-msg" data-f="message">${first?.message || ''}</pre>
          </div>
        </section>
        <aside class="mmc-actions">
          <div class="mmc-actions-title">Actions</div>
          <div class="mmc-actions-group">Security</div>
          <button type="button">Open Saved Log...</button>
          <button type="button">Create Custom View...</button>
          <button type="button">Import Custom View...</button>
          <button type="button">Filter Current Log...</button>
          <button type="button">Find...</button>
          <button type="button">Clear Log...</button>
          <button type="button">Properties</button>
        </aside>
      </div>
      <div class="mmc-status">${rows.length} event(s) · WIN-SRV-2025-01</div>
    </div>`;
}

function wireEventViewer(root: HTMLElement): void {
  const preview = root.querySelector('#mmc-preview');
  if (!preview) return;
  root.querySelectorAll('.mmc-row').forEach((row) => {
    row.addEventListener('click', () => {
      root.querySelectorAll('.mmc-row').forEach((r) => r.classList.remove('selected'));
      row.classList.add('selected');
      const el = row as HTMLElement;
      const set = (field: string, value: string) => {
        const node = preview.querySelector(`[data-f="${field}"]`);
        if (node) node.textContent = value;
      };
      const level = el.dataset.level === 'Failure' ? 'Audit Failure' : 'Audit Success';
      set('source', el.dataset.source || '');
      set('id', el.dataset.id || '');
      set('level', level);
      set('time', el.dataset.time || '');
      set('task', el.dataset.task || '');
      set('message', el.dataset.message || '');
    });
  });

  root.querySelectorAll('.mmc-tree-item').forEach((item) => {
    item.addEventListener('click', () => {
      root.querySelectorAll('.mmc-tree-item').forEach((n) => n.classList.remove('active'));
      item.classList.add('active');
    });
  });
}

function serverManagerHtml(): string {
  return `
    <div class="sm">
      <header class="sm-top">
        <div class="sm-brand">
          <span class="sm-brand-mark" aria-hidden="true"></span>
          <div>
            <div class="sm-brand-title">Server Manager</div>
            <div class="sm-brand-sub">WIN-SRV-2025-01</div>
          </div>
        </div>
        <div class="sm-top-actions">
          <button type="button" class="sm-link">Manage ▾</button>
          <button type="button" class="sm-link">Tools ▾</button>
          <button type="button" class="sm-link">View ▾</button>
          <button type="button" class="sm-link">Help ▾</button>
          <button type="button" class="sm-flag" title="Notifications">⚑ 1</button>
        </div>
      </header>
      <div class="sm-shell">
        <nav class="sm-nav">
          <button type="button" class="sm-nav-item" data-sm-view="dashboard">Dashboard</button>
          <button type="button" class="sm-nav-item active" data-sm-view="local">Local Server</button>
          <button type="button" class="sm-nav-item" data-sm-view="all">All Servers</button>
          <div class="sm-nav-section">Roles and Server Groups</div>
          <button type="button" class="sm-nav-item" data-sm-view="file">File and Storage Services</button>
          <button type="button" class="sm-nav-item" data-sm-view="rds">Remote Desktop Services</button>
        </nav>
        <main class="sm-content">
          <section class="sm-view" data-sm-panel="dashboard" hidden>
            <h2 class="sm-h">Welcome to Server Manager</h2>
            <p class="sm-lead">Configure local and remote servers from this console. Roles below report green when healthy.</p>
            <div class="sm-tiles">
              <article class="sm-tile ok">
                <h3>Local Server</h3>
                <p>1 server · Online</p>
                <ul><li>No alerts</li><li>Roles installed: 2</li></ul>
              </article>
              <article class="sm-tile ok">
                <h3>File and Storage Services</h3>
                <p>1 server · Healthy</p>
                <ul><li>Volumes: OK</li><li>Shares: 3</li></ul>
              </article>
              <article class="sm-tile warn">
                <h3>Remote Desktop Services</h3>
                <p>1 server · Attention</p>
                <ul><li>RDP enabled on 3389</li><li>Review hardening baseline</li></ul>
              </article>
              <article class="sm-tile muted">
                <h3>All Servers</h3>
                <p>1 managed server</p>
                <ul><li>CYBERRANGE.local</li></ul>
              </article>
            </div>
          </section>
          <section class="sm-view" data-sm-panel="local">
            <div class="sm-local-head">
              <h2 class="sm-h">Local Server</h2>
              <div class="sm-tasks">
                <button type="button">Refresh</button>
                <button type="button">Tasks ▾</button>
              </div>
            </div>
            <div class="sm-banner">
              <strong>Properties</strong>
              <span>Last refreshed just now · Hyper-V not detected</span>
            </div>
            <div class="sm-props-grid">
              <div class="sm-prop"><span>Computer name</span><strong>WIN-SRV-2025-01</strong></div>
              <div class="sm-prop"><span>Domain</span><strong>CYBERRANGE.local</strong></div>
              <div class="sm-prop"><span>Windows Firewall</span><strong class="sm-on">Domain: On</strong></div>
              <div class="sm-prop"><span>Remote management</span><strong class="sm-on">Enabled</strong></div>
              <div class="sm-prop"><span>Remote Desktop</span><strong class="sm-warn">Enabled</strong></div>
              <div class="sm-prop"><span>NIC Teaming</span><strong>Disabled</strong></div>
              <div class="sm-prop"><span>Ethernet</span><strong>IPv4 address assigned by DHCP</strong></div>
              <div class="sm-prop"><span>Operating system</span><strong>Windows Server 2025 Datacenter</strong></div>
              <div class="sm-prop"><span>Hardware</span><strong>Cyberrange Virtual Machine</strong></div>
              <div class="sm-prop"><span>Last update installed</span><strong>9/23/2026 6:12 PM</strong></div>
              <div class="sm-prop"><span>Windows Update</span><strong>Managed by lab policy</strong></div>
              <div class="sm-prop"><span>Time zone</span><strong>(UTC-06:00) Central Time</strong></div>
              <div class="sm-prop"><span>Product ID</span><strong>XXXXX-XXXXX-XXXXX-XXXXX-LAB01</strong></div>
              <div class="sm-prop"><span>Processors</span><strong>4 Virtual Processors</strong></div>
              <div class="sm-prop"><span>Installed memory (RAM)</span><strong>16.0 GB</strong></div>
              <div class="sm-prop"><span>Total disk space</span><strong>127 GB</strong></div>
            </div>
            <div class="sm-roles">
              <h3>Roles and Features</h3>
              <table class="sm-table">
                <thead><tr><th>Role / Feature</th><th>Type</th><th>Status</th></tr></thead>
                <tbody>
                  <tr><td>File and Storage Services</td><td>Role</td><td><span class="pill ok">Installed</span></td></tr>
                  <tr><td>Remote Desktop Services</td><td>Role</td><td><span class="pill ok">Installed</span></td></tr>
                  <tr><td>Windows Defender Firewall</td><td>Feature</td><td><span class="pill ok">Installed</span></td></tr>
                  <tr><td>Windows Remote Management</td><td>Feature</td><td><span class="pill ok">Installed</span></td></tr>
                </tbody>
              </table>
            </div>
            <div class="sm-events">
              <h3>Events</h3>
              <p class="sm-lead">Open <em>Event Viewer</em> on the desktop to inspect Security log entries for failed RDP logons.</p>
            </div>
          </section>
          <section class="sm-view" data-sm-panel="all" hidden>
            <h2 class="sm-h">All Servers</h2>
            <table class="sm-table">
              <thead><tr><th>Server Name</th><th>IPv4 Address</th><th>Manageability</th><th>Status</th></tr></thead>
              <tbody>
                <tr>
                  <td>WIN-SRV-2025-01</td>
                  <td>10.20.30.40</td>
                  <td>Online - Performance counters not started</td>
                  <td><span class="pill ok">Online</span></td>
                </tr>
              </tbody>
            </table>
          </section>
          <section class="sm-view" data-sm-panel="file" hidden>
            <h2 class="sm-h">File and Storage Services</h2>
            <div class="sm-tiles">
              <article class="sm-tile ok"><h3>Volumes</h3><p>C: 42 GB free of 127 GB</p></article>
              <article class="sm-tile ok"><h3>Shares</h3><p>3 file shares available</p></article>
            </div>
          </section>
          <section class="sm-view" data-sm-panel="rds" hidden>
            <h2 class="sm-h">Remote Desktop Services</h2>
            <div class="sm-banner warn-banner">
              <strong>Deployment overview</strong>
              <span>RDP listening on TCP 3389 · Review failed logons in Event Viewer after start-attack</span>
            </div>
            <table class="sm-table">
              <thead><tr><th>Collection</th><th>Type</th><th>Status</th></tr></thead>
              <tbody>
                <tr><td>QuickSessionCollection</td><td>Session-based</td><td><span class="pill warn">Exposed</span></td></tr>
              </tbody>
            </table>
          </section>
        </main>
      </div>
    </div>`;
}

function wireServerManager(root: HTMLElement): void {
  const items = root.querySelectorAll<HTMLElement>('.sm-nav-item');
  const panels = root.querySelectorAll<HTMLElement>('.sm-view');
  items.forEach((item) => {
    item.addEventListener('click', () => {
      const view = item.dataset.smView || 'local';
      items.forEach((n) => n.classList.toggle('active', n === item));
      panels.forEach((panel) => {
        panel.hidden = panel.dataset.smPanel !== view;
      });
    });
  });
}

function servicesHtml(): string {
  const rows = [
    ['Running', 'Automatic', 'EventLog', 'Windows Event Log'],
    ['Running', 'Automatic', 'TermService', 'Remote Desktop Services'],
    ['Running', 'Automatic', 'WinRM', 'Windows Remote Management (WS-Management)'],
    ['Running', 'Automatic', 'wuauserv', 'Windows Update'],
    ['Stopped', 'Manual', 'RemoteRegistry', 'Remote Registry'],
  ];
  return `
    <div class="mmc">
      <div class="mmc-menubar"><span>File</span><span>Action</span><span>View</span><span>Help</span></div>
      <div class="mmc-toolbar"><button type="button">Start</button><button type="button">Stop</button><button type="button">Restart</button><span class="mmc-sep"></span><button type="button">Refresh</button></div>
      <div class="mmc-path">Services (Local)</div>
      <div class="mmc-body">
        <aside class="mmc-tree">
          <div class="mmc-tree-root open">Services (Local)</div>
          <div class="mmc-tree-item active">Services</div>
        </aside>
        <section class="mmc-main">
          <div class="mmc-list-pane mmc-list-fill">
            <table class="mmc-table">
              <thead>
                <tr><th>Name</th><th>Description</th><th>Status</th><th>Startup Type</th><th>Log On As</th></tr>
              </thead>
              <tbody>
                ${rows
                  .map(
                    ([status, startup, name, desc], i) => `
                  <tr class="mmc-row ${i === 0 ? 'selected' : ''}">
                    <td>${name}</td>
                    <td>${desc}</td>
                    <td>${status}</td>
                    <td>${startup}</td>
                    <td>Local System</td>
                  </tr>`,
                  )
                  .join('')}
              </tbody>
            </table>
          </div>
        </section>
        <aside class="mmc-actions">
          <div class="mmc-actions-title">Actions</div>
          <div class="mmc-actions-group">Services (Local)</div>
          <button type="button">Connect to another computer...</button>
          <button type="button">Export List...</button>
          <button type="button">Help</button>
        </aside>
      </div>
      <div class="mmc-status">${rows.length} service(s)</div>
    </div>`;
}

function tintSvg(svg: string): string {
  return svg.replace(/<path\b/g, '<path fill="currentColor"');
}

const ICONS: Record<WinKind, string> = {
  server: tintSvg(serverIcon),
  events: tintSvg(eventsIcon),
  services: tintSvg(servicesIcon),
  ps: tintSvg(psIcon),
};

const MIN_SVG = tintSvg(minIcon);
const MAX_SVG = tintSvg(maxIcon);
const CLOSE_SVG = tintSvg(closeIcon);
const START_SVG = tintSvg(appsIcon);

function iconBadge(kind: WinKind, className: string): string {
  return `<span class="${className}" aria-hidden="true">${ICONS[kind]}</span>`;
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
        <button type="button" class="desk-icon" data-open="server">${iconBadge('server', 'ico')}<span>Server Manager</span></button>
        <button type="button" class="desk-icon" data-open="events">${iconBadge('events', 'ico')}<span>Event Viewer</span></button>
        <button type="button" class="desk-icon" data-open="services">${iconBadge('services', 'ico')}<span>Services</span></button>
        <button type="button" class="desk-icon" data-open="ps">${iconBadge('ps', 'ico')}<span>PowerShell</span></button>
      </div>
      <div class="status-pill" id="desk-status">Establish baseline in PowerShell</div>
      <div id="window-layer"></div>
      <div id="w11-start-section">
        <div class="padding-start">
          <div class="app-container-header"><span>Pinned</span></div>
          <div id="second-app-container">
            <div data-open="ps">${iconBadge('ps', 'start-ico')}<span>PowerShell</span></div>
            <div data-open="events">${iconBadge('events', 'start-ico')}<span>Event Viewer</span></div>
            <div data-open="server">${iconBadge('server', 'start-ico')}<span>Server Manager</span></div>
            <div data-open="services">${iconBadge('services', 'start-ico')}<span>Services</span></div>
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
            <div id="windows-div" title="Start"><span class="tb-icon start-btn">${START_SVG}</span></div>
            <div data-open="ps" title="PowerShell">${iconBadge('ps', 'tb-icon')}</div>
            <div data-open="events" title="Event Viewer">${iconBadge('events', 'tb-icon')}</div>
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
      display: grid; place-items: center; color: #fff;
      box-shadow: 0 8px 20px rgba(0,0,0,.35);
    }
    .desk-icon .ico svg, .start-ico svg { width: 28px; height: 28px; display: block; }
    .start-ico { width: 2.5rem; height: 2.5rem; margin-bottom: .2rem; }
    .start-ico svg { width: 1.35rem; height: 1.35rem; }
    .tb-icon {
      width: 100%; height: 100%; display: grid; place-items: center; color: #fff;
    }
    .tb-icon svg { width: 1.15rem; height: 1.15rem; display: block; }
    .tb-icon.start-btn { color: #6bd3ff; }
    .top-left-menu-tab svg { width: 0.85rem; height: 0.85rem; }
    .nome-tab {
      padding-left: .75rem; justify-self: start; font-size: .85rem;
      display: inline-flex; align-items: center; gap: .4rem;
    }
    .nome-tab .title-ico { display: inline-grid; place-items: center; color: #fff; }
    .nome-tab .title-ico svg { width: 1rem; height: 1rem; }
    .status-pill {
      position: absolute; top: 1rem; right: 1rem; z-index: 3; padding: .45rem .75rem;
      border-radius: 999px; background: rgba(0,0,0,.45); border: 1px solid rgba(255,255,255,.2);
      font-size: .78rem; color: #fff;
    }
    #window-layer { position: absolute; inset: 0 0 var(--nav-height) 0; z-index: 4; pointer-events: none; }
    #window-layer .windows-tab { pointer-events: auto; display: grid; z-index: 5; }
    .windows-tab .tab-body { height: calc(100% - 2em); overflow: hidden; background: rgba(32,32,32,.92); color: #eee; }
    .windows-tab .tab-body.ps-body { background: #012456; overflow: hidden; }
    .windows-tab .tab-body.mmc-body { background: #f0f0f0; color: #1a1a1a; overflow: hidden; }
    .ps-term { height: 100%; }
    .evt-host, .mmc-host { height: 100%; }
    .mmc {
      height: 100%; display: grid;
      grid-template-rows: auto auto auto 1fr auto;
      font-family: "Segoe UI", Tahoma, sans-serif; font-size: 12px; background: #f0f0f0; color: #1a1a1a;
    }
    .mmc-menubar {
      display: flex; gap: 1rem; padding: .2rem .55rem; background: #f3f3f3;
      border-bottom: 1px solid #d0d0d0; color: #222;
    }
    .mmc-menubar span { cursor: default; padding: .1rem .25rem; }
    .mmc-menubar span:hover { background: #e5f3ff; }
    .mmc-toolbar {
      display: flex; align-items: center; gap: .35rem; padding: .25rem .45rem;
      background: linear-gradient(#fafafa, #ececec); border-bottom: 1px solid #c8c8c8;
    }
    .mmc-toolbar button {
      border: 1px solid transparent; background: transparent; padding: .2rem .45rem;
      font: inherit; color: #222; border-radius: 2px;
    }
    .mmc-toolbar button:hover:not(:disabled) { border-color: #a8d0f0; background: #e5f3ff; }
    .mmc-toolbar button:disabled { opacity: .45; }
    .mmc-sep { width: 1px; height: 1.1rem; background: #c0c0c0; margin: 0 .2rem; }
    .mmc-path {
      padding: .25rem .55rem; background: #fff; border-bottom: 1px solid #c8c8c8;
      color: #444; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
    }
    .mmc-body {
      display: grid; grid-template-columns: 210px 1fr 170px; min-height: 0; height: 100%;
      border-bottom: 1px solid #c8c8c8;
    }
    .mmc-body-single { grid-template-columns: 1fr; }
    .mmc-tree {
      background: #fff; border-right: 1px solid #c8c8c8; overflow: auto; padding: .35rem 0;
    }
    .mmc-tree-root, .mmc-tree-label, .mmc-tree-item {
      padding: .2rem .55rem .2rem 1rem; cursor: default; white-space: nowrap;
    }
    .mmc-tree-root { font-weight: 600; padding-left: .55rem; }
    .mmc-tree-label { color: #555; font-weight: 600; padding-left: .85rem; }
    .mmc-tree-item { padding-left: 1.5rem; }
    .mmc-tree-item:hover, .mmc-tree-label:hover { background: #e5f3ff; }
    .mmc-tree-item.active { background: #cce8ff; outline: 1px solid #99d1ff; }
    .mmc-main { display: grid; grid-template-rows: 1fr 140px; min-width: 0; background: #fff; }
    .mmc-list-fill { grid-row: 1 / -1; }
    .mmc-list-pane { overflow: auto; border-bottom: 1px solid #c8c8c8; }
    .mmc-list-title {
      padding: .35rem .55rem; font-weight: 600; background: #f7f7f7; border-bottom: 1px solid #e0e0e0;
    }
    .mmc-table { width: 100%; border-collapse: collapse; font-size: 11.5px; }
    .mmc-table th {
      text-align: left; padding: .3rem .45rem; background: #f5f5f5;
      border-bottom: 1px solid #d0d0d0; font-weight: 600; position: sticky; top: 0;
    }
    .mmc-table td { padding: .28rem .45rem; border-bottom: 1px solid #eee; vertical-align: top; }
    .mmc-row { cursor: default; }
    .mmc-row:hover { background: #f5faff; }
    .mmc-row.selected { background: #cce8ff; }
    .mmc-row.fail td { color: #a61f24; }
    .mmc-row .lvl { color: #0078d4; margin-right: .2rem; }
    .mmc-row.fail .lvl { color: #a61f24; }
    .mmc-preview { overflow: auto; padding: .45rem .65rem; background: #fafafa; }
    .mmc-preview-title { font-weight: 700; margin-bottom: .35rem; }
    .mmc-preview-meta {
      display: grid; grid-template-columns: 1fr 1fr; gap: .15rem .75rem; margin-bottom: .5rem;
    }
    .mmc-preview-meta span { color: #666; margin-right: .25rem; }
    .mmc-preview-msg {
      margin: 0; white-space: pre-wrap; font-family: Consolas, monospace; font-size: 11px;
      background: #fff; border: 1px solid #ddd; padding: .45rem; min-height: 2.5rem;
    }
    .mmc-actions {
      background: #f7f7f7; border-left: 1px solid #c8c8c8; overflow: auto; padding: .35rem;
      display: flex; flex-direction: column; gap: .15rem;
    }
    .mmc-actions-title { font-weight: 700; padding: .2rem .3rem; }
    .mmc-actions-group { color: #555; font-weight: 600; padding: .35rem .3rem .15rem; }
    .mmc-actions button {
      text-align: left; border: 0; background: transparent; padding: .28rem .35rem;
      font: inherit; color: #0563c1; border-radius: 2px; cursor: pointer;
    }
    .mmc-actions button:hover { background: #e5f3ff; }
    .mmc-status {
      padding: .2rem .55rem; background: #f3f3f3; border-top: 1px solid #d0d0d0; color: #444;
    }
    .mmc-dash { padding: .85rem 1rem; display: block; overflow: auto; }
    .mmc-dash h3 { margin: 0 0 .75rem; font-size: 1.05rem; }
    .mmc-props { border-collapse: collapse; width: min(520px, 100%); }
    .mmc-props th, .mmc-props td { text-align: left; padding: .35rem .5rem; border-bottom: 1px solid #e2e2e2; }
    .mmc-props th { width: 40%; color: #555; font-weight: 600; }
    .windows-tab .tab-body.sm-body { background: #1b1b1b; color: #f3f3f3; overflow: hidden; }
    .sm { height: 100%; display: grid; grid-template-rows: auto 1fr; font-family: "Segoe UI", Tahoma, sans-serif; font-size: 12.5px; background: #1b1b1b; color: #f3f3f3; }
    .sm-top {
      display: flex; align-items: center; justify-content: space-between; gap: 1rem;
      padding: .55rem .85rem; background: #111; border-bottom: 1px solid #2f2f2f;
    }
    .sm-brand { display: flex; align-items: center; gap: .65rem; }
    .sm-brand-mark {
      width: 28px; height: 28px; border-radius: 4px;
      background: linear-gradient(135deg, #60cdff, #0078d4);
      box-shadow: inset 0 0 0 1px rgba(255,255,255,.2);
    }
    .sm-brand-title { font-size: 15px; font-weight: 600; line-height: 1.1; }
    .sm-brand-sub { font-size: 11px; color: #a6a6a6; }
    .sm-top-actions { display: flex; align-items: center; gap: .2rem; }
    .sm-link, .sm-flag, .sm-tasks button {
      border: 0; background: transparent; color: #ddd; font: inherit; padding: .3rem .55rem;
      border-radius: 4px; cursor: pointer;
    }
    .sm-link:hover, .sm-flag:hover, .sm-tasks button:hover { background: rgba(255,255,255,.08); }
    .sm-flag { color: #ffb900; font-weight: 600; }
    .sm-shell { display: grid; grid-template-columns: 220px 1fr; min-height: 0; height: 100%; }
    .sm-nav {
      background: #202020; border-right: 1px solid #2f2f2f; padding: .45rem 0; overflow: auto;
      display: flex; flex-direction: column;
    }
    .sm-nav-item {
      text-align: left; border: 0; background: transparent; color: #ececec; font: inherit;
      padding: .55rem .9rem; cursor: pointer; border-left: 3px solid transparent;
    }
    .sm-nav-item:hover { background: rgba(255,255,255,.06); }
    .sm-nav-item.active { background: rgba(0,120,212,.28); border-left-color: #60cdff; }
    .sm-nav-section {
      margin-top: .55rem; padding: .45rem .9rem .25rem; color: #9a9a9a;
      font-size: 11px; text-transform: uppercase; letter-spacing: .04em;
    }
    .sm-content { overflow: auto; padding: .85rem 1rem 1.1rem; background: #1f1f1f; }
    .sm-h { margin: 0 0 .35rem; font-size: 1.35rem; font-weight: 600; }
    .sm-lead { margin: 0 0 .85rem; color: #bdbdbd; line-height: 1.45; }
    .sm-local-head { display: flex; align-items: center; justify-content: space-between; gap: 1rem; margin-bottom: .55rem; }
    .sm-tasks { display: flex; gap: .25rem; }
    .sm-banner {
      display: flex; justify-content: space-between; gap: 1rem; align-items: center;
      padding: .55rem .7rem; margin-bottom: .75rem; border-radius: 4px;
      background: #252525; border: 1px solid #3a3a3a;
    }
    .sm-banner.warn-banner { border-color: #9a6b00; background: #2a230f; }
    .sm-banner span { color: #b5b5b5; }
    .sm-props-grid {
      display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 0;
      border: 1px solid #3a3a3a; border-radius: 4px; overflow: hidden; margin-bottom: 1rem;
    }
    .sm-prop {
      display: grid; grid-template-columns: 42% 1fr; gap: .5rem; padding: .45rem .65rem;
      border-bottom: 1px solid #333; border-right: 1px solid #333; background: #242424;
    }
    .sm-prop:nth-child(2n) { border-right: 0; }
    .sm-prop span { color: #9f9f9f; }
    .sm-prop strong { font-weight: 600; color: #f0f0f0; }
    .sm-on { color: #6ccb5f !important; }
    .sm-warn { color: #ffb900 !important; }
    .sm-tiles { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: .75rem; }
    .sm-tile {
      border-radius: 6px; padding: .85rem .9rem; border: 1px solid #3a3a3a; background: #262626;
      min-height: 110px;
    }
    .sm-tile h3 { margin: 0 0 .35rem; font-size: 1rem; }
    .sm-tile p { margin: 0 0 .45rem; color: #c2c2c2; }
    .sm-tile ul { margin: 0; padding-left: 1.1rem; color: #a8a8a8; }
    .sm-tile.ok { border-top: 3px solid #6ccb5f; }
    .sm-tile.warn { border-top: 3px solid #ffb900; }
    .sm-tile.muted { border-top: 3px solid #0078d4; }
    .sm-roles, .sm-events { margin-top: .25rem; }
    .sm-roles h3, .sm-events h3 { margin: 0 0 .45rem; font-size: .95rem; }
    .sm-table { width: 100%; border-collapse: collapse; background: #242424; border: 1px solid #3a3a3a; }
    .sm-table th, .sm-table td { text-align: left; padding: .45rem .6rem; border-bottom: 1px solid #333; }
    .sm-table th { background: #2b2b2b; color: #cfcfcf; font-weight: 600; }
    .pill {
      display: inline-flex; padding: .1rem .45rem; border-radius: 999px; font-size: 11px; font-weight: 600;
    }
    .pill.ok { background: rgba(108,203,95,.18); color: #6ccb5f; }
    .pill.warn { background: rgba(255,185,0,.18); color: #ffb900; }
    .tb-label { color: #fff; font-size: .7rem; font-weight: 700; }
    #w11-start-section {
      background: rgba(32, 32, 48, 0.72);
      z-index: 6;
    }
    #footer-start-section a { color: #fff; text-decoration: none; }
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
    if (eventHost) {
      eventHost.innerHTML = renderEventViewerMmc(state.attackActive);
      wireEventViewer(eventHost);
    }
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
      events: 'Event Viewer - [WIN-SRV-2025-01]',
      services: 'Services - [WIN-SRV-2025-01]',
      server: 'Server Manager - WIN-SRV-2025-01',
      ps: 'Administrator: Windows PowerShell',
    };

    const tab = document.createElement('div');
    tab.className = 'windows-tab';
    tab.style.width = kind === 'events' ? '920px' : kind === 'server' ? '980px' : kind === 'services' ? '820px' : kind === 'ps' ? '720px' : '560px';
    tab.style.height = kind === 'server' ? '620px' : kind === 'events' || kind === 'services' ? '560px' : kind === 'ps' ? '440px' : '360px';
    tab.style.left = `${40 + openTabs.size * 28}px`;
    tab.style.top = `${28 + openTabs.size * 24}px`;
    const bodyClass = kind === 'ps' ? 'ps-body' : kind === 'server' ? 'sm-body' : 'mmc-body';
    tab.innerHTML = `
      <div class="tab-content" style="display:grid;grid-template-rows:2em 1fr;height:100%;">
        <div class="topnavbar-tab">
          <div class="nome-tab"><span class="title-ico">${ICONS[kind]}</span>${titles[kind]}</div>
          <div class="top-left-menu-tab">
            <div data-act="min" title="Minimize">${MIN_SVG}</div>
            <div data-act="max" title="Maximize">${MAX_SVG}</div>
            <div data-act="close" title="Close">${CLOSE_SVG}</div>
          </div>
        </div>
        <div class="tab-body ${bodyClass}"></div>
      </div>
    `;

    const body = tab.querySelector('.tab-body') as HTMLElement;
    const titleBar = tab.querySelector('.topnavbar-tab') as HTMLElement;

    if (kind === 'server') {
      body.innerHTML = serverManagerHtml();
      wireServerManager(body);
    } else if (kind === 'services') body.innerHTML = servicesHtml();
    else if (kind === 'events') {
      eventHost = document.createElement('div');
      eventHost.className = 'evt-host';
      eventHost.innerHTML = renderEventViewerMmc(state.attackActive);
      body.appendChild(eventHost);
      wireEventViewer(eventHost);
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
