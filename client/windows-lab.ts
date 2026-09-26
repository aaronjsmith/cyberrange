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

function mmcShell(opts: {
  consolePath: string;
  treeHtml: string;
  centerHtml: string;
  actionTitle: string;
  actionButtons: string[];
  status?: string;
}): string {
  const actions = opts.actionButtons
    .map((label) => `<button type="button" class="mmc-action">${label}</button>`)
    .join('');
  return `
    <div class="mmc">
      <div class="mmc-menubar">
        <span>File</span><span>Action</span><span>View</span><span>Favorites</span><span>Window</span><span>Help</span>
      </div>
      <div class="mmc-toolbar">
        <button type="button" class="mmc-tool" disabled title="Back">◀</button>
        <button type="button" class="mmc-tool" disabled title="Forward">▶</button>
        <span class="mmc-sep"></span>
        <button type="button" class="mmc-tool" title="Up">▲</button>
        <button type="button" class="mmc-tool" title="Show/Hide Console Tree">▤</button>
        <span class="mmc-sep"></span>
        <button type="button" class="mmc-tool" title="Help">?</button>
      </div>
      <div class="mmc-path">${opts.consolePath}</div>
      <div class="mmc-body">
        <aside class="mmc-tree">${opts.treeHtml}</aside>
        <section class="mmc-main">${opts.centerHtml}</section>
        <aside class="mmc-actions">
          <div class="mmc-actions-title">Actions</div>
          <div class="mmc-actions-group">
            <span>${opts.actionTitle}</span>
            <button type="button" class="mmc-collapse" aria-label="Collapse">▲</button>
          </div>
          ${actions}
          <button type="button" class="mmc-action more">More Actions ▸</button>
        </aside>
      </div>
      <div class="mmc-status">
        <span>${opts.status || ''}</span>
        <span></span>
        <span></span>
      </div>
    </div>`;
}

function mmcTreeNode(opts: {
  label: string;
  depth?: number;
  open?: boolean;
  active?: boolean;
  leaf?: boolean;
  icon?: string;
}): string {
  const depth = opts.depth ?? 0;
  const twist = opts.leaf ? '<span class="twist empty"></span>' : `<span class="twist">${opts.open ? '▼' : '▶'}</span>`;
  const cls = [
    'mmc-node',
    opts.active ? 'active' : '',
    opts.open ? 'open' : '',
    opts.leaf ? 'leaf' : '',
  ]
    .filter(Boolean)
    .join(' ');
  return `<div class="${cls}" style="--d:${depth}" data-label="${opts.label}">${twist}<span class="ico ${opts.icon || 'folder'}"></span><span class="lbl">${opts.label}</span></div>`;
}

function renderEventViewerMmc(attackActive: boolean): string {
  const rows = attackActive ? SECURITY_EVENTS_ATTACK : SECURITY_EVENTS_QUIET;
  const first = rows[0];
  const tree = [
    mmcTreeNode({ label: 'Event Viewer (Local)', depth: 0, open: true, icon: 'console' }),
    mmcTreeNode({ label: 'Custom Views', depth: 1, open: false, icon: 'folder' }),
    mmcTreeNode({ label: 'Windows Logs', depth: 1, open: true, icon: 'folder' }),
    mmcTreeNode({ label: 'Application', depth: 2, leaf: true, icon: 'log' }),
    mmcTreeNode({ label: 'Security', depth: 2, leaf: true, active: true, icon: 'log' }),
    mmcTreeNode({ label: 'Setup', depth: 2, leaf: true, icon: 'log' }),
    mmcTreeNode({ label: 'System', depth: 2, leaf: true, icon: 'log' }),
    mmcTreeNode({ label: 'Forwarded Events', depth: 2, leaf: true, icon: 'log' }),
    mmcTreeNode({ label: 'Applications and Services Logs', depth: 1, open: false, icon: 'folder' }),
    mmcTreeNode({ label: 'Subscriptions', depth: 1, leaf: true, icon: 'doc' }),
  ].join('');

  const center = `
    <div class="mmc-list-pane">
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
    </div>`;

  return mmcShell({
    consolePath: 'Event Viewer (Local)\\Windows Logs\\Security',
    treeHtml: tree,
    centerHtml: center,
    actionTitle: 'Security',
    actionButtons: [
      'Open Saved Log...',
      'Create Custom View...',
      'Filter Current Log...',
      'Find...',
      'Clear Log...',
      'Properties',
      'Help',
      'Refresh',
    ],
    status: `${rows.length} event(s)`,
  });
}

function wireMmcChrome(root: HTMLElement): void {
  root.querySelectorAll('.mmc-node:not(.leaf)').forEach((node) => {
    node.addEventListener('click', (e) => {
      e.stopPropagation();
      node.classList.toggle('open');
      const twist = node.querySelector('.twist');
      if (twist && !twist.classList.contains('empty')) {
        twist.textContent = node.classList.contains('open') ? '▼' : '▶';
      }
    });
  });
  root.querySelectorAll('.mmc-node').forEach((node) => {
    node.addEventListener('click', () => {
      root.querySelectorAll('.mmc-node').forEach((n) => n.classList.remove('active'));
      node.classList.add('active');
    });
  });
}

function wireEventViewer(root: HTMLElement): void {
  wireMmcChrome(root);
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
}

function smTile(opts: {
  title: string;
  count: number;
  critical?: boolean;
  manageIssues?: number;
  stamp?: string;
}): string {
  const critical = Boolean(opts.critical);
  const issues = opts.manageIssues ?? 0;
  return `
    <article class="sm-tile ${critical ? 'critical' : 'healthy'}">
      <header class="sm-tile-head">
        <span class="sm-tile-ico" aria-hidden="true"></span>
        <span class="sm-tile-title">${opts.title}</span>
        <span class="sm-tile-count">${opts.count}</span>
      </header>
      <div class="sm-tile-status">
        ${
          critical
            ? `<span class="sm-badge err">${issues || opts.count}</span>`
            : `<span class="sm-badge ok" aria-hidden="true">↑</span>`
        }
        <span>Manageability</span>
      </div>
      <ul class="sm-tile-links">
        <li>Events</li>
        <li>Services</li>
        <li>Best Practices Analyzer</li>
        <li>Performance</li>
        <li>Roles and Features</li>
      </ul>
      ${opts.stamp ? `<footer class="sm-tile-stamp">${opts.stamp}</footer>` : ''}
    </article>`;
}

function serverManagerHtml(): string {
  const stamp = '9/23/2026 7:40 AM';
  return `
    <div class="sm">
      <header class="sm-top">
        <div class="sm-top-left">
          <button type="button" class="sm-navbtn" title="Back" disabled>◀</button>
          <button type="button" class="sm-navbtn" title="Forward" disabled>▶</button>
          <div class="sm-crumb" id="sm-crumb"><span>Server Manager</span><span class="sep">›</span><span>Dashboard</span></div>
        </div>
        <div class="sm-top-actions">
          <button type="button" class="sm-iconbtn" title="Refresh">↻</button>
          <button type="button" class="sm-flag" title="Notifications"><span class="flag">⚑</span><span class="warn">⚠</span></button>
          <button type="button" class="sm-link">Manage</button>
          <button type="button" class="sm-link">Tools</button>
          <button type="button" class="sm-link">View</button>
          <button type="button" class="sm-link">Help</button>
        </div>
      </header>
      <div class="sm-shell">
        <nav class="sm-nav">
          <button type="button" class="sm-nav-item active" data-sm-view="dashboard" data-sm-label="Dashboard">
            <span class="sm-nav-ico dash"></span>Dashboard
          </button>
          <button type="button" class="sm-nav-item" data-sm-view="local" data-sm-label="Local Server">
            <span class="sm-nav-ico server"></span>Local Server
          </button>
          <button type="button" class="sm-nav-item" data-sm-view="all" data-sm-label="All Servers">
            <span class="sm-nav-ico list"></span>All Servers
          </button>
          <button type="button" class="sm-nav-item" data-sm-view="file" data-sm-label="File and Storage Services">
            <span class="sm-nav-ico folder"></span>File and Storage Services
          </button>
          <button type="button" class="sm-nav-item" data-sm-view="rds" data-sm-label="Remote Desktop Services">
            <span class="sm-nav-ico rds"></span>Remote Desktop Services
          </button>
        </nav>
        <main class="sm-content">
          <section class="sm-view" data-sm-panel="dashboard">
            <div class="sm-section-head">
              <h2>ROLES AND SERVER GROUPS</h2>
              <p>Roles: 4 | Server groups: 1 | Servers total: 1</p>
            </div>
            <div class="sm-tile-grid">
              ${smTile({ title: 'File and Storage Services', count: 1, critical: true, manageIssues: 2, stamp })}
              ${smTile({ title: 'Remote Desktop Services', count: 1, critical: true, manageIssues: 1, stamp })}
              ${smTile({ title: 'Local Server', count: 1, stamp })}
              ${smTile({ title: 'All Servers', count: 1, critical: true, manageIssues: 1, stamp })}
              ${smTile({ title: 'Windows Firewall', count: 1, stamp })}
              ${smTile({ title: 'Windows Remote Management', count: 1, stamp })}
            </div>
          </section>
          <section class="sm-view" data-sm-panel="local" hidden>
            <div class="sm-section-head">
              <h2>LOCAL SERVER</h2>
              <p>WIN-SRV-2025-01 · CYBERRANGE.local</p>
            </div>
            <div class="sm-props-grid light">
              <div class="sm-prop"><span>Computer name</span><strong>WIN-SRV-2025-01</strong></div>
              <div class="sm-prop"><span>Domain</span><strong>CYBERRANGE.local</strong></div>
              <div class="sm-prop"><span>Windows Firewall</span><strong class="sm-on">Domain: On</strong></div>
              <div class="sm-prop"><span>Remote management</span><strong class="sm-on">Enabled</strong></div>
              <div class="sm-prop"><span>Remote Desktop</span><strong class="sm-warn">Enabled</strong></div>
              <div class="sm-prop"><span>Operating system</span><strong>Windows Server 2025 Datacenter</strong></div>
              <div class="sm-prop"><span>Ethernet</span><strong>IPv4 address assigned by DHCP</strong></div>
              <div class="sm-prop"><span>Last update installed</span><strong>9/23/2026 6:12 PM</strong></div>
              <div class="sm-prop"><span>Processors</span><strong>4 Virtual Processors</strong></div>
              <div class="sm-prop"><span>Installed memory (RAM)</span><strong>16.0 GB</strong></div>
              <div class="sm-prop"><span>Total disk space</span><strong>127 GB</strong></div>
              <div class="sm-prop"><span>Time zone</span><strong>(UTC-06:00) Central Time</strong></div>
            </div>
          </section>
          <section class="sm-view" data-sm-panel="all" hidden>
            <div class="sm-section-head"><h2>ALL SERVERS</h2><p>1 managed server</p></div>
            <table class="sm-table light">
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
            <div class="sm-section-head"><h2>FILE AND STORAGE SERVICES</h2><p>1 server</p></div>
            <div class="sm-tile-grid">
              ${smTile({ title: 'Volumes', count: 1, stamp })}
              ${smTile({ title: 'Shares', count: 3, stamp })}
            </div>
          </section>
          <section class="sm-view" data-sm-panel="rds" hidden>
            <div class="sm-section-head"><h2>REMOTE DESKTOP SERVICES</h2><p>RDP listening on TCP 3389</p></div>
            <div class="sm-tile-grid">
              ${smTile({ title: 'Remote Desktop Services', count: 1, critical: true, manageIssues: 1, stamp })}
            </div>
          </section>
        </main>
      </div>
    </div>`;
}

function wireServerManager(root: HTMLElement): void {
  const items = root.querySelectorAll<HTMLElement>('.sm-nav-item');
  const panels = root.querySelectorAll<HTMLElement>('.sm-view');
  const crumb = root.querySelector('#sm-crumb');
  items.forEach((item) => {
    item.addEventListener('click', () => {
      const view = item.dataset.smView || 'dashboard';
      const label = item.dataset.smLabel || 'Dashboard';
      items.forEach((n) => n.classList.toggle('active', n === item));
      panels.forEach((panel) => {
        panel.hidden = panel.dataset.smPanel !== view;
      });
      if (crumb) {
        crumb.innerHTML = `<span>Server Manager</span><span class="sep">›</span><span>${label}</span>`;
      }
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
  const tree = [
    mmcTreeNode({ label: 'Console Root', depth: 0, open: true, icon: 'folder' }),
    mmcTreeNode({ label: 'Services (Local)', depth: 1, open: true, active: true, icon: 'gear' }),
  ].join('');
  const center = `
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
              <td><span class="svc-ico"></span>${name}</td>
              <td>${desc}</td>
              <td>${status}</td>
              <td>${startup}</td>
              <td>Local System</td>
            </tr>`,
            )
            .join('')}
        </tbody>
      </table>
    </div>`;
  return mmcShell({
    consolePath: 'Console Root\\Services (Local)',
    treeHtml: tree,
    centerHtml: center,
    actionTitle: 'Services (Local)',
    actionButtons: [
      'Connect to another computer...',
      'Export List...',
      'New...',
      'All Tasks ▸',
      'View ▸',
      'Refresh',
      'Properties',
      'Help',
    ],
    status: `${rows.length} service(s)`,
  });
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
    .windows-tab.mmc-frame .topnavbar-tab { background: #6ec6e6; color: #0b3a4a; }
    .windows-tab.mmc-frame .nome-tab .title-ico { color: #a4262c; }
    .windows-tab.mmc-frame .top-left-menu-tab svg { color: #163e4f; }
    .mmc {
      height: 100%; display: grid;
      grid-template-rows: 22px 28px 24px 1fr 22px;
      font-family: "Segoe UI", Tahoma, sans-serif; font-size: 12px;
      background: #f0f0f0; color: #1a1a1a; border-top: 1px solid #9ecfe3;
    }
    .mmc-menubar {
      display: flex; gap: .15rem; padding: 0 .35rem; align-items: center;
      background: #f3f3f3; border-bottom: 1px solid #d0d0d0; color: #1b1b1b;
    }
    .mmc-menubar span { cursor: default; padding: .15rem .45rem; }
    .mmc-menubar span:hover { background: #e5f3ff; }
    .mmc-toolbar {
      display: flex; align-items: center; gap: .2rem; padding: .2rem .4rem;
      background: linear-gradient(#fbfbfb, #ebebeb); border-bottom: 1px solid #c8c8c8;
    }
    .mmc-tool {
      min-width: 24px; height: 22px; border: 1px solid transparent; background: transparent;
      font: inherit; color: #1b1b1b; padding: 0 .35rem; cursor: pointer;
    }
    .mmc-tool:hover:not(:disabled) { border-color: #7eb6d8; background: #e5f3ff; }
    .mmc-tool:disabled { opacity: .4; cursor: default; }
    .mmc-sep { width: 1px; height: 1.05rem; background: #c0c0c0; margin: 0 .25rem; }
    .mmc-path {
      padding: .2rem .55rem; background: #fff; border-bottom: 1px solid #c8c8c8;
      color: #333; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
    }
    .mmc-body {
      display: grid; grid-template-columns: 250px minmax(0, 1fr) 190px; min-height: 0; height: 100%;
      background: #fff;
    }
    .mmc-tree {
      background: #fff; border-right: 1px solid #c8c8c8; overflow: auto; padding: .25rem 0;
      user-select: none;
    }
    .mmc-node {
      display: flex; align-items: center; gap: .25rem; padding: .12rem .35rem .12rem calc(6px + var(--d) * 14px);
      white-space: nowrap; cursor: default; line-height: 1.35;
    }
    .mmc-node:hover { background: #e5f3ff; }
    .mmc-node.active { background: #cce8ff; }
    .mmc-node .twist {
      width: 12px; font-size: 9px; color: #555; text-align: center; flex: 0 0 12px;
    }
    .mmc-node .twist.empty { visibility: hidden; }
    .mmc-node .ico {
      width: 14px; height: 14px; flex: 0 0 14px; background: #6b6b6b; opacity: .85;
    }
    .mmc-node .ico.folder { clip-path: polygon(0 22%, 38% 22%, 48% 0, 100% 0, 100% 100%, 0 100%); background: #e8b84a; }
    .mmc-node .ico.console { background: #c50f1f; border-radius: 1px; }
    .mmc-node .ico.log { background: #5b9bd5; border-radius: 1px; }
    .mmc-node .ico.doc { background: #8a8a8a; clip-path: polygon(0 0, 70% 0, 100% 30%, 100% 100%, 0 100%); }
    .mmc-node .ico.gear {
      background: transparent; border: 2px solid #666; border-radius: 50%;
      box-shadow: inset 0 0 0 2px #f0f0f0;
    }
    .mmc-node .lbl { overflow: hidden; text-overflow: ellipsis; }
    .mmc-main { display: grid; grid-template-rows: 1fr 150px; min-width: 0; background: #fff; border-right: 1px solid #c8c8c8; }
    .mmc-list-fill { grid-row: 1 / -1; }
    .mmc-list-pane { overflow: auto; border-bottom: 1px solid #c8c8c8; }
    .mmc-table { width: 100%; border-collapse: collapse; font-size: 11.5px; }
    .mmc-table th {
      text-align: left; padding: .28rem .45rem; background: #f5f5f5;
      border-bottom: 1px solid #d0d0d0; border-right: 1px solid #e4e4e4; font-weight: 600; position: sticky; top: 0;
    }
    .mmc-table td { padding: .28rem .45rem; border-bottom: 1px solid #eee; border-right: 1px solid #f2f2f2; vertical-align: top; }
    .mmc-row { cursor: default; }
    .mmc-row:hover { background: #f5faff; }
    .mmc-row.selected { background: #cce8ff; }
    .mmc-row.fail td { color: #a61f24; }
    .mmc-row .lvl { color: #0078d4; margin-right: .2rem; }
    .mmc-row.fail .lvl { color: #a61f24; }
    .svc-ico {
      display: inline-block; width: 12px; height: 12px; margin-right: .35rem;
      border: 2px solid #666; border-radius: 50%; vertical-align: -1px;
    }
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
      background: #f7f7f7; overflow: auto; padding: 0 0 .35rem;
      display: flex; flex-direction: column;
    }
    .mmc-actions-title {
      font-weight: 700; padding: .35rem .55rem; border-bottom: 1px solid #ddd; background: #f0f0f0;
    }
    .mmc-actions-group {
      display: flex; align-items: center; justify-content: space-between; gap: .35rem;
      margin: .35rem .35rem .15rem; padding: .28rem .45rem;
      background: linear-gradient(#d7ebf8, #b7daf0); border: 1px solid #8eb9d6;
      font-weight: 600; color: #123;
    }
    .mmc-collapse {
      border: 0; background: transparent; cursor: pointer; font-size: 10px; color: #123; padding: 0;
    }
    .mmc-action {
      text-align: left; border: 0; background: transparent; padding: .28rem .65rem;
      font: inherit; color: #0563c1; cursor: pointer;
    }
    .mmc-action:hover { background: #e5f3ff; }
    .mmc-action.more { margin-top: .15rem; }
    .mmc-status {
      display: grid; grid-template-columns: 1.4fr 1fr 1fr; gap: 1px; background: #cfcfcf;
      border-top: 1px solid #bdbdbd; color: #333; font-size: 11px;
    }
    .mmc-status span { background: #f3f3f3; padding: .15rem .45rem; min-height: 18px; }
    .mmc-dash { padding: .85rem 1rem; display: block; overflow: auto; }
    .mmc-dash h3 { margin: 0 0 .75rem; font-size: 1.05rem; }
    .mmc-props { border-collapse: collapse; width: min(520px, 100%); }
    .mmc-props th, .mmc-props td { text-align: left; padding: .35rem .5rem; border-bottom: 1px solid #e2e2e2; }
    .mmc-props th { width: 40%; color: #555; font-weight: 600; }
    .windows-tab .tab-body.sm-body { background: #f0f0f0; color: #1a1a1a; overflow: hidden; }
    .sm {
      height: 100%; display: grid; grid-template-rows: 40px 1fr;
      font-family: "Segoe UI", Tahoma, sans-serif; font-size: 13px;
      background: #f0f0f0; color: #1b1b1b;
    }
    .sm-top {
      display: flex; align-items: center; justify-content: space-between; gap: .75rem;
      padding: 0 .75rem; background: #2b2b2b; color: #fff; border-bottom: 1px solid #1f1f1f;
    }
    .sm-top-left { display: flex; align-items: center; gap: .35rem; min-width: 0; }
    .sm-navbtn, .sm-iconbtn, .sm-link {
      border: 0; background: transparent; color: #fff; font: inherit; padding: .25rem .45rem; cursor: pointer;
    }
    .sm-navbtn:disabled { opacity: .35; cursor: default; }
    .sm-navbtn:hover:not(:disabled), .sm-iconbtn:hover, .sm-link:hover { background: rgba(255,255,255,.12); }
    .sm-crumb { display: flex; align-items: center; gap: .35rem; white-space: nowrap; overflow: hidden; }
    .sm-crumb .sep { opacity: .7; }
    .sm-top-actions { display: flex; align-items: center; gap: .15rem; }
    .sm-flag {
      position: relative; border: 0; background: transparent; color: #fff; padding: .2rem .45rem; cursor: pointer;
    }
    .sm-flag .flag { font-size: 14px; }
    .sm-flag .warn {
      position: absolute; right: 0; top: 0; font-size: 9px; color: #f0c000;
      background: #2b2b2b; border-radius: 50%;
    }
    .sm-shell { display: grid; grid-template-columns: 220px 1fr; min-height: 0; height: 100%; }
    .sm-nav {
      background: #fff; border-right: 1px solid #d4d4d4; overflow: auto;
      display: flex; flex-direction: column; padding: .35rem 0;
    }
    .sm-nav-item {
      display: flex; align-items: center; gap: .55rem; text-align: left; border: 0;
      background: transparent; color: #2b2b2b; font: inherit; padding: .55rem .75rem; cursor: pointer;
    }
    .sm-nav-item:hover { background: #e8e8e8; }
    .sm-nav-item.active { background: #0078d7; color: #fff; }
    .sm-nav-ico {
      width: 14px; height: 14px; flex: 0 0 14px; background: currentColor; opacity: .7;
    }
    .sm-nav-ico.dash { clip-path: polygon(0 0, 45% 0, 45% 45%, 0 45%, 0 55%, 45% 55%, 45% 100%, 0 100%, 0 55%, 55% 55%, 55% 100%, 100% 100%, 100% 55%, 55% 55%, 55% 45%, 100% 45%, 100% 0, 55% 0, 55% 45%, 0 45%); }
    .sm-nav-ico.server { border-radius: 1px; box-shadow: inset 0 -3px 0 rgba(255,255,255,.35), inset 0 3px 0 rgba(0,0,0,.15); }
    .sm-nav-ico.list {
      background: transparent; border-top: 2px solid currentColor; border-bottom: 2px solid currentColor;
      box-shadow: inset 0 6px 0 -4px currentColor;
    }
    .sm-nav-ico.folder { clip-path: polygon(0 20%, 35% 20%, 45% 0, 100% 0, 100% 100%, 0 100%); }
    .sm-nav-ico.rds { border: 2px solid currentColor; background: transparent; box-shadow: inset 3px 3px 0 currentColor; }
    .sm-content { overflow: auto; padding: .85rem 1rem 1.15rem; background: #f0f0f0; }
    .sm-section-head { margin-bottom: .75rem; }
    .sm-section-head h2 {
      margin: 0; font-size: 12px; font-weight: 700; letter-spacing: .04em; color: #5a5a5a;
    }
    .sm-section-head p { margin: .2rem 0 0; color: #666; font-size: 12px; }
    .sm-tile-grid {
      display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: .75rem;
    }
    .sm-tile {
      background: #fff; border: 1px solid #cfcfcf; display: grid;
      grid-template-rows: auto auto 1fr auto; min-height: 168px;
    }
    .sm-tile-head {
      display: grid; grid-template-columns: auto 1fr auto; align-items: center; gap: .45rem;
      padding: .4rem .55rem; background: #e8e8e8; color: #1b1b1b; font-weight: 600;
    }
    .sm-tile.critical .sm-tile-head { background: #c50f1f; color: #fff; }
    .sm-tile-ico {
      width: 16px; height: 16px; background: currentColor; opacity: .55;
      mask: linear-gradient(#000 0 0); border-radius: 1px;
    }
    .sm-tile-title { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .sm-tile-count { font-weight: 700; }
    .sm-tile-status {
      display: flex; align-items: center; gap: .45rem; padding: .4rem .55rem;
      border-bottom: 1px solid #e4e4e4; color: #333;
    }
    .sm-tile.healthy .sm-tile-status { border-top: 2px solid #107c10; }
    .sm-tile.critical .sm-tile-status { border-top: 2px solid #c50f1f; }
    .sm-badge {
      display: inline-grid; place-items: center; width: 18px; height: 18px;
      font-size: 11px; font-weight: 700; color: #fff;
    }
    .sm-badge.ok { background: #107c10; border-radius: 50%; font-size: 10px; }
    .sm-badge.err { background: #c50f1f; border-radius: 2px; }
    .sm-tile-links { list-style: none; margin: 0; padding: .35rem 0; }
    .sm-tile-links li {
      padding: .22rem .55rem; color: #2b2b2b; cursor: default;
    }
    .sm-tile-links li:hover { background: #e5f1fb; color: #0563c1; }
    .sm-tile-stamp {
      text-align: right; padding: .25rem .55rem .4rem; color: #8a8a8a; font-size: 11px;
    }
    .sm-props-grid.light {
      display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 0;
      border: 1px solid #cfcfcf; background: #fff; overflow: hidden;
    }
    .sm-props-grid.light .sm-prop {
      display: grid; grid-template-columns: 42% 1fr; gap: .5rem; padding: .45rem .65rem;
      border-bottom: 1px solid #e6e6e6; border-right: 1px solid #e6e6e6; background: #fff;
    }
    .sm-props-grid.light .sm-prop:nth-child(2n) { border-right: 0; }
    .sm-props-grid.light .sm-prop span { color: #666; }
    .sm-props-grid.light .sm-prop strong { font-weight: 600; color: #1b1b1b; }
    .sm-on { color: #107c10 !important; }
    .sm-warn { color: #c50f1f !important; }
    .sm-table.light { width: 100%; border-collapse: collapse; background: #fff; border: 1px solid #cfcfcf; }
    .sm-table.light th, .sm-table.light td { text-align: left; padding: .45rem .6rem; border-bottom: 1px solid #e6e6e6; }
    .sm-table.light th { background: #f3f3f3; color: #333; font-weight: 600; }
    .pill {
      display: inline-flex; padding: .1rem .45rem; border-radius: 0; font-size: 11px; font-weight: 600;
    }
    .pill.ok { background: #dff6dd; color: #0b6a0b; }
    .pill.warn { background: #fde7e9; color: #a4262c; }
    @media (max-width: 1100px) {
      .sm-tile-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    }
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
      events: 'Event Viewer - [Event Viewer (Local)\\Windows Logs\\Security]',
      services: 'Services - [Console Root\\Services (Local)]',
      server: 'Server Manager',
      ps: 'Administrator: Windows PowerShell',
    };

    const tab = document.createElement('div');
    tab.className = `windows-tab${kind === 'events' || kind === 'services' ? ' mmc-frame' : ''}`;
    tab.style.width = kind === 'events' ? '960px' : kind === 'server' ? '1080px' : kind === 'services' ? '900px' : kind === 'ps' ? '720px' : '560px';
    tab.style.height = kind === 'server' ? '680px' : kind === 'events' || kind === 'services' ? '580px' : kind === 'ps' ? '440px' : '360px';
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
    } else if (kind === 'services') {
      body.innerHTML = servicesHtml();
      wireMmcChrome(body);
    } else if (kind === 'events') {
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
