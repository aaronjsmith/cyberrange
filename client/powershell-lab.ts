import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import xtermCss from '@xterm/xterm/css/xterm.css?inline';

{
  const style = document.createElement('style');
  style.textContent = xtermCss;
  document.head.appendChild(style);
}

import {
  advanceStep,
  getBoot,
  normalizeCommand,
  readStore,
  writeStore,
  type LabBoot,
} from './lab-session';
import { lookupPowerShell } from './scenario/powershell';

function updateSidebar(boot: LabBoot): void {
  const steps = boot.steps;
  const done = boot.step >= steps.length;
  const view = steps[Math.min(boot.step, Math.max(steps.length - 1, 0))];
  const progress = done ? 100 : Math.round((boot.step / steps.length) * 100);

  const fill = document.getElementById('progress-fill');
  if (fill) fill.style.width = `${progress}%`;

  const count = document.getElementById('step-count');
  if (count) {
    count.textContent = done ? 'Lab complete' : `Step ${boot.step + 1} of ${steps.length}`;
  }

  const title = document.getElementById('step-title');
  if (title) {
    title.textContent = done ? 'Detect and document' : `Step ${boot.step + 1}: ${view.label}`;
  }

  const setText = (id: string, text: string) => {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
  };

  if (done) {
    setText('step-why', 'Guided path complete. Keep investigating in Free mode, or restart the attack.');
    setText('step-observe', 'Your notepad should include the attacker IP 203.0.113.45 and how you found it.');
    setText(
      'step-action',
      boot.attackActive
        ? 'Attack is still active.\nDo this now:\nstop-attack'
        : 'Optional: start-attack again, or switch to Free mode.',
    );
  } else {
    setText('step-why', view.why);
    setText('step-observe', view.observe);
    setText('step-action', view.action);
  }

  const status = document.getElementById('status-slot');
  if (status) {
    if (boot.attackActive) {
      status.innerHTML = '<span class="sb sb-a">ATTACK ACTIVE</span>';
    } else if (boot.baselineEstablished) {
      status.innerHTML = '<span class="sb sb-b">BASELINE OK</span>';
    } else {
      status.innerHTML = '<span class="tag">Establish Baseline</span>';
    }
  }

  const stopBtn = document.getElementById('stop-attack') as HTMLButtonElement | null;
  if (stopBtn) stopBtn.style.display = boot.attackActive ? 'inline-flex' : 'none';

  const prev = document.getElementById('prev') as HTMLButtonElement | null;
  if (prev) prev.style.display = boot.step > 0 ? 'inline-flex' : 'none';

  const modeKicker = document.getElementById('mode-kicker');
  if (modeKicker) modeKicker.textContent = boot.mode === 'free' ? 'Free Mode' : 'Learning Mode';
}

function syncUrl(boot: LabBoot): void {
  const params = new URLSearchParams({
    mode: boot.mode,
    step: String(boot.step),
    shellType: boot.shellType,
    attack: boot.attackActive ? 'true' : 'false',
    baseline: boot.baselineEstablished ? 'true' : 'false',
  });
  history.replaceState(null, '', `${boot.base}/labs/${boot.labId}?${params.toString()}`);
}

function persist(boot: LabBoot, history: string[], observations: string): void {
  writeStore(boot.labId, {
    step: boot.step,
    mode: boot.mode,
    shellType: boot.shellType,
    attackActive: boot.attackActive,
    baselineEstablished: boot.baselineEstablished,
    commandHistory: history.slice(-200),
    observations,
  });
}

async function main(): Promise<void> {
  const boot = getBoot();
  boot.shellType = 'powershell';
  const stored = readStore(boot.labId);
  const params = new URLSearchParams(location.search);
  const explicit =
    params.has('step') ||
    params.has('mode') ||
    params.has('shellType') ||
    params.has('attack') ||
    params.has('baseline');

  if (stored && !explicit) {
    if (typeof stored.step === 'number') boot.step = stored.step;
    if (stored.mode === 'learning' || stored.mode === 'free') boot.mode = stored.mode;
    if (typeof stored.attackActive === 'boolean') boot.attackActive = stored.attackActive;
    if (typeof stored.baselineEstablished === 'boolean') {
      boot.baselineEstablished = stored.baselineEstablished;
    }
  }

  const notes = document.getElementById('obs-notes') as HTMLTextAreaElement | null;
  if (notes && stored?.observations) notes.value = stored.observations;

  const mount = document.getElementById('term');
  if (!mount) throw new Error('#term mount missing');

  const term = new Terminal({
    cursorBlink: true,
    fontFamily: 'Consolas, "IBM Plex Mono", monospace',
    fontSize: 13,
    theme: {
      background: '#012456',
      foreground: '#f3f3f3',
      cursor: '#f3f3f3',
      selectionBackground: '#264f78',
    },
  });
  const fit = new FitAddon();
  term.loadAddon(fit);
  term.open(mount);
  fit.fit();
  window.addEventListener('resize', () => fit.fit());

  let history: string[] = Array.isArray(stored?.commandHistory) ? stored!.commandHistory! : [];
  let line = '';
  const prompt = 'PS C:\\Users\\blueteam-user> ';

  const writeln = (text: string) => {
    for (const row of text.replace(/\r\n/g, '\n').split('\n')) {
      if (row === '' && text.endsWith('\n')) continue;
      term.writeln(row);
    }
  };

  const showPrompt = () => {
    term.write(`\r\n\x1b[36m${prompt}\x1b[0m`);
  };

  term.writeln('Windows PowerShell — Cyberrange simulation (xterm)');
  term.writeln('Type help, then whoami / hostname / Get-Date. Use baseline → start-attack → stop-attack.');
  updateSidebar(boot);
  showPrompt();
  term.focus();

  const execute = (raw: string) => {
    const cmd = normalizeCommand(raw);
    if (!cmd) {
      showPrompt();
      return;
    }
    history.push(cmd);

    if (cmd === 'Clear-Host' || cmd === 'cls' || cmd === 'clear') {
      term.clear();
      showPrompt();
      return;
    }

    if (cmd.startsWith('shell-type ')) {
      const next = cmd.slice('shell-type '.length);
      if (next === 'bash' || next === 'powershell') {
        const q = new URLSearchParams({
          mode: boot.mode,
          step: String(boot.step),
          shellType: next,
          attack: String(boot.attackActive),
          baseline: String(boot.baselineEstablished),
        });
        location.href = `${boot.base}/labs/${boot.labId}?${q.toString()}`;
        return;
      }
      writeln(`Unknown shell type: ${next}. Use 'bash' or 'powershell'.`);
      showPrompt();
      return;
    }

    if (cmd === 'baseline') {
      boot.baselineEstablished = true;
      writeln(lookupPowerShell('baseline', false) || '');
    } else if (cmd === 'start-attack') {
      if (!boot.baselineEstablished) {
        writeln('Establish a baseline first (type: baseline).');
      } else {
        boot.attackActive = true;
        writeln(lookupPowerShell('start-attack', true) || '');
      }
    } else if (cmd === 'stop-attack') {
      boot.attackActive = false;
      writeln(lookupPowerShell('stop-attack', false) || '');
    } else {
      const out = lookupPowerShell(cmd, boot.attackActive);
      if (out == null) {
        writeln(`Command not recognized in this simulation: ${cmd}`);
        writeln('Type help for available commands.');
      } else {
        writeln(out);
      }
    }

    if (boot.mode === 'learning') {
      const adv = advanceStep(boot.steps, boot.step, history, cmd);
      boot.step = adv.step;
      if (adv.note) writeln(`\x1b[33m${adv.note}\x1b[0m`);
    }

    updateSidebar(boot);
    syncUrl(boot);
    persist(boot, history, notes?.value || '');
    showPrompt();
  };

  term.onData((data) => {
    if (data === '\r') {
      term.write('\r\n');
      const current = line;
      line = '';
      execute(current);
      return;
    }
    if (data === '\u007f') {
      if (line.length) {
        line = line.slice(0, -1);
        term.write('\b \b');
      }
      return;
    }
    if (data === '\u0003') {
      term.write('^C');
      line = '';
      showPrompt();
      return;
    }
    if (data.length === 1 && data >= ' ') {
      line += data;
      term.write(data);
    }
  });

  document.getElementById('stop-attack')?.addEventListener('click', () => execute('stop-attack'));
  document.getElementById('prev')?.addEventListener('click', () => {
    boot.step = Math.max(0, boot.step - 1);
    updateSidebar(boot);
    syncUrl(boot);
    persist(boot, history, notes?.value || '');
  });
  notes?.addEventListener('input', () => persist(boot, history, notes.value));

  (window as unknown as { setMode: (m: string) => void }).setMode = (mode: string) => {
    boot.mode = mode === 'free' ? 'free' : 'learning';
    syncUrl(boot);
    location.reload();
  };
  (window as unknown as { setShellType: (s: string) => void }).setShellType = (shell: string) => {
    execute(`shell-type ${shell}`);
  };
  (window as unknown as { resetSession: () => void }).resetSession = () => {
    if (confirm('Reset this lab session? All command history and progress will be cleared.')) {
      localStorage.removeItem(`cyberrange-session-${boot.labId}`);
      location.href = `${boot.base}/labs/${boot.labId}`;
    }
  };
  (window as unknown as { prevStep: () => void }).prevStep = () => {
    document.getElementById('prev')?.click();
  };
  (window as unknown as { stopAttack: () => void }).stopAttack = () => execute('stop-attack');
}

void main();
