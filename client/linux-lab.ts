import { Bash, defineCommand } from 'just-bash/browser';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import '@xterm/xterm/css/xterm.css';

import {
  advanceStep,
  getBoot,
  normalizeCommand,
  readStore,
  writeStore,
  type LabBoot,
} from './lab-session';
import {
  ATTACK_AUTH_LOG,
  BASH_LAB_NOTES,
  HOME,
  HOST,
  NETSTAT,
  PS_AUX,
  PS_AUX_ATTACK,
  QUIET_AUTH_LOG,
  USER,
  buildLinuxFiles,
  topOutput,
} from './scenario/linux';

function formatPrompt(cwd: string): string {
  let shown = cwd || HOME;
  if (shown === HOME) shown = '~';
  else if (shown.startsWith(`${HOME}/`)) shown = `~${shown.slice(HOME.length)}`;
  return `${USER}@cyberrange:${shown}$ `;
}

function createBash(attackActive: boolean): Bash {
  let attack = attackActive;

  const ps = defineCommand('ps', async (args) => {
    const joined = args.join(' ');
    if (joined.includes('aux') || args.length === 0) {
      return { stdout: `${attack ? PS_AUX_ATTACK : PS_AUX}\n`, stderr: '', exitCode: 0 };
    }
    return { stdout: `${attack ? PS_AUX_ATTACK : PS_AUX}\n`, stderr: '', exitCode: 0 };
  });

  const netstat = defineCommand('netstat', async () => ({
    stdout: `${NETSTAT}\n`,
    stderr: '',
    exitCode: 0,
  }));

  const ss = defineCommand('ss', async () => ({
    stdout: `${NETSTAT}\n`,
    stderr: '',
    exitCode: 0,
  }));

  const top = defineCommand('top', async () => ({
    stdout: `${topOutput(attack)}\n`,
    stderr: '',
    exitCode: 0,
  }));

  const bash = new Bash({
    files: buildLinuxFiles(attackActive),
    cwd: HOME,
    env: {
      HOME,
      USER,
      LOGNAME: USER,
      HOSTNAME: HOST,
      PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
    },
    customCommands: [ps, netstat, ss, top],
  });

  (bash as Bash & { __setAttack?: (v: boolean) => void }).__setAttack = (v: boolean) => {
    attack = v;
  };

  return bash;
}

async function writeAuthLog(bash: Bash, attackActive: boolean): Promise<void> {
  const content = attackActive ? ATTACK_AUTH_LOG : QUIET_AUTH_LOG;
  await bash.exec(`cat > /var/log/auth.log << 'EOF'\n${content}\nEOF`);
}

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
  const url = `${boot.base}/labs/${boot.labId}?${params.toString()}`;
  history.replaceState(null, '', url);
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
      background: '#0a0a0a',
      foreground: '#d4d4d4',
      cursor: '#4ade80',
      selectionBackground: '#264f78',
    },
  });
  const fit = new FitAddon();
  term.loadAddon(fit);
  term.open(mount);
  fit.fit();
  window.addEventListener('resize', () => fit.fit());

  let bash = createBash(boot.attackActive);
  let cwd = HOME;
  let history: string[] = Array.isArray(stored?.commandHistory) ? stored!.commandHistory! : [];
  let line = '';
  let browsing = -1;
  let draft = '';

  const prompt = () => formatPrompt(cwd);

  const writeln = (text: string) => {
    const lines = text.replace(/\r\n/g, '\n').split('\n');
    for (let i = 0; i < lines.length; i++) {
      if (i === lines.length - 1 && lines[i] === '') continue;
      term.writeln(lines[i]);
    }
  };

  const showPrompt = () => {
    term.write(`\r\n\x1b[32m${prompt()}\x1b[0m`);
  };

  term.writeln('Linux Terminal (just-bash + xterm). Type help, then try ls, cd, pwd, and cat.');
  updateSidebar(boot);
  showPrompt();
  term.focus();

  const rebuildBash = async () => {
    bash = createBash(boot.attackActive);
    await writeAuthLog(bash, boot.attackActive);
    const setter = (bash as Bash & { __setAttack?: (v: boolean) => void }).__setAttack;
    setter?.(boot.attackActive);
  };

  const runSpecial = async (cmd: string): Promise<string | null> => {
    if (cmd === 'baseline') {
      boot.baselineEstablished = true;
      return BASH_LAB_NOTES.baseline;
    }
    if (cmd === 'start-attack') {
      if (!boot.baselineEstablished) {
        return 'Establish a baseline first (type: baseline).';
      }
      boot.attackActive = true;
      await rebuildBash();
      return BASH_LAB_NOTES['start-attack'];
    }
    if (cmd === 'stop-attack') {
      boot.attackActive = false;
      await rebuildBash();
      return BASH_LAB_NOTES['stop-attack'];
    }
    if (cmd === 'lab-info') return BASH_LAB_NOTES['lab-info'];
    if (cmd === 'clear' || cmd === 'Clear-Host' || cmd === 'cls') {
      term.clear();
      return '';
    }
    if (cmd.startsWith('shell-type ')) {
      const next = cmd.slice('shell-type '.length);
      if (next === 'powershell' || next === 'bash') {
        const params = new URLSearchParams({
          mode: boot.mode,
          step: String(boot.step),
          shellType: next,
          attack: String(boot.attackActive),
          baseline: String(boot.baselineEstablished),
        });
        location.href = `${boot.base}/labs/${boot.labId}?${params.toString()}`;
        return null;
      }
      return `Unknown shell type: ${next}. Use 'bash' or 'powershell'.`;
    }
    return null;
  };

  const execute = async (raw: string) => {
    const cmd = normalizeCommand(raw);
    if (!cmd) {
      showPrompt();
      return;
    }

    history.push(cmd);
    browsing = -1;

    const special = await runSpecial(cmd);
    if (special !== null) {
      if (special) writeln(special);
    } else {
      try {
        const result = await bash.exec(cmd);
        if (result.stdout) writeln(result.stdout.replace(/\n$/, ''));
        if (result.stderr) writeln(`\x1b[31m${result.stderr.replace(/\n$/, '')}\x1b[0m`);
        // Refresh cwd from a pwd exec
        const pwd = await bash.exec('pwd');
        cwd = (pwd.stdout || HOME).trim() || HOME;
      } catch (err) {
        writeln(`\x1b[31m${err instanceof Error ? err.message : String(err)}\x1b[0m`);
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
    for (const ch of data) {
      if (ch === '\r') {
        term.write('\r\n');
        const current = line;
        line = '';
        void execute(current);
        continue;
      }
      if (ch === '\u007f') {
        if (line.length > 0) {
          line = line.slice(0, -1);
          term.write('\b \b');
        }
        continue;
      }
      if (ch === '\u0003') {
        term.write('^C');
        line = '';
        showPrompt();
        continue;
      }
      if (ch === '\u001b') {
        // ignore bare esc
        continue;
      }
      // arrow up/down: ESC [ A / B
      if (data.includes('\u001b[A')) {
        if (history.length === 0) return;
        if (browsing === -1) draft = line;
        browsing = browsing === -1 ? history.length - 1 : Math.max(0, browsing - 1);
        while (line.length) {
          line = line.slice(0, -1);
          term.write('\b \b');
        }
        line = history[browsing] || '';
        term.write(line);
        return;
      }
      if (data.includes('\u001b[B')) {
        if (browsing === -1) return;
        browsing += 1;
        while (line.length) {
          line = line.slice(0, -1);
          term.write('\b \b');
        }
        if (browsing >= history.length) {
          browsing = -1;
          line = draft;
        } else {
          line = history[browsing] || '';
        }
        term.write(line);
        return;
      }
      if (ch >= ' ' || ch === '\t') {
        line += ch;
        term.write(ch);
      }
    }
  });

  document.getElementById('stop-attack')?.addEventListener('click', () => {
    void execute('stop-attack');
  });

  document.getElementById('prev')?.addEventListener('click', () => {
    boot.step = Math.max(0, boot.step - 1);
    updateSidebar(boot);
    syncUrl(boot);
    persist(boot, history, notes?.value || '');
  });

  notes?.addEventListener('input', () => {
    persist(boot, history, notes.value);
  });

  (window as unknown as { setMode: (m: string) => void }).setMode = (mode: string) => {
    boot.mode = mode === 'free' ? 'free' : 'learning';
    syncUrl(boot);
    location.reload();
  };

  (window as unknown as { setShellType: (s: string) => void }).setShellType = (shell: string) => {
    void execute(`shell-type ${shell}`);
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

  (window as unknown as { stopAttack: () => void }).stopAttack = () => {
    void execute('stop-attack');
  };
}

void main();
