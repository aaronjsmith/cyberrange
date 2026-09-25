export type ShellMode = 'learning' | 'free';
export type ShellType = 'bash' | 'powershell';

export interface LearningStep {
  label: string;
  why: string;
  observe: string;
  action: string;
  accept: string[];
  requireAll?: boolean;
}

export interface LabBoot {
  base: string;
  labId: string;
  step: number;
  mode: ShellMode;
  shellType: ShellType;
  attackActive: boolean;
  baselineEstablished: boolean;
  steps: LearningStep[];
}

declare global {
  interface Window {
    __LAB_BOOT__?: LabBoot;
  }
}

export function getBoot(): LabBoot {
  const boot = window.__LAB_BOOT__;
  if (!boot) {
    throw new Error('Missing window.__LAB_BOOT__');
  }
  return boot;
}

export function appPath(base: string, path: string): string {
  if (path === '/' || path === '') return base || '/';
  const normalized = path.startsWith('/') ? path : `/${path}`;
  return `${base}${normalized}`;
}

export function normalizeCommand(command: string): string {
  return command.trim().replace(/\s+/g, ' ');
}

export function storageKey(labId: string): string {
  return `cyberrange-session-${labId}`;
}

export interface SessionStore {
  transcript?: Array<{ command: string; output?: string; note?: string; error?: string }>;
  step?: number;
  mode?: ShellMode;
  shellType?: ShellType;
  attackActive?: boolean;
  baselineEstablished?: boolean;
  observations?: string;
  commandHistory?: string[];
}

export function readStore(labId: string): SessionStore | null {
  try {
    return JSON.parse(localStorage.getItem(storageKey(labId)) || 'null');
  } catch {
    return null;
  }
}

export function writeStore(labId: string, data: SessionStore): void {
  try {
    localStorage.setItem(storageKey(labId), JSON.stringify(data));
  } catch {
    /* ignore quota */
  }
}

export function advanceStep(
  steps: LearningStep[],
  currentStep: number,
  history: string[],
  command: string,
): { step: number; changed: boolean; note: string | null } {
  if (currentStep >= steps.length) {
    return { step: currentStep, changed: false, note: null };
  }
  const step = steps[currentStep];
  const cmd = normalizeCommand(command);
  const matched = step.accept.some((a) => normalizeCommand(a) === cmd);
  if (!matched) {
    return { step: currentStep, changed: false, note: null };
  }

  if (step.requireAll) {
    const needed = step.accept.map(normalizeCommand);
    const have = new Set(history.map(normalizeCommand));
    have.add(cmd);
    const allDone = needed.every((n) => have.has(n));
    if (!allDone) {
      const remaining = needed.filter((n) => !have.has(n));
      return {
        step: currentStep,
        changed: false,
        note: `Progress: still need ${remaining.join(', ')}`,
      };
    }
  }

  const next = currentStep + 1;
  return {
    step: next,
    changed: true,
    note: next >= steps.length ? 'Lab complete — switch to Free mode or keep investigating.' : null,
  };
}

export async function postCommand(
  base: string,
  labId: string,
  body: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const response = await fetch(appPath(base, `/api/labs/${labId}/command`), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const data = (await response.json()) as Record<string, unknown>;
  if (!response.ok) {
    throw new Error(typeof data.error === 'string' ? data.error : 'Request failed');
  }
  return data;
}
