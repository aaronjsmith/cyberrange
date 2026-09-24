/**
 * In-memory Linux-like bash environment for the cyberrange lab.
 * Filesystem and cwd are session-owned and returned to the client after each command.
 */

export type FsNode =
  | { type: 'dir'; children: Record<string, FsNode> }
  | { type: 'file'; content: string };

export interface BashSession {
  cwd: string;
  filesystem: FsNode;
  history: string[];
}

export interface BashExecResult {
  output: string;
  error: string | null;
  cwd: string;
  filesystem: FsNode;
  clear?: boolean;
}

const HOME = '/home/blueteam-user';
const HOST = 'cyberrange-training-01';
const USER = 'blueteam-user';

const QUIET_AUTH_LOG = `Sep 23 19:40:01 ${HOST} sshd[12001]: Accepted password for blueteam-user from 192.168.1.100 port 51234 ssh2
Sep 23 19:41:12 ${HOST} CRON[12010]: (root) CMD (cd / && run-parts --report /etc/cron.hourly)
Sep 23 19:42:03 ${HOST} systemd[1]: Started Session 42 of user blueteam-user.
Sep 23 19:43:44 ${HOST} sshd[12100]: Accepted publickey for blueteam-user from 192.168.1.55 port 49821 ssh2
Sep 23 19:45:01 ${HOST} sshd[12345]: Accepted password for blueteam-user from 192.168.1.100 port 51302 ssh2
[NORMAL] No failed attempts`;

const ATTACK_AUTH_LOG = `Sep 23 19:45:01 ${HOST} sshd[12345]: Accepted password for blueteam-user from 192.168.1.100 port 51302 ssh2
Sep 23 19:46:01 ${HOST} sshd[54321]: Failed password for blueteam-user from 203.0.113.45 port 22 ssh2
Sep 23 19:46:02 ${HOST} sshd[54322]: Failed password for root from 203.0.113.45 port 22 ssh2
Sep 23 19:46:03 ${HOST} sshd[54323]: Failed password for admin from 203.0.113.45 port 22 ssh2
Sep 23 19:46:04 ${HOST} sshd[54324]: Failed password for invalid user oracle from 203.0.113.45 port 22 ssh2
Sep 23 19:46:05 ${HOST} sshd[54325]: Failed password for blueteam-user from 203.0.113.45 port 22 ssh2
Sep 23 19:46:06 ${HOST} sshd[54326]: Failed password for root from 203.0.113.45 port 22 ssh2
[ALERT] Brute force SSH from 203.0.113.45`;

const NETSTAT = `Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN
tcp6       0      0 :::22                   :::*                    LISTEN`;

const IFCONFIG = `eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.50  netmask 255.255.255.0  broadcast 192.168.1.255
        inet6 fe80::a00:27ff:fe4e:66a1  prefixlen 64  scopeid 0x20<link>
        ether 08:00:27:4e:66:a1  txqueuelen 1000  (Ethernet)
lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>`;

interface HostMetrics {
  now: string;
  uptimeHuman: string;
  users: number;
  load1: string;
  load5: string;
  load15: string;
  tasksTotal: number;
  tasksRunning: number;
  tasksSleeping: number;
  tasksStopped: number;
  tasksZombie: number;
  cpuUser: string;
  cpuSystem: string;
  cpuNice: string;
  cpuIdle: string;
  cpuWait: string;
  cpuHard: string;
  cpuSoft: string;
  cpuSteal: string;
  memTotalMiB: string;
  memFreeMiB: string;
  memUsedMiB: string;
  memBuffCacheMiB: string;
  memAvailableMiB: string;
  swapTotalMiB: string;
  swapFreeMiB: string;
  swapUsedMiB: string;
  memTotalKb: number;
  memUsedKb: number;
  memFreeKb: number;
  memSharedKb: number;
  memBuffCacheKb: number;
  memAvailableKb: number;
  swapTotalKb: number;
  swapUsedKb: number;
  swapFreeKb: number;
  diskTotal: number;
  diskUsed: number;
  diskAvail: number;
  diskUsePct: number;
}

const pad = (value: string | number, width: number): string => String(value).padStart(width, ' ');

const jitter = (seed: number, min: number, max: number): number => {
  const span = max - min;
  const unit = Math.abs(Math.sin(seed) * 10000) % 1;
  return min + unit * span;
};

const formatLoad = (n: number): string => n.toFixed(2);

const buildHostMetrics = (attackActive = false): HostMetrics => {
  const now = new Date();
  const seed = Math.floor(now.getTime() / 15000); // mild drift every ~15s
  const loadBase = attackActive ? 0.85 : 0.12;
  const load1 = formatLoad(loadBase + jitter(seed, 0.01, 0.18));
  const load5 = formatLoad(loadBase * 0.9 + jitter(seed + 1, 0.02, 0.14));
  const load15 = formatLoad(loadBase * 0.75 + jitter(seed + 2, 0.01, 0.1));

  const cpuUser = attackActive ? 12.4 + jitter(seed, 0, 4) : 1.8 + jitter(seed, 0, 1.4);
  const cpuSystem = attackActive ? 4.1 + jitter(seed, 0, 1.5) : 0.6 + jitter(seed, 0, 0.5);
  const cpuNice = 0.0;
  const cpuWait = attackActive ? 0.8 + jitter(seed, 0, 0.4) : 0.2 + jitter(seed, 0, 0.2);
  const cpuHard = 0.0;
  const cpuSoft = attackActive ? 0.3 : 0.1;
  const cpuSteal = 0.0;
  const cpuIdle = Math.max(0, 100 - cpuUser - cpuSystem - cpuNice - cpuWait - cpuHard - cpuSoft - cpuSteal);

  const memTotalKb = 8042124;
  const memUsedKb = attackActive ? 2688440 : 2214552;
  const memSharedKb = 142088;
  const memBuffCacheKb = attackActive ? 3688120 : 4110440;
  const memFreeKb = memTotalKb - memUsedKb - Math.floor(memBuffCacheKb * 0.35);
  const memAvailableKb = attackActive ? 4488120 : 5120440;
  const swapTotalKb = 2097148;
  const swapUsedKb = attackActive ? 124 : 0;
  const swapFreeKb = swapTotalKb - swapUsedKb;

  const toMiB = (kb: number) => (kb / 1024).toFixed(1);

  const tasksTotal = attackActive ? 138 : 124;
  const tasksRunning = attackActive ? 3 : 1;
  const tasksStopped = 0;
  const tasksZombie = 0;
  const tasksSleeping = tasksTotal - tasksRunning - tasksStopped - tasksZombie;

  const diskTotal = 30830592;
  const diskUsed = 8120344;
  const diskAvail = 21094084;

  const upHours = 4;
  const upMins = 17 + Math.floor(jitter(seed, 0, 3));

  return {
    now: now.toTimeString().slice(0, 8),
    uptimeHuman: `${upHours}:${String(upMins).padStart(2, '0')}`,
    users: 1,
    load1,
    load5,
    load15,
    tasksTotal,
    tasksRunning,
    tasksSleeping,
    tasksStopped,
    tasksZombie,
    cpuUser: cpuUser.toFixed(1),
    cpuSystem: cpuSystem.toFixed(1),
    cpuNice: cpuNice.toFixed(1),
    cpuIdle: cpuIdle.toFixed(1),
    cpuWait: cpuWait.toFixed(1),
    cpuHard: cpuHard.toFixed(1),
    cpuSoft: cpuSoft.toFixed(1),
    cpuSteal: cpuSteal.toFixed(1),
    memTotalMiB: toMiB(memTotalKb),
    memFreeMiB: toMiB(Math.max(memFreeKb, 0)),
    memUsedMiB: toMiB(memUsedKb),
    memBuffCacheMiB: toMiB(memBuffCacheKb),
    memAvailableMiB: toMiB(memAvailableKb),
    swapTotalMiB: toMiB(swapTotalKb),
    swapFreeMiB: toMiB(swapFreeKb),
    swapUsedMiB: toMiB(swapUsedKb),
    memTotalKb,
    memUsedKb,
    memFreeKb: Math.max(memFreeKb, 0),
    memSharedKb,
    memBuffCacheKb,
    memAvailableKb,
    swapTotalKb,
    swapUsedKb,
    swapFreeKb,
    diskTotal,
    diskUsed,
    diskAvail,
    diskUsePct: 28,
  };
};

const formatTop = (attackActive = false): string => {
  const m = buildHostMetrics(attackActive);
  const sshCpu = attackActive ? '18.7' : '0.3';
  const sshMem = attackActive ? '0.4' : '0.2';
  const mysqlCpu = attackActive ? '2.1' : '1.4';
  const header = [
    `top - ${m.now} up ${m.uptimeHuman},  ${m.users} user,  load average: ${m.load1}, ${m.load5}, ${m.load15}`,
    `Tasks: ${pad(m.tasksTotal, 3)} total, ${pad(m.tasksRunning, 3)} running, ${pad(m.tasksSleeping, 3)} sleeping, ${pad(m.tasksStopped, 3)} stopped, ${pad(m.tasksZombie, 3)} zombie`,
    `%Cpu(s):  ${pad(m.cpuUser, 4)} us,  ${pad(m.cpuSystem, 4)} sy,  ${pad(m.cpuNice, 4)} ni,  ${pad(m.cpuIdle, 4)} id,  ${pad(m.cpuWait, 4)} wa,  ${pad(m.cpuHard, 4)} hi,  ${pad(m.cpuSoft, 4)} si,  ${pad(m.cpuSteal, 4)} st`,
    `MiB Mem : ${pad(m.memTotalMiB, 8)} total, ${pad(m.memFreeMiB, 8)} free, ${pad(m.memUsedMiB, 8)} used, ${pad(m.memBuffCacheMiB, 8)} buff/cache`,
    `MiB Swap: ${pad(m.swapTotalMiB, 8)} total, ${pad(m.swapFreeMiB, 8)} free, ${pad(m.swapUsedMiB, 8)} used. ${pad(m.memAvailableMiB, 8)} avail Mem`,
    '',
    `  PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND`,
    `    1 root      20   0  169448   9844   6680 S   0.0   0.1   0:04.82 systemd`,
    `  112 root      20   0   62188   7324   4988 S   0.0   0.1   0:00.41 systemd-journal`,
    `  198 root      20   0   28964   3420   2888 S   0.0   0.0   0:00.12 systemd-udevd`,
    `  401 root      20   0   16384   2140   1880 S   0.0   0.0   0:00.03 cron`,
    `  512 systemd+  20   0   26912   5488   4212 S   0.0   0.1   0:00.18 systemd-resolve`,
    `  640 message+  20   0    9376   3724   3120 S   0.0   0.0   0:00.27 dbus-daemon`,
    `  788 root      20   0  217492  11240   8420 S   ${sshCpu}   ${sshMem}   0:03.41 sshd`,
    `  912 mysql     20   0 1854320 214328  18440 S   ${mysqlCpu}   2.7   1:18.55 mysqld`,
    ` 1024 root      20   0   15420   4216   3520 S   0.0   0.1   0:00.09 nginx`,
    ` 1025 www-data  20   0   15888   2864   1988 S   0.0   0.0   0:00.02 nginx`,
    ` 1188 root      20   0       0      0      0 I   0.0   0.0   0:00.14 kworker/0:1-events`,
    ` 1234 bluetea+  20   0   21456   5124   3420 S   0.3   0.1   0:00.18 bash`,
    ` 1456 bluetea+  20   0   42880   3988   3204 R   0.7   0.0   0:00.03 top`,
  ];

  if (attackActive) {
    header.splice(14, 0, ` 5432 sshd      20   0  121884   8920   6104 R  24.5   0.1   0:01.88 sshd`);
    header.splice(15, 0, ` 5433 sshd      20   0  121884   8744   5980 R  19.2   0.1   0:01.44 sshd`);
  }

  return header.join('\n');
};

const formatPsAux = (attackActive = false): string => {
  const mysqlCpu = attackActive ? '2.1' : '0.4';
  const sshCpu = attackActive ? '6.8' : '0.0';
  const lines = [
    'USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND',
    'root           1  0.0  0.1 169448  9844 ?        Ss   08:00   0:04 /sbin/init',
    'root         112  0.0  0.1  62188  7324 ?        Ss   08:00   0:00 /lib/systemd/systemd-journald',
    'root         198  0.0  0.0  28964  3420 ?        Ss   08:00   0:00 /lib/systemd/systemd-udevd',
    'systemd+     512  0.0  0.1  26912  5488 ?        Ss   08:00   0:00 /lib/systemd/systemd-resolved',
    'message+     640  0.0  0.0   9376  3724 ?        Ss   08:00   0:00 /usr/bin/dbus-daemon --system',
    `root         788  ${sshCpu}  0.1 217492 11240 ?        Ss   08:00   0:03 /usr/sbin/sshd -D`,
    `mysql        912  ${mysqlCpu}  2.7 1854320 214328 ?      Ssl  08:00   1:18 /usr/sbin/mysqld`,
    'root        1024  0.0  0.1  15420  4216 ?        Ss   08:01   0:00 nginx: master process /usr/sbin/nginx',
    'www-data    1025  0.0  0.0  15888  2864 ?        S    08:01   0:00 nginx: worker process',
    'root        1102  0.0  0.0  16384  2140 ?        Ss   08:00   0:00 /usr/sbin/cron -f',
    'blueteam    1234  0.0  0.1  21456  5124 pts/0    Ss   09:15   0:00 -bash',
    'blueteam    1488  0.0  0.0  21456  3200 pts/0    R+   09:42   0:00 ps aux',
  ];
  if (attackActive) {
    lines.splice(7, 0, 'sshd        5432 12.4  0.1 121884  8920 ?        R    09:46   0:01 sshd: [accepted]');
    lines.splice(8, 0, 'sshd        5433  9.8  0.1 121884  8744 ?        R    09:46   0:01 sshd: [accepted]');
  }
  return lines.join('\n');
};

const formatFree = (attackActive = false): string => {
  const m = buildHostMetrics(attackActive);
  return [
    '               total        used        free      shared  buff/cache   available',
    `Mem:        ${pad(m.memTotalKb, 8)}    ${pad(m.memUsedKb, 8)}    ${pad(m.memFreeKb, 8)}    ${pad(m.memSharedKb, 8)}    ${pad(m.memBuffCacheKb, 8)}    ${pad(m.memAvailableKb, 8)}`,
    `Swap:       ${pad(m.swapTotalKb, 8)}    ${pad(m.swapUsedKb, 8)}    ${pad(m.swapFreeKb, 8)}`,
  ].join('\n');
};

const formatUptime = (attackActive = false): string => {
  const m = buildHostMetrics(attackActive);
  return ` ${m.now} up ${m.uptimeHuman},  ${m.users} user,  load average: ${m.load1}, ${m.load5}, ${m.load15}`;
};

const formatDf = (): string => {
  const m = buildHostMetrics(false);
  return [
    'Filesystem     1K-blocks    Used Available Use% Mounted on',
    `/dev/vda1      ${pad(m.diskTotal, 9)} ${pad(m.diskUsed, 7)}  ${pad(m.diskAvail, 8)}  ${m.diskUsePct}% /`,
    `tmpfs            4021060        0   4021060   0% /dev/shm`,
    `tmpfs             804212     1184    803028   1% /run`,
    `tmpfs               5120        0      5120   0% /run/lock`,
  ].join('\n');
};

const dir = (children: Record<string, FsNode> = {}): FsNode => ({ type: 'dir', children });
const file = (content: string): FsNode => ({ type: 'file', content });

export const createDefaultFilesystem = (attackActive = false): FsNode =>
  dir({
    home: dir({
      'blueteam-user': dir({
        Desktop: dir({}),
        Documents: dir({
          'notes.txt': file('Blue team notes\n- Establish baseline before investigating alerts\n- Watch /var/log/auth.log for SSH failures\n'),
          'incident-checklist.md': file('# Incident Checklist\n1. Identify host\n2. Capture process and port baseline\n3. Review auth logs\n4. Document findings\n'),
        }),
        Downloads: dir({}),
        '.bashrc': file('# ~/.bashrc\nexport PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nexport PS1="\\u@\\h:\\w\\$ "\n'),
        '.bash_history': file('whoami\nhostname\npwd\nls\n'),
        'README.txt': file('Welcome to the Cyberrange Linux lab.\nType help for common commands.\n'),
      }),
    }),
    etc: dir({
      hostname: file(`${HOST}\n`),
      passwd: file(`root:x:0:0:root:/root:/bin/bash\nsshd:x:108:65534::/run/sshd:/usr/sbin/nologin\nblueteam-user:x:1000:1000:Blue Team User:/home/blueteam-user:/bin/bash\n`),
      hosts: file(`127.0.0.1 localhost\n192.168.1.50 ${HOST}\n`),
      'os-release': file('NAME="Ubuntu"\nVERSION="22.04.4 LTS (Jammy Jellyfish)"\nID=ubuntu\nVERSION_ID="22.04"\n'),
      ssh: dir({
        sshd_config: file('Port 22\nPermitRootLogin no\nPasswordAuthentication yes\n'),
      }),
    }),
    var: dir({
      log: dir({
        'auth.log': file(attackActive ? ATTACK_AUTH_LOG : QUIET_AUTH_LOG),
        syslog: file(`Sep 23 19:40:00 ${HOST} kernel: Linux version 5.15.0-112-generic\nSep 23 19:40:01 ${HOST} systemd[1]: Started User Manager for UID 1000.\n`),
        nginx: dir({
          'access.log': file('192.168.1.20 - - [23/Sep/2026:19:40:11 +0000] "GET / HTTP/1.1" 200 1234\n'),
        }),
      }),
      www: dir({
        html: dir({
          'index.html': file('<!doctype html><html><body><h1>Cyberrange</h1></body></html>\n'),
        }),
      }),
    }),
    tmp: dir({}),
    usr: dir({
      bin: dir({}),
      local: dir({
        bin: dir({}),
      }),
    }),
    bin: dir({}),
    root: dir({
      '.profile': file('# root profile\n'),
    }),
    proc: dir({
      version: file('Linux version 5.15.0-112-generic (buildd@lcy02) (gcc version 11.4.0)\n'),
      cpuinfo: file('processor\t: 0\nmodel name\t: Cyberrange Virtual CPU\ncpu cores\t: 2\n'),
      meminfo: file('MemTotal:        8042124 kB\nMemFree:         2145020 kB\nMemAvailable:    5120440 kB\n'),
    }),
  });

const cloneFs = (node: FsNode): FsNode => {
  if (node.type === 'file') return file(node.content);
  const children: Record<string, FsNode> = {};
  for (const [name, child] of Object.entries(node.children)) {
    children[name] = cloneFs(child);
  }
  return dir(children);
};

const isFsNode = (value: unknown): value is FsNode => {
  if (!value || typeof value !== 'object') return false;
  const node = value as FsNode;
  if (node.type === 'file' && typeof node.content === 'string') return true;
  if (node.type === 'dir' && node.children && typeof node.children === 'object') {
    return Object.values(node.children).every(isFsNode);
  }
  return false;
};

export const createBashSession = (input?: {
  cwd?: string;
  filesystem?: unknown;
  history?: unknown;
  attackActive?: boolean;
}): BashSession => {
  const filesystem = isFsNode(input?.filesystem)
    ? cloneFs(input.filesystem)
    : createDefaultFilesystem(input?.attackActive === true);
  const history = Array.isArray(input?.history)
    ? input.history.filter((entry): entry is string => typeof entry === 'string').slice(-200)
    : [];
  let cwd = typeof input?.cwd === 'string' && input.cwd.startsWith('/') ? input.cwd : HOME;
  if (!getNode(filesystem, cwd) || getNode(filesystem, cwd)?.type !== 'dir') {
    cwd = HOME;
  }
  syncAuthLog(filesystem, input?.attackActive === true);
  return { cwd, filesystem, history };
};

const syncAuthLog = (filesystem: FsNode, attackActive: boolean): void => {
  const log = getNode(filesystem, '/var/log/auth.log');
  if (log && log.type === 'file') {
    log.content = attackActive ? ATTACK_AUTH_LOG : QUIET_AUTH_LOG;
  }
};

const normalizePath = (path: string): string => {
  const parts = path.split('/').filter((part) => part.length > 0 && part !== '.');
  const stack: string[] = [];
  for (const part of parts) {
    if (part === '..') {
      stack.pop();
    } else {
      stack.push(part);
    }
  }
  return '/' + stack.join('/');
};

const expandPath = (cwd: string, target = '.'): string => {
  let path = target.trim();
  if (!path) path = '.';
  if (path === '~' || path.startsWith('~/')) {
    path = HOME + path.slice(1);
  }
  if (!path.startsWith('/')) {
    path = cwd === '/' ? `/${path}` : `${cwd}/${path}`;
  }
  return normalizePath(path);
};

const getNode = (root: FsNode, absolutePath: string): FsNode | null => {
  const path = normalizePath(absolutePath);
  if (path === '/') return root;
  let current: FsNode = root;
  for (const part of path.split('/').filter(Boolean)) {
    if (current.type !== 'dir' || !Object.prototype.hasOwnProperty.call(current.children, part)) {
      return null;
    }
    current = current.children[part];
  }
  return current;
};

const getParent = (root: FsNode, absolutePath: string): { parent: FsNode & { type: 'dir' }; name: string } | null => {
  const path = normalizePath(absolutePath);
  if (path === '/') return null;
  const parts = path.split('/').filter(Boolean);
  const name = parts.pop()!;
  const parentPath = '/' + parts.join('/');
  const parent = getNode(root, parentPath === '/' ? '/' : parentPath);
  if (!parent || parent.type !== 'dir') return null;
  return { parent, name };
};

const ensureParentDirs = (root: FsNode, absolutePath: string): string | null => {
  const path = normalizePath(absolutePath);
  const parts = path.split('/').filter(Boolean);
  let current = root;
  for (let i = 0; i < parts.length - 1; i++) {
    const part = parts[i];
    if (current.type !== 'dir') return `Not a directory`;
    if (!Object.prototype.hasOwnProperty.call(current.children, part)) {
      current.children[part] = dir({});
    }
    current = current.children[part];
    if (current.type !== 'dir') return `Not a directory: /${parts.slice(0, i + 1).join('/')}`;
  }
  return null;
};

const tokenize = (command: string): string[] => {
  const tokens: string[] = [];
  let current = '';
  let quote: '"' | "'" | null = null;
  for (let i = 0; i < command.length; i++) {
    const ch = command[i];
    if (quote) {
      if (ch === quote) {
        quote = null;
      } else {
        current += ch;
      }
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      continue;
    }
    if (/\s/.test(ch)) {
      if (current) {
        tokens.push(current);
        current = '';
      }
      continue;
    }
    current += ch;
  }
  if (current) tokens.push(current);
  return tokens;
};

const splitFlags = (args: string[]): { flags: Set<string>; positionals: string[] } => {
  const flags = new Set<string>();
  const positionals: string[] = [];
  for (const arg of args) {
    if (arg === '--') continue;
    if (arg.startsWith('--')) {
      flags.add(arg.slice(2));
      continue;
    }
    if (arg.startsWith('-') && arg.length > 1) {
      for (const flag of arg.slice(1)) flags.add(flag);
      continue;
    }
    positionals.push(arg);
  }
  return { flags, positionals };
};

const formatPromptPath = (cwd: string): string => {
  if (cwd === HOME) return '~';
  if (cwd.startsWith(HOME + '/')) return '~' + cwd.slice(HOME.length);
  return cwd;
};

export const formatBashPrompt = (cwd: string): string =>
  `${USER}@cyberrange:${formatPromptPath(cwd)}$`;

const ok = (session: BashSession, output = '', error: string | null = null, clear = false): BashExecResult => ({
  output,
  error,
  cwd: session.cwd,
  filesystem: session.filesystem,
  clear,
});

const fail = (session: BashSession, error: string): BashExecResult => ok(session, '', error);

const readFileContent = (session: BashSession, path: string): { content?: string; error?: string } => {
  const absolute = expandPath(session.cwd, path);
  const node = getNode(session.filesystem, absolute);
  if (!node) return { error: `${path}: No such file or directory` };
  if (node.type === 'dir') return { error: `${path}: Is a directory` };
  return { content: node.content };
};

const listDir = (session: BashSession, target: string, flags: Set<string>): string => {
  const absolute = expandPath(session.cwd, target);
  const node = getNode(session.filesystem, absolute);
  if (!node) throw new Error(`ls: cannot access '${target}': No such file or directory`);
  if (node.type === 'file') {
    return flags.has('l') ? `-rw-r--r-- 1 ${USER} ${USER} ${node.content.length} Sep 23 19:40 ${target.split('/').pop()}` : (target.split('/').pop() || target);
  }

  let names = Object.keys(node.children);
  if (!flags.has('a') && !flags.has('A')) {
    names = names.filter((name) => !name.startsWith('.'));
  }
  names.sort((a, b) => a.localeCompare(b));

  if (flags.has('l')) {
    const rows = names.map((name) => {
      const child = node.children[name];
      if (child.type === 'dir') {
        return `drwxr-xr-x 2 ${USER} ${USER} 4096 Sep 23 19:40 ${name}`;
      }
      return `-rw-r--r-- 1 ${USER} ${USER} ${String(child.content.length).padStart(4, ' ')} Sep 23 19:40 ${name}`;
    });
    return rows.join('\n');
  }

  return names.join('  ');
};

const cmdHelp = (): string =>
  `Cyberrange bash simulator — common commands:
  File system:  ls  cd  pwd  cat  less  head  tail  mkdir  touch  rm  rmdir  cp  mv  find  tree
  Text:        echo  grep  wc  sort  clear  history
  System:       whoami  id  hostname  date  uname  env  df  free  uptime  ps  top
  Network:      netstat  ss  ifconfig  ip  ping
  Lab:          lab-info  baseline  start-attack  shell-type bash|powershell  help
Tips: paths support ~, ., and ..  Example: cd /var/log && ls && cat auth.log`;

export const executeBash = (
  session: BashSession,
  command: string,
  options: { attackActive?: boolean } = {},
): BashExecResult => {
  syncAuthLog(session.filesystem, options.attackActive === true);
  const trimmed = command.trim();
  if (!trimmed) return ok(session);

  // Support simple command lists: cmd1 && cmd2 ; cmd3
  if (/&&|;/.test(trimmed) && !/[|><]/.test(trimmed)) {
    const parts = trimmed.split(/&&|;/).map((part) => part.trim()).filter(Boolean);
    const outputs: string[] = [];
    for (const part of parts) {
      const result = executeBash(session, part, options);
      if (result.error) {
        if (result.output) outputs.push(result.output);
        return {
          ...result,
          output: [...outputs, result.error].filter(Boolean).join('\n'),
          error: result.error,
        };
      }
      if (result.clear) return result;
      if (result.output) outputs.push(result.output);
    }
    return ok(session, outputs.join('\n'));
  }

  session.history = [...session.history, trimmed].slice(-200);
  const tokens = tokenize(trimmed);
  const cmd = tokens[0];
  const args = tokens.slice(1);
  const { flags, positionals } = splitFlags(args);

  try {
    switch (cmd) {
      case 'help':
      case '--help':
        return ok(session, cmdHelp());
      case 'pwd':
        return ok(session, session.cwd);
      case 'whoami':
        return ok(session, USER);
      case 'id':
        return ok(session, `uid=1000(${USER}) gid=1000(${USER}) groups=1000(${USER}),27(sudo),100(users)`);
      case 'hostname':
        return ok(session, HOST);
      case 'date':
        return ok(session, new Date().toString());
      case 'uname':
        if (flags.has('a') || positionals.includes('-a')) {
          return ok(session, `Linux ${HOST} 5.15.0-112-generic #122-Ubuntu SMP x86_64 GNU/Linux`);
        }
        return ok(session, 'Linux');
      case 'env':
      case 'printenv':
        return ok(
          session,
          [
            `USER=${USER}`,
            `HOME=${HOME}`,
            `PWD=${session.cwd}`,
            `SHELL=/bin/bash`,
            `PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`,
            `HOSTNAME=${HOST}`,
          ].join('\n'),
        );
      case 'clear':
        return ok(session, '', null, true);
      case 'history':
        return ok(session, session.history.map((entry, index) => `${String(index + 1).padStart(4, ' ')}  ${entry}`).join('\n'));
      case 'cd': {
        const target = positionals[0] || HOME;
        const absolute = expandPath(session.cwd, target);
        const node = getNode(session.filesystem, absolute);
        if (!node) return fail(session, `bash: cd: ${target}: No such file or directory`);
        if (node.type !== 'dir') return fail(session, `bash: cd: ${target}: Not a directory`);
        session.cwd = absolute === '/' ? '/' : absolute.replace(/\/$/, '') || '/';
        return ok(session);
      }
      case 'ls': {
        const targets = positionals.length ? positionals : ['.'];
        if (targets.length === 1) {
          return ok(session, listDir(session, targets[0], flags));
        }
        const blocks = targets.map((target) => {
          try {
            return `${target}:\n${listDir(session, target, flags)}`;
          } catch (err) {
            return (err as Error).message;
          }
        });
        return ok(session, blocks.join('\n\n'));
      }
      case 'cat':
      case 'less':
      case 'more': {
        if (!positionals.length) return fail(session, `${cmd}: missing file operand`);
        const chunks: string[] = [];
        for (const path of positionals) {
          const result = readFileContent(session, path);
          if (result.error) return fail(session, `${cmd}: ${result.error}`);
          chunks.push(result.content || '');
        }
        return ok(session, chunks.join(''));
      }
      case 'head': {
        const n = flags.has('n') ? Number(positionals.shift() || 10) : 10;
        const path = positionals[0];
        if (!path) return fail(session, 'head: missing file operand');
        const result = readFileContent(session, path);
        if (result.error) return fail(session, `head: ${result.error}`);
        return ok(session, (result.content || '').split('\n').slice(0, Number.isFinite(n) ? n : 10).join('\n'));
      }
      case 'tail': {
        let count = 10;
        let path = positionals[0];
        if (flags.has('n') && positionals.length) {
          const maybe = Number(positionals[0]);
          if (Number.isFinite(maybe)) {
            count = maybe;
            path = positionals[1];
          }
        } else if (args[0]?.startsWith('-n')) {
          // tokenize already split "-n" "20" via splitFlags when "-n" alone, but "-n20" is one token
        }
        // Support: tail -n 20 file  and  tail -20 file
        for (const arg of args) {
          if (/^-n\d+$/.test(arg)) count = Number(arg.slice(2));
          if (/^-\d+$/.test(arg)) count = Number(arg.slice(1));
        }
        if (flags.has('n') && positionals[0] && /^\d+$/.test(positionals[0])) {
          count = Number(positionals[0]);
          path = positionals[1];
        }
        if (!path) return fail(session, 'tail: missing file operand');
        const result = readFileContent(session, path);
        if (result.error) return fail(session, `tail: ${result.error}`);
        const lines = (result.content || '').replace(/\n$/, '').split('\n');
        return ok(session, lines.slice(-count).join('\n'));
      }
      case 'mkdir': {
        if (!positionals.length) return fail(session, 'mkdir: missing operand');
        for (const target of positionals) {
          const absolute = expandPath(session.cwd, target);
          if (flags.has('p')) {
            const err = ensureParentDirs(session.filesystem, absolute);
            if (err) return fail(session, `mkdir: ${err}`);
          }
          const parentInfo = getParent(session.filesystem, absolute);
          if (!parentInfo) return fail(session, `mkdir: cannot create directory '${target}': Invalid path`);
          if (Object.prototype.hasOwnProperty.call(parentInfo.parent.children, parentInfo.name)) {
            if (!flags.has('p')) return fail(session, `mkdir: cannot create directory '${target}': File exists`);
            continue;
          }
          if (!flags.has('p') && !getNode(session.filesystem, normalizePath(absolute.split('/').slice(0, -1).join('/') || '/'))) {
            return fail(session, `mkdir: cannot create directory '${target}': No such file or directory`);
          }
          parentInfo.parent.children[parentInfo.name] = dir({});
        }
        return ok(session);
      }
      case 'touch': {
        if (!positionals.length) return fail(session, 'touch: missing file operand');
        for (const target of positionals) {
          const absolute = expandPath(session.cwd, target);
          const existing = getNode(session.filesystem, absolute);
          if (existing) {
            if (existing.type === 'dir') return fail(session, `touch: cannot touch '${target}': Is a directory`);
            continue;
          }
          const parentInfo = getParent(session.filesystem, absolute);
          if (!parentInfo) return fail(session, `touch: cannot touch '${target}': No such file or directory`);
          parentInfo.parent.children[parentInfo.name] = file('');
        }
        return ok(session);
      }
      case 'rm': {
        if (!positionals.length) return fail(session, 'rm: missing operand');
        for (const target of positionals) {
          const absolute = expandPath(session.cwd, target);
          const node = getNode(session.filesystem, absolute);
          if (!node) return fail(session, `rm: cannot remove '${target}': No such file or directory`);
          if (node.type === 'dir' && !flags.has('r') && !flags.has('R')) {
            return fail(session, `rm: cannot remove '${target}': Is a directory`);
          }
          const parentInfo = getParent(session.filesystem, absolute);
          if (!parentInfo) return fail(session, `rm: cannot remove '${target}'`);
          delete parentInfo.parent.children[parentInfo.name];
        }
        return ok(session);
      }
      case 'rmdir': {
        if (!positionals.length) return fail(session, 'rmdir: missing operand');
        for (const target of positionals) {
          const absolute = expandPath(session.cwd, target);
          const node = getNode(session.filesystem, absolute);
          if (!node) return fail(session, `rmdir: failed to remove '${target}': No such file or directory`);
          if (node.type !== 'dir') return fail(session, `rmdir: failed to remove '${target}': Not a directory`);
          if (Object.keys(node.children).length) return fail(session, `rmdir: failed to remove '${target}': Directory not empty`);
          const parentInfo = getParent(session.filesystem, absolute);
          if (!parentInfo) return fail(session, `rmdir: failed to remove '${target}'`);
          delete parentInfo.parent.children[parentInfo.name];
        }
        return ok(session);
      }
      case 'cp': {
        if (positionals.length < 2) return fail(session, 'cp: missing file operand');
        const dest = positionals[positionals.length - 1];
        const sources = positionals.slice(0, -1);
        const destAbs = expandPath(session.cwd, dest);
        const destNode = getNode(session.filesystem, destAbs);
        for (const source of sources) {
          const srcAbs = expandPath(session.cwd, source);
          const srcNode = getNode(session.filesystem, srcAbs);
          if (!srcNode) return fail(session, `cp: cannot stat '${source}': No such file or directory`);
          if (srcNode.type === 'dir' && !flags.has('r') && !flags.has('R')) {
            return fail(session, `cp: -r not specified; omitting directory '${source}'`);
          }
          let targetAbs = destAbs;
          if (destNode && destNode.type === 'dir') {
            targetAbs = normalizePath(`${destAbs}/${srcAbs.split('/').pop()}`);
          }
          const parentInfo = getParent(session.filesystem, targetAbs);
          if (!parentInfo) return fail(session, `cp: cannot create '${dest}'`);
          parentInfo.parent.children[parentInfo.name] = cloneFs(srcNode);
        }
        return ok(session);
      }
      case 'mv': {
        if (positionals.length < 2) return fail(session, 'mv: missing file operand');
        const dest = positionals[positionals.length - 1];
        const sources = positionals.slice(0, -1);
        const destAbs = expandPath(session.cwd, dest);
        const destNode = getNode(session.filesystem, destAbs);
        for (const source of sources) {
          const srcAbs = expandPath(session.cwd, source);
          const srcNode = getNode(session.filesystem, srcAbs);
          if (!srcNode) return fail(session, `mv: cannot stat '${source}': No such file or directory`);
          let targetAbs = destAbs;
          if (destNode && destNode.type === 'dir') {
            targetAbs = normalizePath(`${destAbs}/${srcAbs.split('/').pop()}`);
          }
          const destParent = getParent(session.filesystem, targetAbs);
          const srcParent = getParent(session.filesystem, srcAbs);
          if (!destParent || !srcParent) return fail(session, `mv: cannot move '${source}'`);
          destParent.parent.children[destParent.name] = cloneFs(srcNode);
          delete srcParent.parent.children[srcParent.name];
          if (session.cwd === srcAbs || session.cwd.startsWith(srcAbs + '/')) {
            session.cwd = targetAbs;
          }
        }
        return ok(session);
      }
      case 'echo':
        return ok(session, args.join(' ').replace(/^"|"$/g, ''));
      case 'grep': {
        if (positionals.length < 2) return fail(session, 'Usage: grep PATTERN FILE');
        const pattern = positionals[0];
        const path = positionals[1];
        const result = readFileContent(session, path);
        if (result.error) return fail(session, `grep: ${result.error}`);
        const matched = (result.content || '')
          .split('\n')
          .filter((line) => line.includes(pattern));
        if (!matched.length) {
          // Real grep exits 1 with no output; keep empty output for quiet results
          if (path.includes('auth.log') && pattern === 'Failed' && !options.attackActive) {
            return ok(session, 'No failed logins');
          }
          return ok(session, '');
        }
        let output = matched.join('\n');
        if (path.includes('auth.log') && pattern === 'Failed' && options.attackActive) {
          output += '\n[ALERT] Brute Force Attack from 203.0.113.45!';
        }
        return ok(session, output);
      }
      case 'find': {
        const start = expandPath(session.cwd, positionals[0] || '.');
        const nameIdx = args.indexOf('-name');
        const needle = nameIdx >= 0 ? args[nameIdx + 1]?.replace(/^['"]|['"]$/g, '') : null;
        const rootNode = getNode(session.filesystem, start);
        if (!rootNode) return fail(session, `find: '${positionals[0] || '.'}': No such file or directory`);

        const all: string[] = [];
        const walkAll = (node: FsNode, path: string) => {
          all.push(path || '/');
          if (node.type === 'dir') {
            for (const [name, child] of Object.entries(node.children)) {
              walkAll(child, path === '/' ? `/${name}` : `${path}/${name}`);
            }
          }
        };
        walkAll(rootNode, start);

        const filtered = needle
          ? all.filter((path) => {
              const base = path.split('/').pop() || '';
              if (needle.includes('*')) {
                const re = new RegExp(
                  '^' +
                    needle
                      .split('*')
                      .map((part) => part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
                      .join('.*') +
                    '$',
                );
                return re.test(base);
              }
              return base === needle;
            })
          : all;
        return ok(session, filtered.join('\n'));
      }
      case 'tree': {
        const start = expandPath(session.cwd, positionals[0] || '.');
        const rootNode = getNode(session.filesystem, start);
        if (!rootNode) return fail(session, `tree: ${positionals[0] || '.'}: No such file or directory`);
        const lines = [start];
        const walk = (node: FsNode, prefix: string) => {
          if (node.type !== 'dir') return;
          const entries = Object.keys(node.children).sort();
          entries.forEach((name, index) => {
            const last = index === entries.length - 1;
            lines.push(`${prefix}${last ? '└── ' : '├── '}${name}`);
            walk(node.children[name], `${prefix}${last ? '    ' : '│   '}`);
          });
        };
        walk(rootNode, '');
        return ok(session, lines.join('\n'));
      }
      case 'wc': {
        if (!positionals.length) return fail(session, 'wc: missing file operand');
        const result = readFileContent(session, positionals[0]);
        if (result.error) return fail(session, `wc: ${result.error}`);
        const text = result.content || '';
        const lines = text ? text.replace(/\n$/, '').split('\n').length : 0;
        const words = text.trim() ? text.trim().split(/\s+/).length : 0;
        const bytes = text.length;
        return ok(session, `${lines} ${words} ${bytes} ${positionals[0]}`);
      }
      case 'sort': {
        if (!positionals.length) return fail(session, 'sort: missing file operand');
        const result = readFileContent(session, positionals[0]);
        if (result.error) return fail(session, `sort: ${result.error}`);
        return ok(session, (result.content || '').split('\n').filter((line, idx, arr) => line || idx < arr.length - 1).sort().join('\n'));
      }
      case 'df':
        return ok(session, formatDf());
      case 'free':
        return ok(session, formatFree(options.attackActive === true));
      case 'uptime':
        return ok(session, formatUptime(options.attackActive === true));
      case 'ps':
        return ok(
          session,
          flags.has('a') || flags.has('u') || flags.has('x') || positionals.includes('aux') || args.join(' ').includes('aux')
            ? formatPsAux(options.attackActive === true)
            : `  PID TTY          TIME CMD\n 1234 pts/0    00:00:00 bash\n 1488 pts/0    00:00:00 ps`,
        );
      case 'top':
        return ok(session, formatTop(options.attackActive === true));
      case 'netstat':
      case 'ss':
        return ok(session, NETSTAT);
      case 'ifconfig':
      case 'ip':
        return ok(session, IFCONFIG);
      case 'ping': {
        const host = positionals[0] || '127.0.0.1';
        return ok(
          session,
          `PING ${host} (${host === '127.0.0.1' ? '127.0.0.1' : '203.0.113.45'}) 56(84) bytes of data.\n64 bytes from ${host}: icmp_seq=1 ttl=64 time=0.042 ms\n64 bytes from ${host}: icmp_seq=2 ttl=64 time=0.038 ms\n\n--- ${host} ping statistics ---\n2 packets transmitted, 2 received, 0% packet loss`,
        );
      }
      case 'which': {
        const bin = positionals[0];
        if (!bin) return fail(session, 'which: missing operand');
        const known = new Set(['ls', 'cd', 'pwd', 'cat', 'grep', 'ps', 'netstat', 'bash', 'ping', 'head', 'tail']);
        return known.has(bin) ? ok(session, `/usr/bin/${bin}`) : fail(session, '');
      }
      case 'file': {
        if (!positionals.length) return fail(session, 'file: missing operand');
        const absolute = expandPath(session.cwd, positionals[0]);
        const node = getNode(session.filesystem, absolute);
        if (!node) return fail(session, `file: cannot open '${positionals[0]}'`);
        return ok(session, node.type === 'dir' ? `${positionals[0]}: directory` : `${positionals[0]}: ASCII text`);
      }
      case 'chmod':
      case 'chown':
        return ok(session, '');
      case 'man':
        return ok(session, `No manual entry for ${positionals[0] || 'command'}. Try 'help'.`);
      default:
        // Support "ps aux" as two tokens already handled; also accept joined forms via exact lab aliases
        if (cmd === 'ps' && args[0] === 'aux') return ok(session, formatPsAux(options.attackActive === true));
        return fail(session, `bash: ${cmd}: command not found`);
    }
  } catch (err) {
    return fail(session, (err as Error).message);
  }
};
