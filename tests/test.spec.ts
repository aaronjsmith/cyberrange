/**
 * Unit tests for Cyberrange application
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { Env } from '../src/index';

// We need to import the Worker handler
// For Cloudflare Workers, we can test the fetch handler directly

// Mock the global fetch for testing
const mockFetch = async (request: Request, env: Env) => {
  const url = new URL(request.url);
  const path = url.pathname;
  
  // Import the handler dynamically
  const module = await import('../src/index.ts');
  return module.default.fetch(request, env);
};

describe('Cyberrange Worker', () => {
  describe('Dashboard Route', () => {
    it('should return HTML for root path', async () => {
      const request = new Request('http://localhost:8787/', {
        method: 'GET',
      });
      
      const response = await mockFetch(request, {});
      
      expect(response.status).toBe(200);
      expect(response.headers.get('Content-Type')).toContain('text/html');
      
      const html = await response.text();
      expect(html).toContain('Cyberrange Dashboard');
      expect(html).toContain('Blue Team Training Platform');
    });
  });

  describe('Labs Index Route', () => {
    it('should return HTML for /labs', async () => {
      const request = new Request('http://localhost:8787/labs', {
        method: 'GET',
      });
      
      const response = await mockFetch(request, {});
      
      expect(response.status).toBe(200);
      expect(response.headers.get('Content-Type')).toContain('text/html');
      
      const html = await response.text();
      expect(html).toContain('Available Labs');
      expect(html).toContain('Network Intrusion Detection');
    });
  });

  describe('Lab Detail Route', () => {
    it('should return HTML for /labs/network-intrusion-baseline', async () => {
      const request = new Request('http://localhost:8787/labs/network-intrusion-baseline', {
        method: 'GET',
      });
      
      const response = await mockFetch(request, {});
      
      expect(response.status).toBe(200);
      expect(response.headers.get('Content-Type')).toContain('text/html');
      
      const html = await response.text();
      expect(html).toContain('Network Intrusion Detection');
      expect(html).toContain('Terminal');
      expect(html).toContain('Do this now:');
      expect(html).toContain('Why this matters');
      expect(html).toContain('What to observe');
      expect(html).toContain('Observation notepad');
      expect(html).toContain('Stop attack');
      expect(html).toContain('stop-attack');
      expect(html).toContain('window.__LAB_BOOT__');
      expect(html).toContain('/emulation/linux-lab.js');
      expect(html).toContain('id="term"');
      expect(html).not.toContain('contenteditable');
      expect(html).not.toContain('[object Object]');
    });

    it('should open the Windows Server 2025 lab in PowerShell', async () => {
      const request = new Request('http://localhost:8787/labs/windows-server-2025', {
        method: 'GET',
      });

      const response = await mockFetch(request, {});
      const html = await response.text();

      expect(response.status).toBe(200);
      expect(html).toContain('Windows Server 2025 Hardening');
      expect(html).toContain('Terminal (powershell)');
      expect(html).toContain('PS C:\\\\Users\\\\blueteam-user>');
    });

    it('should return 404 for unknown lab', async () => {
      const request = new Request('http://localhost:8787/labs/unknown-lab', {
        method: 'GET',
      });
      
      const response = await mockFetch(request, {});
      
      expect(response.status).toBe(404);
    });
  });

  describe('Health Check Route', () => {
    it('should return JSON for /health', async () => {
      const request = new Request('http://localhost:8787/health', {
        method: 'GET',
      });
      
      const response = await mockFetch(request, {});
      
      expect(response.status).toBe(200);
      expect(response.headers.get('Content-Type')).toContain('application/json');
      
      const json = await response.json();
      expect(json).toHaveProperty('status', 'ok');
      expect(json).toHaveProperty('timestamp');
    });
  });

  describe('API Root Route', () => {
    it('should return JSON for /api', async () => {
      const request = new Request('http://localhost:8787/api', {
        method: 'GET',
      });
      
      const response = await mockFetch(request, {});
      
      expect(response.status).toBe(200);
      expect(response.headers.get('Content-Type')).toContain('application/json');
      
      const json = await response.json();
      expect(json).toHaveProperty('name', 'Cyberrange API');
      expect(json).toHaveProperty('version');
    });
  });

  describe('Command Execution', () => {
    it('should handle POST to /api/labs/:id/command', async () => {
      const request = new Request('http://localhost:8787/api/labs/network-intrusion-baseline/command', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command: 'whoami' }),
      });
      
      const response = await mockFetch(request, {});
      
      expect(response.status).toBe(200);
      expect(response.headers.get('Content-Type')).toContain('application/json');
      
      const json = await response.json();
      expect(json).toHaveProperty('output');
    });

    it('should return error for invalid command', async () => {
      const request = new Request('http://localhost:8787/api/labs/network-intrusion-baseline/command', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command: 'invalid-command-xyz' }),
      });
      
      const response = await mockFetch(request, {});
      
      expect(response.status).toBe(200);
      const json = await response.json();
      expect(json).toHaveProperty('error');
    });

    it('should handle baseline command', async () => {
      const request = new Request('http://localhost:8787/api/labs/network-intrusion-baseline/command', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command: 'baseline' }),
      });
      
      const response = await mockFetch(request, {});
      const json = await response.json();
      
      expect(json.output).toContain('BASELINE ESTABLISHED');
      expect(json.baselineEstablished).toBe(true);
    });

    it('should handle start-attack command', async () => {
      const request = new Request('http://localhost:8787/api/labs/network-intrusion-baseline/command', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          command: 'start-attack',
          baselineEstablished: true
        }),
      });
      
      const response = await mockFetch(request, {});
      const json = await response.json();
      
      expect(json.output).toContain('ATTACK STARTED');
      expect(json.attackActive).toBe(true);
    });

    it('should render realistic top metrics for a quiet Linux host', async () => {
      const response = await mockFetch(new Request('http://localhost:8787/api/labs/network-intrusion-baseline/command', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command: 'top', shellType: 'bash', attackActive: false }),
      }), {});
      const json = await response.json();

      expect(json.output).toContain('load average:');
      expect(json.output).toContain('%Cpu(s):');
      expect(json.output).toContain('MiB Mem');
      expect(json.output).toContain('MiB Swap');
      expect(json.output).toContain('systemd');
      expect(json.output).toContain('mysqld');
      expect(json.output).toMatch(/Tasks:\s+\d+\s+total/);
    });

    it('should keep prior commands in history', async () => {
      const response = await mockFetch(new Request('http://localhost:8787/api/labs/network-intrusion-baseline/command', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          command: 'whoami',
          shellType: 'bash',
          commandHistory: ['hostname'],
        }),
      }), {});
      const json = await response.json();

      expect(json.commandHistory).toEqual(['hostname', 'whoami']);
      expect(json.output).toBe('blueteam-user');
    });

    it('should collapse extra whitespace before lookup', async () => {
      const response = await mockFetch(new Request('http://localhost:8787/api/labs/network-intrusion-baseline/command', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command: 'ps  aux', shellType: 'bash' }),
      }), {});
      const json = await response.json();

      expect(json.output).toContain('blueteam');
      expect(json.error).toBeNull();
    });

    it('should advance the bash learning steps and reveal the attack in the logs', async () => {
      let step = 0;
      let history: string[] = [];
      let baseline = false;
      let attack = false;

      const run = async (command: string) => {
        const response = await mockFetch(new Request('http://localhost:8787/api/labs/network-intrusion-baseline/command', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            command,
            shellType: 'bash',
            mode: 'learning',
            currentStep: step,
            commandHistory: history,
            baselineEstablished: baseline,
            attackActive: attack,
          }),
        }), {});
        const json = await response.json();
        step = json.currentStep;
        history = json.commandHistory;
        baseline = json.baselineEstablished;
        attack = json.attackActive;
        return json;
      };

      const hostname = await run('hostname');
      expect(hostname.stepChanged).toBe(false);
      expect(hostname.progressNote).toContain('whoami');
      expect(hostname.output).toBe('cyberrange-training-01');

      await run('whoami');
      const identified = await run('date');
      expect(identified.stepChanged).toBe(true);
      expect(identified.currentStep).toBe(1);
      expect(identified.output).toBeTruthy();

      expect((await run('ps aux')).currentStep).toBe(2);
      expect((await run('netstat -tuln')).currentStep).toBe(3);
      expect((await run('top')).currentStep).toBe(4);

      const quietLog = await run('tail -n 20 /var/log/auth.log');
      expect(quietLog.currentStep).toBe(5);
      expect(quietLog.output).toContain('NORMAL');

      const baselineResult = await run('baseline');
      expect(baselineResult.currentStep).toBe(6);
      expect(baselineResult.baselineEstablished).toBe(true);

      const attackResult = await run('start-attack');
      expect(attackResult.currentStep).toBe(7);
      expect(attackResult.attackActive).toBe(true);

      const grep = await run('grep Failed /var/log/auth.log');
      expect(grep.output).toContain('[ALERT]');
      expect(grep.output).toContain('203.0.113.45');
      expect(grep.currentStep).toBe(8);

      const stop = await run('stop-attack');
      expect(stop.output).toContain('ATTACK STOPPED');
      expect(stop.attackActive).toBe(false);
      expect(stop.currentStep).toBe(9);

      const quietAgain = await run('grep Failed /var/log/auth.log');
      expect(quietAgain.output).toBe('No failed logins');
    });

    it('should keep quiet auth logs until the attack starts', async () => {
      const response = await mockFetch(new Request('http://localhost:8787/api/labs/network-intrusion-baseline/command', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          command: 'grep Failed /var/log/auth.log',
          shellType: 'bash',
          attackActive: false,
        }),
      }), {});
      const json = await response.json();

      expect(json.output).toBe('No failed logins');
    });

    it('should keep quiet auth logs until the attack starts via cat as well', async () => {
      const response = await mockFetch(new Request('http://localhost:8787/api/labs/network-intrusion-baseline/command', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          command: 'cat /var/log/auth.log',
          shellType: 'bash',
          attackActive: false,
        }),
      }), {});
      const json = await response.json();

      expect(json.output).toContain('NORMAL');
      expect(json.output).not.toContain('Failed password');
    });

    it('should reject prototype lookups as unknown commands', async () => {
      const response = await mockFetch(new Request('http://localhost:8787/api/labs/network-intrusion-baseline/command', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command: 'toString', shellType: 'bash' }),
      }), {});
      const json = await response.json();

      expect(response.status).toBe(200);
      expect(json.error).toContain('command not found');
    });

    it('should simulate a Linux filesystem with cd, ls, pwd, and cat', async () => {
      let cwd = '/home/blueteam-user';
      let filesystem: unknown = undefined;

      const run = async (command: string) => {
        const response = await mockFetch(new Request('http://localhost:8787/api/labs/network-intrusion-baseline/command', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            command,
            shellType: 'bash',
            cwd,
            filesystem,
          }),
        }), {});
        const json = await response.json();
        cwd = json.cwd;
        filesystem = json.filesystem;
        return json;
      };

      expect((await run('pwd')).output).toBe('/home/blueteam-user');
      expect((await run('ls')).output).toContain('Documents');
      expect((await run('cd Documents')).cwd).toBe('/home/blueteam-user/Documents');
      expect((await run('pwd')).output).toBe('/home/blueteam-user/Documents');
      expect((await run('pwd')).prompt).toBe('blueteam-user@cyberrange:~/Documents$');

      const notes = await run('cat notes.txt');
      expect(notes.output).toContain('Blue team notes');

      await run('mkdir labs');
      await run('cd labs');
      await run('touch report.txt');
      expect((await run('ls')).output).toContain('report.txt');
      expect((await run('cd /var/log')).cwd).toBe('/var/log');
      expect((await run('ls')).output).toContain('auth.log');
    });

    it('should handle shell-type switch', async () => {
      const request = new Request('http://localhost:8787/api/labs/network-intrusion-baseline/command', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command: 'shell-type powershell' }),
      });
      
      const response = await mockFetch(request, {});
      const json = await response.json();
      
      expect(json.output).toContain('Shell switched to powershell');
      expect(json.shellType).toBe('powershell');
    });
  });

  describe('PowerShell Commands', () => {
    it('should handle PowerShell whoami', async () => {
      const request = new Request('http://localhost:8787/api/labs/network-intrusion-baseline/command', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          command: 'whoami',
          shellType: 'powershell'
        }),
      });
      
      const response = await mockFetch(request, {});
      const json = await response.json();
      
      expect(json.output).toContain('CYBERRANGE');
    });

    it('should handle Get-Process', async () => {
      const request = new Request('http://localhost:8787/api/labs/network-intrusion-baseline/command', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          command: 'Get-Process',
          shellType: 'powershell'
        }),
      });
      
      const response = await mockFetch(request, {});
      const json = await response.json();
      
      expect(json.output).toContain('Handles');
    });
  });

  describe('404 Handler', () => {
    it('should return 404 for unknown routes', async () => {
      const request = new Request('http://localhost:8787/unknown-route', {
        method: 'GET',
      });
      
      const response = await mockFetch(request, {});
      
      expect(response.status).toBe(404);
    });
  });

  describe('Mounted /range paths', () => {
    it('should serve dashboard under /range', async () => {
      const response = await mockFetch(new Request('http://localhost:8787/range'), {});
      expect(response.status).toBe(200);
      const html = await response.text();
      expect(html).toContain('Cyberrange Dashboard');
      expect(html).toContain('href="/range/labs"');
    });

    it('should serve labs index under /range/labs', async () => {
      const response = await mockFetch(new Request('http://localhost:8787/range/labs'), {});
      expect(response.status).toBe(200);
      const html = await response.text();
      expect(html).toContain('Available Labs');
      expect(html).toContain('href="/range/labs/network-intrusion-baseline"');
    });

    it('should boot bash labs with just-bash client bundle', async () => {
      const response = await mockFetch(
        new Request('http://localhost:8787/range/labs/network-intrusion-baseline'),
        {},
      );
      const html = await response.text();
      expect(html).toContain('window.__LAB_BOOT__');
      expect(html).toContain('/range/emulation/linux-lab.js');
      expect(html).toContain('id="term"');
      expect(html).toContain('just-bash');
    });

    it('should serve Windows desktop UI route', async () => {
      const response = await mockFetch(
        new Request('http://localhost:8787/range/desktop/windows-server-2025'),
        {},
      );
      expect(response.status).toBe(200);
      const html = await response.text();
      expect(html).toContain('desktop-root');
      expect(html).toContain('/range/emulation/windows-lab.js');
    });

    it('should honor X-Base-Path for proxied /range mounts', async () => {
      const response = await mockFetch(
        new Request('http://localhost:8787/labs/network-intrusion-baseline', {
          headers: { 'X-Base-Path': '/range' },
        }),
        {},
      );
      expect(response.status).toBe(200);
      const html = await response.text();
      expect(html).toContain('"base":"/range"');
      expect(html).toContain('/range/emulation/linux-lab.js');
    });

    it('should accept commands at /range/api/...', async () => {
      const response = await mockFetch(
        new Request('http://localhost:8787/range/api/labs/network-intrusion-baseline/command', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ command: 'whoami', shellType: 'bash' }),
        }),
        {},
      );
      expect(response.status).toBe(200);
      const json = await response.json();
      expect(json.output).toContain('blueteam');
    });
  });
});
