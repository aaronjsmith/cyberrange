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
      expect(html).toContain('Run: hostname, whoami, and date');
      expect(html).not.toContain('contenteditable');
      expect(html).not.toContain('location.reload');
      expect(html).not.toContain('[object Object]');

      const script = html.match(/<script>\n([\s\S]*?)<\/script>/);
      expect(script).toBeTruthy();
      expect(script?.[1]).toContain('replace(/\\s+/g, \' \')');
      expect(script?.[1]).toContain('blueteam@cyberrange:~$');
      expect(() => new Function(script?.[1] || '')).not.toThrow();
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

      const tail = await run('tail -n 20 /var/log/auth.log');
      expect(tail.output).toContain('Failed password');
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

    it('should reject prototype lookups as unknown commands', async () => {
      const response = await mockFetch(new Request('http://localhost:8787/api/labs/network-intrusion-baseline/command', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command: 'toString', shellType: 'bash' }),
      }), {});
      const json = await response.json();

      expect(response.status).toBe(200);
      expect(json.error).toContain('Command not found');
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
});
