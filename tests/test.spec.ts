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
