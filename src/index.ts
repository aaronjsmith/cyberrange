/**
 * Cyberrange Cloudflare Worker
 * Entry point for the cyberrange infrastructure
 */

export interface Env {
  // Environment variables for the cyberrange
  CYBERRANGE_ENV?: string;
  API_SECRET?: string;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    // Health check endpoint
    if (path === '/health') {
      return new Response(JSON.stringify({ status: 'ok', timestamp: Date.now() }), {
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // API root
    if (path === '/api' || path === '/') {
      return new Response(
        JSON.stringify({
          name: 'Cyberrange API',
          version: '1.0.0',
          endpoints: {
            health: '/health',
            scenarios: '/api/scenarios',
            status: '/api/status',
          },
        }),
        { headers: { 'Content-Type': 'application/json' } }
      );
    }

    // Scenario management (stub)
    if (path.startsWith('/api/scenarios')) {
      return new Response(
        JSON.stringify({ message: 'Scenario endpoints coming soon' }),
        { headers: { 'Content-Type': 'application/json' } }
      );
    }

    // Status endpoint
    if (path === '/api/status') {
      return new Response(
        JSON.stringify({
          environment: env.CYBERRANGE_ENV || 'development',
          uptime: process.uptime(),
        }),
        { headers: { 'Content-Type': 'application/json' } }
      );
    }

    // 404 for unknown routes
    return new Response('Not Found', { status: 404 });
  },
};
