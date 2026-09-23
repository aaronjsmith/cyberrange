/**
 * Cyberrange Cloudflare Worker
 * Entry point for the cyberrange infrastructure
 */

export interface Env {
  // Environment variables for the cyberrange
  CYBERRANGE_ENV?: string;
  API_SECRET?: string;
  ASSETS?: Fetcher;
}

const DASHBOARD_HTML = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Cyberrange Dashboard</title>
    <style>
      :root {
        --bg-surface: #161d17;
        --bg-app: #1f2721;
        --bg-inset: #2a342d;
        --border: #3a453f;
        --text-primary: #e6edf3;
        --text-secondary: #b8c5d1;
        --text-muted: #7a8a99;
        --accent-module: #4ade80;
        --accent-module-soft: rgba(74, 222, 128, 0.15);
        --accent-module-border: rgba(74, 222, 128, 0.3);
        --accent-sync: #3b82f6;
        --accent-sync-hover: #2563eb;
        --radius: 12px;
        --radius-sm: 6px;
        --shadow-card: 0 1px 3px rgba(0, 0, 0, 0.3);
        --shadow-pop: 0 8px 16px rgba(0, 0, 0, 0.4);
        --panel-accent: #4ade80;
        --panel-soft: #2a342d;
        --panel-soft-border: #3a453f;
        --status-good: #4ade80;
        --status-notable: #fbbf24;
        --status-critical: #f87171;
      }

      * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
      }

      body {
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        background: var(--bg-surface);
        color: var(--text-primary);
        min-height: 100vh;
      }

      .bar {
        background: var(--bg-surface);
        border-bottom: 1px solid var(--border);
        flex-wrap: wrap;
        justify-content: space-between;
        align-items: center;
        gap: 12px 16px;
        padding: 14px 28px;
        display: flex;
      }

      .brand {
        align-items: center;
        gap: 12px;
        display: flex;
      }

      .logo {
        border-radius: 6px;
        flex-shrink: 0;
        width: auto;
        height: 40px;
        display: block;
      }

      .title {
        letter-spacing: -0.01em;
        margin: 0;
        font-size: 16px;
        font-weight: 700;
      }

      .subtitle {
        color: var(--text-muted);
        margin: 1px 0 0;
        font-size: 12px;
      }

      .button {
        background: var(--accent-sync);
        color: #fff;
        letter-spacing: 0.06em;
        text-transform: uppercase;
        box-shadow: var(--shadow-card);
        border: none;
        border-radius: 999px;
        align-items: center;
        gap: 8px;
        padding: 9px 22px;
        font-size: 13px;
        font-weight: 700;
        transition: background 0.12s;
        display: inline-flex;
        cursor: pointer;
        text-decoration: none;
      }

      .button:hover:not(:disabled) {
        background: var(--accent-sync-hover);
      }

      .button:active:not(:disabled) {
        transform: translateY(1px);
      }

      .button:disabled {
        opacity: 0.75;
        cursor: default;
      }

      .panel {
        background: var(--bg-surface);
        border: 1px solid var(--border);
        border-top: 3px solid var(--panel-accent);
        border-radius: var(--radius);
        box-shadow: var(--shadow-card);
        padding: 16px 18px 18px;
      }

      .kicker {
        letter-spacing: 0.12em;
        text-transform: uppercase;
        color: var(--panel-accent);
        margin: 0;
        font-size: 10px;
        font-weight: 700;
      }

      .panel-title {
        letter-spacing: -0.01em;
        margin: 6px 0 2px;
        font-size: 17px;
        font-weight: 700;
      }

      .caption {
        color: var(--text-muted);
        margin: 0 0 12px;
        font-size: 12px;
      }

      .container {
        max-width: 1400px;
        margin: 0 auto;
        padding: 24px;
      }

      .grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
        gap: 20px;
      }

      .tag {
        background: var(--bg-surface);
        letter-spacing: 0.08em;
        text-transform: uppercase;
        border-radius: 999px;
        flex-shrink: 0;
        padding: 2px 8px;
        font-size: 10px;
        font-weight: 700;
        border: 1px solid var(--panel-soft-border);
        color: var(--panel-accent);
      }

      .tag-goal {
        border: 1px solid color-mix(in srgb, var(--status-good) 35%, var(--border));
        color: var(--status-good);
      }

      .list {
        flex-direction: column;
        gap: 8px;
        margin: 0;
        padding: 0;
        list-style: none;
        display: flex;
      }

      .list-item {
        border: 1px solid var(--border);
        border-radius: var(--radius-sm);
        background: var(--bg-inset);
        padding: 8px 10px;
      }

      .list-item-label {
        color: var(--text-primary);
        overflow-wrap: anywhere;
        word-break: break-word;
        margin: 0;
        font-size: 13px;
        font-weight: 600;
        line-height: 1.35;
      }

      .list-item-meta {
        color: var(--text-muted);
        margin: 4px 0 0;
        font-size: 11.5px;
        line-height: 1.45;
      }

      .filter-bar {
        flex-wrap: wrap;
        align-items: center;
        gap: 22px;
        display: flex;
        padding: 16px 0;
      }

      .filter-group {
        align-items: center;
        gap: 9px;
        display: flex;
      }

      .filter-label {
        letter-spacing: 0.08em;
        text-transform: uppercase;
        color: var(--text-muted);
        font-size: 11px;
        font-weight: 700;
      }

      .filter-chips {
        background: var(--bg-app);
        border-radius: 999px;
        gap: 4px;
        padding: 3px;
        display: inline-flex;
      }

      .filter-chip {
        color: var(--text-secondary);
        background: 0 0;
        border: none;
        border-radius: 999px;
        padding: 5px 11px;
        font-size: 12px;
        font-weight: 600;
        transition: background 0.1s, color 0.1s;
        cursor: pointer;
      }

      .filter-chip:hover {
        color: var(--text-primary);
      }

      .filter-chip-active {
        background: var(--bg-surface);
        color: var(--text-primary);
        box-shadow: var(--shadow-card);
      }

      .alerts {
        flex-direction: column;
        gap: 8px;
        display: flex;
      }

      .alert-pill {
        border: 1px solid var(--status-critical);
        background: var(--bg-surface);
        box-shadow: var(--shadow-card);
        color: var(--status-critical);
        cursor: pointer;
        border-radius: 999px;
        align-self: flex-start;
        align-items: center;
        gap: 8px;
        padding: 5px 12px 5px 5px;
        font-size: 12px;
        font-weight: 700;
        display: inline-flex;
        text-decoration: none;
      }

      .bang {
        background: var(--status-critical);
        width: 20px;
        height: 20px;
        color: var(--bg-surface);
        border-radius: 50%;
        place-items: center;
        font-size: 13px;
        font-weight: 800;
        display: grid;
      }

      .empty {
        border: 1px dashed var(--border);
        border-radius: var(--radius-sm);
        min-height: 84px;
        color: var(--text-muted);
        place-items: center;
        font-size: 12px;
        display: grid;
      }

      .main {
        padding: 24px 0;
      }
    </style>
  </head>
  <body>
    <div class="bar">
      <div class="brand">
        <div>
          <h1 class="title">Cyberrange Dashboard</h1>
          <p class="subtitle">Security Training Platform</p>
        </div>
      </div>
      <div>
        <a href="/api/scenarios" class="button">New Scenario</a>
      </div>
    </div>

    <div class="container">
      <div class="main">
        <div class="filter-bar">
          <div class="filter-group">
            <span class="filter-label">Environment</span>
            <div class="filter-chips">
              <button class="filter-chip filter-chip-active">All</button>
              <button class="filter-chip">Production</button>
              <button class="filter-chip">Staging</button>
            </div>
          </div>
          <div class="filter-group">
            <span class="filter-label">Status</span>
            <div class="filter-chips">
              <button class="filter-chip filter-chip-active">All</button>
              <button class="filter-chip">Active</button>
              <button class="filter-chip">Paused</button>
            </div>
          </div>
        </div>

        <div class="grid">
          <div class="panel">
            <p class="kicker">Overview</p>
            <h2 class="panel-title">Active Scenarios</h2>
            <p class="caption">3 running training exercises</p>
            <ul class="list">
              <li class="list-item">
                <p class="list-item-label">Phishing Simulation</p>
                <p class="list-item-meta">Started 2h ago &bull; 15 participants</p>
              </li>
              <li class="list-item">
                <p class="list-item-label">Network Intrusion</p>
                <p class="list-item-meta">Started 1h ago &bull; 8 participants</p>
              </li>
              <li class="list-item">
                <p class="list-item-label">Malware Analysis</p>
                <p class="list-item-meta">Started 30m ago &bull; 5 participants</p>
              </li>
            </ul>
          </div>

          <div class="panel">
            <p class="kicker">Quick Actions</p>
            <h2 class="panel-title">Launch New Exercise</h2>
            <p class="caption">Select a preset or customize</p>
            <div class="empty">No recent presets</div>
            <a href="/api/scenarios" class="button" style="margin-top: 12px;">
              Browse Templates
            </a>
          </div>

          <div class="panel">
            <p class="kicker">System</p>
            <h2 class="panel-title">Status</h2>
            <p class="caption">All systems operational</p>
            <div style="display: flex; gap: 8px; flex-wrap: wrap;">
              <span class="tag tag-goal">API Online</span>
              <span class="tag tag-goal">Workers Ready</span>
              <span class="tag tag-goal">KV Available</span>
            </div>
          </div>

          <div class="panel">
            <p class="kicker">Alerts</p>
            <h2 class="panel-title">Notifications</h2>
            <p class="caption">1 critical alert</p>
            <div class="alerts">
              <a href="/health" class="alert-pill">
                <span class="bang">!</span>
                Authentication service restart required
              </a>
            </div>
          </div>
        </div>

        <div style="margin-top: 24px;">
          <div class="panel">
            <p class="kicker">Cyberrange</p>
            <h2 class="panel-title">Welcome to Your Security Training Platform</h2>
            <p class="caption">Build, deploy, and manage cybersecurity training scenarios on Cloudflare Workers</p>
          </div>
        </div>
      </div>
    </div>
  </body>
</html>`;

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    // Dashboard - serve HTML
    if (path === '/') {
      return new Response(DASHBOARD_HTML, {
        headers: { 'Content-Type': 'text/html;charset=UTF-8' },
      });
    }

    // Health check endpoint
    if (path === '/health') {
      return new Response(JSON.stringify({ status: 'ok', timestamp: Date.now() }), {
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // API root
    if (path === '/api') {
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
          timestamp: Date.now(),
        }),
        { headers: { 'Content-Type': 'application/json' } }
      );
    }

    // 404 for unknown routes
    return new Response('Not Found', { status: 404 });
  },
};
