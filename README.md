# Cyberrange

A cybersecurity training range built on Cloudflare Workers.

## Project Structure

- `src/index.ts` - Main Worker entry point
- `wrangler.jsonc` - Cloudflare Workers configuration
- `package.json` - Project dependencies and scripts
- `tsconfig.json` - TypeScript configuration

## Setup

### Prerequisites

- [Node.js](https://nodejs.org/) (v18 or later)
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/install-and-update/)
- A [Cloudflare account](https://dash.cloudflare.com/sign-up)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/aaronjsmith/cyberrange.git
   cd cyberrange
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Authenticate with Cloudflare:
   ```bash
   npx wrangler login
   ```

## Development

- **Run locally:**
  ```bash
  npm run dev
  ```

- **Deploy to Cloudflare:**
  ```bash
  npm run deploy
  ```

- **View logs:**
  ```bash
  npm run tail
  ```

- **Type check:**
  ```bash
  npm run typecheck
  ```

## Configuration

Edit `wrangler.jsonc` to configure your Worker:
- `name` - Worker name
- `compatibility_date` - Workers runtime version
- `observability.enabled` - Enable Workers Logs

## API Endpoints

- `GET /` - API information
- `GET /health` - Health check
- `GET /api/status` - Environment status
- `GET /api/scenarios` - Scenario management (stub)

## License

MIT