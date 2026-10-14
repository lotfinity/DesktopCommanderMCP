# Synaptic Fleet

A self-hosted central dashboard and authenticated MCP gateway for DesktopCommanderMCP. This is an independent fleet layer, not the proprietary Remote Desktop Commander service or a copy of its private implementation.

## What works

- One central Streamable HTTP MCP endpoint, with explicit device routing.
- Outbound authenticated WebSocket device agents wrapping the existing stdio backend.
- Dashboard: device cards, live status, tool schemas, JSON tool console, image results, enrollment, client credentials and activity.
- One-use pairing codes (10 minutes), separate hashed device credentials, scoped client keys and revocation.
- Reconnect with exponential backoff, keepalive, bounded concurrency, disconnect/timeout handling without automatic command replay.
- Persistent registry, credential hashes and the latest 500 activity events. Arguments and result payloads are not recorded.
- Restartable services and a containerized central host; no incoming device ports required.

## Central host

Node.js >=22.12. From this directory:

```sh
npm ci
FLEET_PUBLIC_URL=https://your-host.example FLEET_HOST=127.0.0.1 npm start
```

Default local port: 8800. Persistent data defaults to `runtime/`, or set `FLEET_DATA`. The owner key is generated once in `runtime/admin-key`, mode 0600. Sign in with that key. The owner can also issue one-use login links from the authenticated `/api/login-links` endpoint; links expire after 10 minutes and redeem into 12-hour browser sessions. Signing out invalidates these sessions. Serve TLS with a reverse proxy that supports WebSocket upgrades. Keep the runtime directory on persistent storage and back it up securely; the owner key grants full fleet access.

For private Tailscale access, expose this port with Tailscale Serve. For a container, bind inside the container to 0.0.0.0 and persist `/data`; terminate HTTPS at the reverse proxy. Changing the central hostname requires updating each agent's `server` URL in its configuration and restarting the agent.

## Agent

From this directory on Linux or Windows, install the fleet dependencies and the local backend:

```sh
npm ci
# On POSIX shells; set the same environment variable in PowerShell on Windows:
PUPPETEER_SKIP_DOWNLOAD=true npm install --no-save @wonderwhy-er/desktop-commander@0.3.0
node agent.mjs --server https://your-host.example --pair PAIRING_CODE
```

Create the pairing code from the dashboard. Use `--backend /absolute/path/to/dist/index.js` to wrap an existing stdio backend (including a built checkout). `--config /path/to/agent.json` selects a separate device identity/configuration. Default configuration: `~/.config/synaptic-fleet/agent.json`, mode 0600. Subsequent launches need no pairing code: `node agent.mjs`. Remote URLs require HTTPS; HTTP is allowed only for localhost testing.

The backend process stays local. Files, running processes and process/session IDs belong to the target device. The gateway forwards native MCP content, including images. The agent exits when its backend exits so a service manager can restart both.

## AI connection

Create a scoped client key in **AI connections**. Configure an MCP client supporting Streamable HTTP with URL `https://your-host.example/mcp` and header `Authorization: Bearer CLIENT_KEY`. The endpoint requires authentication for discovery and execution. Tools include `list_devices`, `device_tools`, `call_device_tool`, and `dc_` aliases of native tools with a required `deviceId`.

Browser OAuth is also implemented: discovery metadata, dynamic public-client registration, PKCE S256, explicit owner consent with device scope, one-use authorization codes, one-hour access tokens and rotating refresh tokens. OAuth grants can be revoked in the dashboard. Set FLEET_PUBLIC_URL to the exact HTTPS origin. ChatGPT's cloud cannot reach a tailnet-only endpoint directly. Do not make the endpoint public without HTTPS and keep authentication enabled.

## Deployment and tests

```sh
npm test
docker build -t synaptic-fleet .
docker run -d --name synaptic-fleet -p 127.0.0.1:8800:8800 -v fleet-data:/data -e FLEET_PUBLIC_URL=https://your-host.example synaptic-fleet
```

See `deploy/*.service.example` for user systemd units; replace paths before installation. Run each device agent as the OS user whose files and processes the AI should access.

## Current scope

Single-owner fleet, not multi-tenant SaaS. No billing, account recovery, automatic agent updates, HA/failover, native Android APK, desktop streaming, or multi-user role management in this release. Linux is verified on Inspiron; Windows and Android/Termux are portable agent targets but have not been physically verified. PDF rendering may need Chromium and other platform dependencies. Device credentials can be revoked centrally; do not replay a timed-out state-changing call without checking its outcome.

The central service performs no terminal/file actions on its own host. Only explicitly enrolled agents execute requests. Dashboard credentials use browser session storage; a tab sign-out clears the browser key, while server-side revocation invalidates client/device keys. Treat owner keys and agent configuration as credentials. Proxy deployment, filesystem permissions and Node/backend updates remain the operator's responsibility.

## License

This fleet extension uses the parent repository's MIT license. DesktopCommanderMCP remains credited to its upstream authors. Fleet code is independent of the proprietary hosted service.
