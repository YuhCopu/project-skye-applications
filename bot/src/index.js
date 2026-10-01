import 'dotenv/config';
import http from 'http';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

import {
  Client,
  GatewayIntentBits,
  Partials,
  ActionRowBuilder,
  ButtonBuilder,
  ButtonStyle,
  EmbedBuilder,
  ModalBuilder,
  TextInputBuilder,
  TextInputStyle,
} from 'discord.js';

import {
  load,
  save,
  allSubmissions,
  defaults,
  updateSubmission,
} from './config.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMembers,
    GatewayIntentBits.DirectMessages,
    GatewayIntentBits.MessageContent,
  ],
  partials: [Partials.Channel],
});

const cfg = load();

const sessions = new Map();
const dashboardSessions = new Map();

const trustedUsers = new Set(
  String(
    process.env.TRUSTED_USER_IDS ||
      process.env.TRUSTED_USERS ||
      ''
  )
    .split(',')
    .map((x) => x.trim())
    .filter(Boolean)
);

if (process.env.TRUSTED_USER_ID) {
  trustedUsers.add(process.env.TRUSTED_USER_ID.trim());
}

const publicUrl =
  process.env.PUBLIC_URL ||
  'https://project-skye-applications.onrender.com';

const oauthRedirect =
  process.env.DISCORD_OAUTH_REDIRECT ||
  'https://project-skye-applications.onrender.com/oauth/callback';

const oauthConfigured = Boolean(
  process.env.CLIENT_ID &&
    process.env.DISCORD_CLIENT_SECRET
);

const dashboardPort = Number(
  process.env.PORT ||
    process.env.DASHBOARD_PORT ||
    8787
);

/* =========================================================
   HELPERS
========================================================= */

function json(res, status, data) {
  const body = JSON.stringify(data);

  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
  });

  res.end(body);
}

function html(res, status, body, headers = {}) {
  res.writeHead(status, {
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store',
    ...headers,
  });

  res.end(body);
}

function redirect(res, location, extraHeaders = {}) {
  res.writeHead(302, {
    Location: location,
    ...extraHeaders,
  });

  res.end();
}

function cookie(name, value, maxAge = 3600, httpOnly = true) {
  return [
    `${name}=${encodeURIComponent(value)}`,
    'Path=/',
    `Max-Age=${maxAge}`,
    'SameSite=Lax',
    'Secure',
    httpOnly ? 'HttpOnly' : '',
  ]
    .filter(Boolean)
    .join('; ');
}

function clearCookie(name) {
  return [
    `${name}=`,
    'Path=/',
    'Max-Age=0',
    'SameSite=Lax',
    'Secure',
    'HttpOnly',
  ].join('; ');
}

function parseCookies(req) {
  const result = {};

  const raw = req.headers.cookie || '';

  for (const part of raw.split(';')) {
    const index = part.indexOf('=');

    if (index === -1) continue;

    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();

    result[key] = decodeURIComponent(value);
  }

  return result;
}

function getRequestBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';

    req.on('data', (chunk) => {
      body += chunk;

      if (body.length > 2_000_000) {
        reject(new Error('Request body too large.'));
        req.destroy();
      }
    });

    req.on('end', () => {
      if (!body) {
        resolve({});
        return;
      }

      try {
        resolve(JSON.parse(body));
      } catch {
        reject(new Error('Invalid JSON.'));
      }
    });

    req.on('error', reject);
  });
}

function isTrusted(userId) {
  return trustedUsers.has(String(userId));
}

function makeId(prefix = 'id') {
  return `${prefix}_${crypto.randomBytes(10).toString('hex')}`;
}

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

/* =========================================================
   OAUTH
========================================================= */

/*
 * IMPORTANT:
 *
 * OAuth state is now stateless.
 *
 * We sign the state with the Discord client secret instead
 * of keeping it in a memory Map.
 *
 * This means Render restarts / multiple instances will not
 * destroy the OAuth state.
 */

function oauthStateSecret() {
  return String(
    process.env.DISCORD_CLIENT_SECRET ||
      process.env.DISCORD_TOKEN ||
      'skye-oauth-fallback-secret'
  );
}

function createOAuthState() {
  const payload = JSON.stringify({
    nonce: crypto.randomBytes(32).toString('hex'),
    createdAt: Date.now(),
  });

  const encoded = Buffer.from(payload).toString('base64url');

  const signature = crypto
    .createHmac('sha256', oauthStateSecret())
    .update(encoded)
    .digest('base64url');

  return `${encoded}.${signature}`;
}

function verifyOAuthState(state) {
  if (!state || typeof state !== 'string') {
    return false;
  }

  const parts = state.split('.');

  if (parts.length !== 2) {
    return false;
  }

  const [encoded, signature] = parts;

  const expected = crypto
    .createHmac('sha256', oauthStateSecret())
    .update(encoded)
    .digest('base64url');

  const a = Buffer.from(signature);
  const b = Buffer.from(expected);

  if (
    a.length !== b.length ||
    !crypto.timingSafeEqual(a, b)
  ) {
    return false;
  }

  try {
    const payload = JSON.parse(
      Buffer.from(encoded, 'base64url').toString('utf8')
    );

    if (!payload.createdAt) {
      return false;
    }

    const age = Date.now() - Number(payload.createdAt);

    if (age < 0 || age > 10 * 60 * 1000) {
      return false;
    }

    return true;
  } catch {
    return false;
  }
}

function oauthLogin(req, res) {
  if (!oauthConfigured) {
    html(
      res,
      500,
      `
      <!doctype html>
      <html>
        <head>
          <meta charset="utf-8">
          <title>OAuth not configured</title>
        </head>
        <body style="font-family:Arial;padding:40px">
          <h1>Discord OAuth is not configured</h1>
          <p>CLIENT_ID and DISCORD_CLIENT_SECRET must be configured in Render.</p>
        </body>
      </html>
      `
    );

    return;
  }

  const state = createOAuthState();

  const params = new URLSearchParams({
    client_id: process.env.CLIENT_ID,
    response_type: 'code',
    redirect_uri: oauthRedirect,
    scope: 'identify',
    state,
  });

  const authorizeUrl =
    'https://discord.com/oauth2/authorize?' +
    params.toString();

  console.log('[OAUTH] Starting login');
  console.log('[OAUTH] Redirect URI:', oauthRedirect);
  console.log('[OAUTH] State generated:', state.slice(0, 20) + '...');

  redirect(res, authorizeUrl);
}

async function oauthCallback(req, res, url) {
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  const error = url.searchParams.get('error');

  console.log('[OAUTH CALLBACK] Received callback');
  console.log(
    '[OAUTH CALLBACK] State received:',
    state ? `${state.slice(0, 20)}...` : 'MISSING'
  );

  if (error) {
    console.error(
      '[OAUTH CALLBACK] Discord returned error:',
      error
    );

    html(
      res,
      400,
      `
      <!doctype html>
      <html>
        <head>
          <meta charset="utf-8">
          <title>Discord Login Error</title>
        </head>
        <body style="font-family:Arial;padding:40px">
          <h1>Discord login failed</h1>
          <p>${escapeHtml(error)}</p>
          <p><a href="/login">Try again</a></p>
        </body>
      </html>
      `
    );

    return;
  }

  if (!code) {
    html(
      res,
      400,
      `
      <!doctype html>
      <html>
        <body style="font-family:Arial;padding:40px">
          <h1>Missing OAuth code</h1>
          <p><a href="/login">Try again</a></p>
        </body>
      </html>
      `
    );

    return;
  }

  if (!state || !verifyOAuthState(state)) {
    console.error('[OAUTH CALLBACK] Invalid or expired OAuth state.');

    html(
      res,
      400,
      `
      <!doctype html>
      <html>
        <head>
          <meta charset="utf-8">
          <title>OAuth Error</title>
        </head>
        <body style="font-family:Arial;padding:40px">
          <h1>Invalid or expired OAuth state.</h1>
          <p>Please start the Discord login again.</p>
          <p><a href="/login">Try again</a></p>
        </body>
      </html>
      `
    );

    return;
  }

  try {
    console.log('[OAUTH CALLBACK] State verified.');
    console.log('[OAUTH CALLBACK] Exchanging code with Discord...');

    const tokenResponse = await fetch(
      'https://discord.com/api/oauth2/token',
      {
        method: 'POST',
        headers: {
          'Content-Type':
            'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          client_id: process.env.CLIENT_ID,
          client_secret: process.env.DISCORD_CLIENT_SECRET,
          grant_type: 'authorization_code',
          code,
          redirect_uri: oauthRedirect,
        }),
      }
    );

    const tokenText = await tokenResponse.text();

    if (!tokenResponse.ok) {
      console.error(
        '[OAUTH CALLBACK] Token exchange failed:',
        tokenResponse.status,
        tokenText
      );

      html(
        res,
        500,
        `
        <!doctype html>
        <html>
          <body style="font-family:Arial;padding:40px">
            <h1>Discord OAuth token exchange failed</h1>
            <p>Check the Render logs for details.</p>
            <p><a href="/login">Try again</a></p>
          </body>
        </html>
        `
      );

      return;
    }

    const token = JSON.parse(tokenText);

    const userResponse = await fetch(
      'https://discord.com/api/users/@me',
      {
        headers: {
          Authorization: `${token.token_type} ${token.access_token}`,
        },
      }
    );

    if (!userResponse.ok) {
      console.error(
        '[OAUTH CALLBACK] Failed to fetch Discord user:',
        userResponse.status
      );

      html(
        res,
        500,
        `
        <!doctype html>
        <html>
          <body style="font-family:Arial;padding:40px">
            <h1>Could not read your Discord account.</h1>
            <p><a href="/login">Try again</a></p>
          </body>
        </html>
        `
      );

      return;
    }

    const user = await userResponse.json();

    console.log(
      '[OAUTH CALLBACK] Logged in Discord user:',
      user.username,
      user.id
    );

    const sessionId = crypto
      .randomBytes(32)
      .toString('hex');

    dashboardSessions.set(sessionId, {
      userId: user.id,
      username: user.username,
      avatar: user.avatar || null,
      createdAt: Date.now(),
      expires: Date.now() + 24 * 60 * 60 * 1000,
    });

    redirect(res, '/', {
      'Set-Cookie': cookie(
        'skye_dashboard_session',
        sessionId,
        24 * 60 * 60,
        true
      ),
    });
  } catch (error) {
    console.error('[OAUTH CALLBACK] Unexpected error:', error);

    html(
      res,
      500,
      `
      <!doctype html>
      <html>
        <body style="font-family:Arial;padding:40px">
          <h1>Discord login failed</h1>
          <p>An unexpected error occurred.</p>
          <p><a href="/login">Try again</a></p>
        </body>
      </html>
      `
    );
  }
}

/* =========================================================
   DASHBOARD AUTH
========================================================= */

function getDashboardSession(req) {
  const cookies = parseCookies(req);

  const sessionId =
    cookies.skye_dashboard_session;

  if (!sessionId) {
    return null;
  }

  const session = dashboardSessions.get(sessionId);

  if (!session) {
    return null;
  }

  if (session.expires < Date.now()) {
    dashboardSessions.delete(sessionId);
    return null;
  }

  return session;
}

function requireDashboardAuth(req, res) {
  const session = getDashboardSession(req);

  if (!session) {
    json(res, 401, {
      error: 'Not authenticated.',
    });

    return null;
  }

  return session;
}

function requireTrustedDashboard(req, res) {
  const session = requireDashboardAuth(req, res);

  if (!session) {
    return null;
  }

  if (!isTrusted(session.userId)) {
    json(res, 403, {
      error: 'You are not a trusted Skye administrator.',
    });

    return null;
  }

  return session;
}

/* =========================================================
   DASHBOARD HTML
========================================================= */

function dashboardPage() {
  return `
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Skye Applications</title>

  <style>
    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      font-family: Inter, Arial, sans-serif;
      background: #0d1117;
      color: #f0f6fc;
    }

    a {
      color: inherit;
    }

    .wrap {
      max-width: 1200px;
      margin: 0 auto;
      padding: 32px 20px;
    }

    .top {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 20px;
      margin-bottom: 30px;
    }

    .brand h1 {
      margin: 0;
      font-size: 30px;
    }

    .brand p {
      margin: 6px 0 0;
      color: #8b949e;
    }

    .button {
      display: inline-block;
      padding: 11px 16px;
      border-radius: 8px;
      text-decoration: none;
      border: 1px solid #30363d;
      background: #161b22;
      color: #fff;
      cursor: pointer;
    }

    .button.primary {
      background: #5865f2;
      border-color: #5865f2;
    }

    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit,minmax(220px,1fr));
      gap: 16px;
    }

    .card {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 12px;
      padding: 20px;
      margin-bottom: 20px;
    }

    .stat {
      font-size: 34px;
      font-weight: 700;
      margin-top: 8px;
    }

    .muted {
      color: #8b949e;
    }

    table {
      width: 100%;
      border-collapse: collapse;
    }

    th,
    td {
      padding: 12px;
      border-bottom: 1px solid #30363d;
      text-align: left;
      vertical-align: top;
    }

    th {
      color: #8b949e;
      font-weight: 600;
    }

    pre {
      white-space: pre-wrap;
      word-break: break-word;
      background: #0d1117;
      padding: 12px;
      border-radius: 8px;
    }

    .error {
      color: #ff7b72;
    }

    .success {
      color: #7ee787;
    }

    @media (max-width: 700px) {
      .top {
        flex-direction: column;
        align-items: flex-start;
      }

      table {
        font-size: 13px;
      }
    }
  </style>
</head>

<body>
  <div class="wrap">
    <div class="top">
      <div class="brand">
        <h1>Skye Applications</h1>
        <p>Application dashboard</p>
      </div>

      <div>
        <a class="button" href="/api/logout">Logout</a>
      </div>
    </div>

    <div id="app">
      <div class="card">
        Loading dashboard...
      </div>
    </div>
  </div>

<script>
async function api(url, options = {}) {
  const response = await fetch(url, {
    credentials: 'same-origin',
    ...options
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(data.error || 'Request failed');
  }

  return data;
}

function esc(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

async function loadDashboard() {
  const app = document.getElementById('app');

  try {
    const me = await api('/api/me');

    if (!me.authenticated) {
      window.location.href = '/login';
      return;
    }

    if (!me.trusted) {
      app.innerHTML = \`
        <div class="card">
          <h2>Access denied</h2>
          <p class="muted">
            Your Discord account is not configured as a trusted administrator.
          </p>
        </div>
      \`;
      return;
    }

    const [config, submissions] = await Promise.all([
      api('/api/config'),
      api('/api/submissions')
    ]);

    const list = submissions.submissions || [];

    const pending = list.filter(
      x => String(x.status || '').toLowerCase() === 'pending'
    ).length;

    const accepted = list.filter(
      x => String(x.status || '').toLowerCase() === 'accepted'
    ).length;

    const denied = list.filter(
      x => String(x.status || '').toLowerCase() === 'denied'
    ).length;

    app.innerHTML = \`
      <div class="grid">
        <div class="card">
          <div class="muted">Total Applications</div>
          <div class="stat">\${list.length}</div>
        </div>

        <div class="card">
          <div class="muted">Pending</div>
          <div class="stat">\${pending}</div>
        </div>

        <div class="card">
          <div class="muted">Accepted</div>
          <div class="stat">\${accepted}</div>
        </div>

        <div class="card">
          <div class="muted">Denied</div>
          <div class="stat">\${denied}</div>
        </div>
      </div>

      <div class="card">
        <h2>Configuration</h2>
        <pre>\${esc(JSON.stringify(config.config, null, 2))}</pre>
      </div>

      <div class="card">
        <h2>Applications</h2>

        <div style="overflow:auto">
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>User</th>
                <th>Status</th>
                <th>Created</th>
                <th>Answers</th>
              </tr>
            </thead>

            <tbody>
              \${list.length
                ? list.map(item => \`
                  <tr>
                    <td>\${esc(item.id || '')}</td>
                    <td>
                      <strong>\${esc(item.username || item.userId || 'Unknown')}</strong>
                      <br>
                      <span class="muted">\${esc(item.userId || '')}</span>
                    </td>
                    <td>\${esc(item.status || 'pending')}</td>
                    <td>\${item.createdAt ? new Date(item.createdAt).toLocaleString() : ''}</td>
                    <td>
                      <pre>\${esc(JSON.stringify(item.answers || item.responses || {}, null, 2))}</pre>
                    </td>
                  </tr>
                \`).join('')
                : '<tr><td colspan="5">No applications yet.</td></tr>'
              }
            </tbody>
          </table>
        </div>
      </div>
    \`;
  } catch (error) {
    app.innerHTML = \`
      <div class="card">
        <h2 class="error">Dashboard error</h2>
        <p>\${esc(error.message)}</p>
      </div>
    \`;
  }
}

loadDashboard();
</script>
</body>
</html>
`;
}

/* =========================================================
   DASHBOARD API
========================================================= */

async function handleDashboard(req, res, url) {
  if (url.pathname === '/login') {
    oauthLogin(req, res);
    return;
  }

  if (url.pathname === '/oauth/callback') {
    await oauthCallback(req, res, url);
    return;
  }

  if (url.pathname === '/api/logout') {
    const cookies = parseCookies(req);

    if (cookies.skye_dashboard_session) {
      dashboardSessions.delete(
        cookies.skye_dashboard_session
      );
    }

    redirect(res, '/login', {
      'Set-Cookie': clearCookie(
        'skye_dashboard_session'
      ),
    });

    return;
  }

  if (url.pathname === '/api/health') {
    json(res, 200, {
      ok: true,
      service: 'Skye Applications',
      online: client.isReady(),
      user: client.user
        ? `${client.user.username}#${client.user.discriminator}`
        : null,
      timestamp: Date.now(),
    });

    return;
  }

  if (url.pathname === '/api/me') {
    const session = getDashboardSession(req);

    json(res, 200, {
      authenticated: Boolean(session),
      trusted: session
        ? isTrusted(session.userId)
        : false,
      user: session
        ? {
            id: session.userId,
            username: session.username,
            avatar: session.avatar,
          }
        : null,
    });

    return;
  }

  if (url.pathname === '/api/config') {
    const session = requireTrustedDashboard(req, res);

    if (!session) return;

    json(res, 200, {
      config: cfg,
    });

    return;
  }

  if (url.pathname === '/api/submissions') {
    const session = requireTrustedDashboard(req, res);

    if (!session) return;

    json(res, 200, {
      submissions: allSubmissions(),
    });

    return;
  }

  if (url.pathname === '/api/trusted') {
    const session = requireTrustedDashboard(req, res);

    if (!session) return;

    json(res, 200, {
      trustedUsers: [...trustedUsers],
    });

    return;
  }

  if (
    url.pathname === '/api/reset' &&
    req.method === 'POST'
  ) {
    const session = requireTrustedDashboard(req, res);

    if (!session) return;

    save(defaults);

    json(res, 200, {
      ok: true,
      message: 'Configuration reset.',
    });

    return;
  }

  if (url.pathname === '/' || url.pathname === '/index.html') {
    const session = getDashboardSession(req);

    if (!session) {
      redirect(res, '/login');
      return;
    }

    html(res, 200, dashboardPage());
    return;
  }

  const sitePath = path.resolve(
    __dirname,
    '../../dashboard/site'
  );

  let requestedPath = url.pathname;

  if (requestedPath === '/') {
    requestedPath = '/index.html';
  }

  const filePath = path.join(
    sitePath,
    requestedPath
  );

  if (
    filePath.startsWith(sitePath) &&
    fs.existsSync(filePath) &&
    fs.statSync(filePath).isFile()
  ) {
    const ext = path.extname(filePath);

    const types = {
      '.html': 'text/html; charset=utf-8',
      '.css': 'text/css; charset=utf-8',
      '.js': 'application/javascript; charset=utf-8',
      '.json': 'application/json; charset=utf-8',
      '.png': 'image/png',
      '.jpg': 'image/jpeg',
      '.jpeg': 'image/jpeg',
      '.svg': 'image/svg+xml',
      '.ico': 'image/x-icon',
    };

    res.writeHead(200, {
      'Content-Type':
        types[ext] || 'application/octet-stream',
    });

    fs.createReadStream(filePath).pipe(res);
    return;
  }

  json(res, 404, {
    error: 'Not found.',
  });
}

/* =========================================================
   APPLICATION SYSTEM
========================================================= */

const applicationSessions = new Map();

function getApplicationQuestions() {
  return (
    cfg.applicationQuestions ||
    cfg.questions ||
    defaults.applicationQuestions ||
    defaults.questions ||
    [
      'What is your Discord username?',
      'How old are you?',
      'Why do you want to join?',
      'What experience do you have?',
      'Anything else we should know?',
    ]
  );
}

function applicationChannelId() {
  return (
    cfg.applicationChannelId ||
    cfg.application_channel_id ||
    process.env.APPLICATION_CHANNEL_ID ||
    null
  );
}

function reviewChannelId() {
  return (
    cfg.reviewChannelId ||
    cfg.review_channel_id ||
    process.env.REVIEW_CHANNEL_ID ||
    applicationChannelId()
  );
}

function applicationRoleId() {
  return (
    cfg.applicationRoleId ||
    cfg.application_role_id ||
    process.env.APPLICATION_ROLE_ID ||
    null
  );
}

function buildApplicationEmbed() {
  return new EmbedBuilder()
    .setTitle(
      cfg.applicationTitle ||
        'Skye Applications'
    )
    .setDescription(
      cfg.applicationDescription ||
        'Click the button below to start an application.'
    )
    .setColor(0x5865f2);
}

function buildApplicationRow() {
  return new ActionRowBuilder().addComponents(
    new ButtonBuilder()
      .setCustomId('skye_application_start')
      .setLabel(
        cfg.applicationButtonLabel ||
          'Start Application'
      )
      .setStyle(ButtonStyle.Primary)
  );
}

async function sendApplicationPanel() {
  const channelId = applicationChannelId();

  if (!channelId) {
    console.log(
      '[APPLICATIONS] No application channel configured.'
    );
    return;
  }

  try {
    const channel = await client.channels.fetch(
      channelId
    );

    if (!channel || !channel.isTextBased()) {
      console.log(
        '[APPLICATIONS] Application channel is not text based.'
      );
      return;
    }

    await channel.send({
      embeds: [buildApplicationEmbed()],
      components: [buildApplicationRow()],
    });

    console.log(
      '[APPLICATIONS] Application panel sent.'
    );
  } catch (error) {
    console.error(
      '[APPLICATIONS] Failed to send panel:',
      error
    );
  }
}

async function startApplication(interaction) {
  const userId = interaction.user.id;

  if (applicationSessions.has(userId)) {
    await interaction.reply({
      content:
        'You already have an application in progress.',
      ephemeral: true,
    });

    return;
  }

  const questions = getApplicationQuestions();

  if (!questions.length) {
    await interaction.reply({
      content:
        'No application questions are configured.',
      ephemeral: true,
    });

    return;
  }

  applicationSessions.set(userId, {
    userId,
    username: interaction.user.username,
    answers: {},
    questionIndex: 0,
    createdAt: Date.now(),
    expires: Date.now() + 3 * 60 * 60 * 1000,
  });

  await interaction.reply({
    content:
      'Your application has started. I will DM you the questions.',
    ephemeral: true,
  });

  try {
    const dm = await interaction.user.createDM();

    await dm.send(
      `**${cfg.applicationTitle || 'Skye Application'}**\n\n` +
        `You have 3 hours to complete your application.\n\n` +
        `Question 1 of ${questions.length}:\n**${questions[0]}**`
    );
  } catch (error) {
    applicationSessions.delete(userId);

    console.error(
      '[APPLICATIONS] Could not DM applicant:',
      error
    );

    await interaction.followUp({
      content:
        'I could not DM you. Please enable DMs from server members and try again.',
      ephemeral: true,
    });
  }
}

async function handleApplicationDM(message) {
  if (message.author.bot) return;

  const session = applicationSessions.get(
    message.author.id
  );

  if (!session) return;

  if (session.expires < Date.now()) {
    applicationSessions.delete(message.author.id);

    await message.reply(
      'Your application session expired. Please start a new application.'
    );

    return;
  }

  const questions = getApplicationQuestions();

  const index = session.questionIndex;

  session.answers[index] = message.content.trim();

  session.questionIndex += 1;

  if (session.questionIndex >= questions.length) {
    applicationSessions.delete(message.author.id);

    const submission = {
      id: makeId('application'),
      userId: message.author.id,
      username: message.author.username,
      discriminator: message.author.discriminator,
      answers: session.answers,
      questions,
      status: 'pending',
      createdAt: Date.now(),
    };

    updateSubmission(
      submission.id,
      submission
    );

    await message.reply(
      'Your application has been submitted. Thank you!'
    );

    await sendApplicationForReview(submission);

    return;
  }

  const nextQuestion =
    questions[session.questionIndex];

  await message.reply(
    `Question ${session.questionIndex + 1} of ${questions.length}:\n**${nextQuestion}**`
  );
}

async function sendApplicationForReview(submission) {
  const channelId = reviewChannelId();

  if (!channelId) {
    console.log(
      '[APPLICATIONS] No review channel configured.'
    );
    return;
  }

  try {
    const channel = await client.channels.fetch(
      channelId
    );

    if (!channel || !channel.isTextBased()) {
      return;
    }

    const answerText = submission.questions
      .map(
        (question, index) =>
          `**${question}**\n${submission.answers[index] || '(No answer)'}`
      )
      .join('\n\n');

    const embed = new EmbedBuilder()
      .setTitle('New Application')
      .setDescription(answerText)
      .addFields(
        {
          name: 'Applicant',
          value: `<@${submission.userId}>`,
          inline: true,
        },
        {
          name: 'Application ID',
          value: submission.id,
          inline: true,
        },
        {
          name: 'Status',
          value: 'Pending',
          inline: true,
        }
      )
      .setColor(0xfee75c)
      .setTimestamp();

    const row = new ActionRowBuilder().addComponents(
      new ButtonBuilder()
        .setCustomId(
          `skye_accept_${submission.id}`
        )
        .setLabel('Accept')
        .setStyle(ButtonStyle.Success),

      new ButtonBuilder()
        .setCustomId(
          `skye_deny_${submission.id}`
        )
        .setLabel('Deny')
        .setStyle(ButtonStyle.Danger)
    );

    const sent = await channel.send({
      embeds: [embed],
      components: [row],
    });

    updateSubmission(submission.id, {
      reviewMessageId: sent.id,
      reviewChannelId: channel.id,
    });
  } catch (error) {
    console.error(
      '[APPLICATIONS] Failed to send review:',
      error
    );
  }
}

/* =========================================================
   REVIEW ACTIONS
========================================================= */

async function showDecisionModal(
  interaction,
  action,
  submissionId
) {
  const modal = new ModalBuilder()
    .setCustomId(
      `skye_${action}_modal_${submissionId}`
    )
    .setTitle(
      action === 'accept'
        ? 'Accept Application'
        : 'Deny Application'
    );

  const reason = new TextInputBuilder()
    .setCustomId('reason')
    .setLabel(
      action === 'accept'
        ? 'Acceptance message'
        : 'Denial reason'
    )
    .setStyle(TextInputStyle.Paragraph)
    .setRequired(false)
    .setPlaceholder(
      action === 'accept'
        ? 'Optional message to the applicant'
        : 'Explain why the application was denied'
    );

  modal.addComponents(
    new ActionRowBuilder().addComponents(reason)
  );

  await interaction.showModal(modal);
}

async function handleDecisionModal(interaction) {
  const parts = interaction.customId.split('_');

  if (parts.length < 4) {
    return;
  }

  const action = parts[1];
  const submissionId = parts.slice(3).join('_');

  const submission =
    allSubmissions().find(
      (item) => item.id === submissionId
    );

  if (!submission) {
    await interaction.reply({
      content: 'Application not found.',
      ephemeral: true,
    });

    return;
  }

  const reason =
    interaction.fields.getTextInputValue(
      'reason'
    ) || '';

  const status =
    action === 'accept'
      ? 'accepted'
      : 'denied';

  updateSubmission(submissionId, {
    status,
    decisionReason: reason,
    decidedBy: interaction.user.id,
    decidedByUsername: interaction.user.username,
    decidedAt: Date.now(),
  });

  try {
    const user = await client.users.fetch(
      submission.userId
    );

    const message =
      status === 'accepted'
        ? `Your application has been **accepted**!${
            reason ? `\n\n${reason}` : ''
          }`
        : `Your application has been **denied**.${
            reason ? `\n\nReason: ${reason}` : ''
          }`;

    await user.send(message);
  } catch (error) {
    console.error(
      '[APPLICATIONS] Could not DM applicant decision:',
      error
    );
  }

  await interaction.reply({
    content:
      status === 'accepted'
        ? 'Application accepted.'
        : 'Application denied.',
    ephemeral: true,
  });

  if (interaction.message) {
    const disabledRow =
      new ActionRowBuilder().addComponents(
        new ButtonBuilder()
          .setCustomId(
            `skye_done_accept_${submissionId}`
          )
          .setLabel(
            status === 'accepted'
              ? 'Accepted'
              : 'Accepted'
          )
          .setStyle(ButtonStyle.Success)
          .setDisabled(true),

        new ButtonBuilder()
          .setCustomId(
            `skye_done_deny_${submissionId}`
          )
          .setLabel(
            status === 'denied'
              ? 'Denied'
              : 'Denied'
          )
          .setStyle(ButtonStyle.Danger)
          .setDisabled(true)
      );

    await interaction.message.edit({
      components: [disabledRow],
    }).catch(() => {});
  }
}

/* =========================================================
   COMMANDS / BOT READY
========================================================= */

client.once('ready', async () => {
  console.log(
    `Skye Applications online as ${client.user.tag}`
  );

  console.log(
    `Skye dashboard: http://127.0.0.1:${dashboardPort}`
  );

  try {
    const guilds = [...client.guilds.cache.values()];

    for (const guild of guilds) {
      console.log(
        `[DISCORD] Connected to ${guild.name} (${guild.id})`
      );
    }
  } catch (error) {
    console.error(
      '[DISCORD] Guild logging error:',
      error
    );
  }
});

client.on('interactionCreate', async (interaction) => {
  try {
    if (interaction.isButton()) {
      if (
        interaction.customId ===
        'skye_application_start'
      ) {
        await startApplication(interaction);
        return;
      }

      if (
        interaction.customId.startsWith(
          'skye_accept_'
        )
      ) {
        const submissionId =
          interaction.customId.slice(
            'skye_accept_'.length
          );

        await showDecisionModal(
          interaction,
          'accept',
          submissionId
        );

        return;
      }

      if (
        interaction.customId.startsWith(
          'skye_deny_'
        )
      ) {
        const submissionId =
          interaction.customId.slice(
            'skye_deny_'.length
          );

        await showDecisionModal(
          interaction,
          'deny',
          submissionId
        );

        return;
      }
    }

    if (interaction.isModalSubmit()) {
      if (
        interaction.customId.startsWith(
          'skye_accept_modal_'
        ) ||
        interaction.customId.startsWith(
          'skye_deny_modal_'
        )
      ) {
        await handleDecisionModal(interaction);
        return;
      }
    }
  } catch (error) {
    console.error(
      '[INTERACTION ERROR]',
      error
    );

    if (!interaction.replied && !interaction.deferred) {
      await interaction.reply({
        content:
          'Something went wrong while processing that action.',
        ephemeral: true,
      }).catch(() => {});
    }
  }
});

client.on('messageCreate', async (message) => {
  try {
    await handleApplicationDM(message);
  } catch (error) {
    console.error(
      '[MESSAGE ERROR]',
      error
    );
  }
});

/* =========================================================
   DASHBOARD SERVER
========================================================= */

const server = http.createServer(
  async (req, res) => {
    try {
      const host =
        req.headers.host ||
        '127.0.0.1';

      const url = new URL(
        req.url || '/',
        `http://${host}`
      );

      await handleDashboard(
        req,
        res,
        url
      );
    } catch (error) {
      console.error(
        '[DASHBOARD ERROR]',
        error
      );

      if (!res.headersSent) {
        json(res, 500, {
          error: 'Internal server error.',
        });
      } else {
        res.end();
      }
    }
  }
);

server.listen(
  dashboardPort,
  '0.0.0.0',
  () => {
    console.log(
      `Skye dashboard listening on port ${dashboardPort}`
    );
  }
);

/* =========================================================
   CLEANUP
========================================================= */

setInterval(() => {
  const now = Date.now();

  for (const [
    userId,
    session,
  ] of applicationSessions) {
    if (session.expires < now) {
      applicationSessions.delete(userId);
    }
  }

  for (const [
    sessionId,
    session,
  ] of dashboardSessions) {
    if (session.expires < now) {
      dashboardSessions.delete(sessionId);
    }
  }
}, 60 * 1000);

/* =========================================================
   LOGIN
========================================================= */

if (!process.env.DISCORD_TOKEN) {
  console.error(
    'DISCORD_TOKEN is missing.'
  );
} else {
  client
    .login(process.env.DISCORD_TOKEN)
    .catch((error) => {
      console.error(
        'Discord login failed:',
        error
      );
    });
}