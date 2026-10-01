import 'dotenv/config';
import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  Client,
  GatewayIntentBits,
  PermissionsBitField,
  EmbedBuilder,
  ActionRowBuilder,
  ButtonBuilder,
  ButtonStyle,
  ModalBuilder,
  TextInputBuilder,
  TextInputStyle,
} from 'discord.js';

import {
  load,
  save,
  nextId,
  addSubmission,
  updateSubmission,
  allSubmissions,
  defaults,
} from './config.js';

/* =========================================================
   BASIC SETUP
========================================================= */

const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMembers,
    GatewayIntentBits.DirectMessages,
    GatewayIntentBits.MessageContent,
  ],
  partials: ['CHANNEL'],
});

let cfg = load();

/*
 * IMPORTANT:
 * dashboardPort must exist BEFORE oauthRedirect is created.
 * This fixes the Render ReferenceError.
 */
let dashboardPort = Number(process.env.DASHBOARD_PORT || 8787);

const dashboardStarted = false;

const sessions = new Map();
const dashboardSessions = new Map();

const timeoutMs = 3 * 60 * 60 * 1000;

function envList(name) {
  return String(process.env[name] || '')
    .split(',')
    .map((x) => x.trim())
    .filter(Boolean);
}

const bootstrapTrusted = new Set(envList('TRUSTED_USER_IDS'));

if (bootstrapTrusted.size) {
  cfg.trustedUserIds = [
    ...new Set([
      ...(cfg.trustedUserIds || []),
      ...bootstrapTrusted,
    ]),
  ];

  save(cfg);
}

const publicUrl = String(process.env.PUBLIC_URL || '').replace(/\/$/, '');

const oauthRedirect =
  process.env.DISCORD_OAUTH_REDIRECT ||
  `${publicUrl || `http://127.0.0.1:${dashboardPort}`}/oauth/callback`;

const oauthConfigured = Boolean(
  process.env.DISCORD_CLIENT_SECRET &&
  process.env.CLIENT_ID
);

/* =========================================================
   DASHBOARD PATH
========================================================= */

const dashboardDist = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../dashboard/site'
);

/* =========================================================
   AUTH / COOKIES
========================================================= */

function cookieMap(req) {
  const out = {};

  for (const part of String(req.headers.cookie || '').split(';')) {
    const [k, ...v] = part.trim().split('=');

    if (k) {
      out[k] = decodeURIComponent(v.join('='));
    }
  }

  return out;
}

function cookie(
  name,
  value,
  maxAge = 604800,
  secure = Boolean(publicUrl.startsWith('https://'))
) {
  return [
    `${name}=${encodeURIComponent(value)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${maxAge}`,
    secure ? 'Secure' : '',
  ]
    .filter(Boolean)
    .join('; ');
}

function clearCookie(name) {
  return [
    `${name}=`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    'Max-Age=0',
  ].join('; ');
}

function trusted(id) {
  return (cfg.trustedUserIds || []).includes(id);
}

function sessionUser(req) {
  const token = cookieMap(req).skye_session;

  if (!token) return null;

  return dashboardSessions.get(token) || null;
}

function authRequired(req, res) {
  const user = sessionUser(req);

  if (!user) {
    res.writeHead(302, {
      Location: '/login',
    });

    res.end();
    return null;
  }

  if (!trusted(user.id)) {
    res.writeHead(403, {
      'Content-Type': 'text/html; charset=utf-8',
    });

    res.end(`
      <!doctype html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>Relive Dashboard</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
      </head>
      <body style="font-family:system-ui;background:#090b0f;color:#e8ecf5;display:grid;place-items:center;height:100vh;margin:0">
        <main style="max-width:520px;padding:30px;border:1px solid #272d39;border-radius:14px;background:#0e1218">
          <h2>Relive Dashboard</h2>
          <p>Your Discord account is authenticated, but it is not registered as a trusted dashboard user.</p>
          <p>Ask the Relive owner to add your Discord user ID to the trusted users list.</p>
          <a href="/logout" style="color:#aebfff">Sign out</a>
        </main>
      </body>
      </html>
    `);

    return null;
  }

  return user;
}

/* =========================================================
   OAUTH STATE
========================================================= */

/*
 * Render can restart the Node process at any time.
 *
 * The old version stored OAuth states in a Map:
 *
 *   oauthStates.set(...)
 *
 * That means a restart between login and callback caused:
 *
 *   Invalid or expired OAuth state.
 *
 * Instead, the state is now cryptographically signed.
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

  const actualBuffer = Buffer.from(signature);
  const expectedBuffer = Buffer.from(expected);

  if (
    actualBuffer.length !== expectedBuffer.length ||
    !crypto.timingSafeEqual(actualBuffer, expectedBuffer)
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

    return age >= 0 && age <= 10 * 60 * 1000;
  } catch {
    return false;
  }
}

/* =========================================================
   OAUTH LOGIN
========================================================= */

function oauthLogin(req, res) {
  if (!oauthConfigured) {
    res.writeHead(503, {
      'Content-Type': 'text/html; charset=utf-8',
    });

    return res.end(`
      <h2>Discord login is not configured.</h2>
      <p>Set DISCORD_CLIENT_SECRET and CLIENT_ID in Render.</p>
    `);
  }

  const state = createOAuthState();

  const redirect =
    oauthRedirect ||
    `http://${req.headers.host || `127.0.0.1:${dashboardPort}`}/oauth/callback`;

  /*
   * IMPORTANT:
   * state is included in the actual Discord OAuth URL.
   */
  const params = new URLSearchParams({
    client_id: process.env.CLIENT_ID,
    response_type: 'code',
    redirect_uri: redirect,
    scope: 'identify',
    state,
  });

  res.writeHead(302, {
    Location: `https://discord.com/oauth2/authorize?${params.toString()}`,
    'Set-Cookie': cookie('skye_oauth_state', state, 600),
  });

  res.end();
}

/* =========================================================
   OAUTH CALLBACK
========================================================= */

async function oauthCallback(req, res, url) {
  const state = url.searchParams.get('state') || '';
  const cookies = cookieMap(req);

  /*
   * Validate the signed state.
   *
   * We also check the browser cookie when available.
   */
  if (!verifyOAuthState(state)) {
    res.writeHead(400, {
      'Content-Type': 'text/plain; charset=utf-8',
    });

    return res.end('Invalid or expired OAuth state.');
  }

  if (
    cookies.skye_oauth_state &&
    cookies.skye_oauth_state !== state
  ) {
    res.writeHead(400, {
      'Content-Type': 'text/plain; charset=utf-8',
    });

    return res.end('Invalid OAuth session.');
  }

  const code = url.searchParams.get('code');

  if (!code) {
    res.writeHead(400, {
      'Content-Type': 'text/plain; charset=utf-8',
    });

    return res.end('Discord OAuth was cancelled or failed.');
  }

  const tokenRes = await fetch(
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

  if (!tokenRes.ok) {
    const errorText = await tokenRes.text().catch(() => '');

    console.error(
      'Discord OAuth token exchange failed:',
      tokenRes.status,
      errorText
    );

    res.writeHead(502, {
      'Content-Type': 'text/plain; charset=utf-8',
    });

    return res.end('Discord token exchange failed.');
  }

  const token = await tokenRes.json();

  const meRes = await fetch(
    'https://discord.com/api/users/@me',
    {
      headers: {
        Authorization: `Bearer ${token.access_token}`,
      },
    }
  );

  if (!meRes.ok) {
    res.writeHead(502, {
      'Content-Type': 'text/plain; charset=utf-8',
    });

    return res.end(
      'Could not read your Discord account.'
    );
  }

  const me = await meRes.json();

  const session = crypto
    .randomBytes(32)
    .toString('hex');

  dashboardSessions.set(session, {
    id: me.id,
    username: me.username,
    global_name: me.global_name || me.username,
    avatar: me.avatar || null,
    createdAt: Date.now(),
  });

  res.writeHead(302, {
    Location: '/',
    'Set-Cookie': [
      cookie('skye_session', session),
      clearCookie('skye_oauth_state'),
    ],
  });

  res.end();
}

/* =========================================================
   LOGIN PAGE
========================================================= */

function authPage() {
  return `
    <!doctype html>
    <html>
    <head>
      <meta charset="utf-8">
      <title>Relive Dashboard Login</title>
      <meta name="viewport" content="width=device-width,initial-scale=1">
    </head>
    <body style="font-family:system-ui;background:#090b0f;color:#e8ecf5;display:grid;place-items:center;height:100vh;margin:0">
      <main style="width:min(420px,calc(100% - 32px));padding:30px;border:1px solid #272d39;border-radius:16px;background:#0e1218;text-align:center">
        <div style="font-size:38px">☁️</div>
        <h1>Relive Applications</h1>
        <p style="color:#7f899b">Private dashboard. Discord authentication is required.</p>

        <a
          href="/login/start"
          style="display:block;padding:12px;border-radius:8px;background:#aebfff;color:#080a0e;text-decoration:none;font-weight:700"
        >
          Continue with Discord
        </a>
      </main>
    </body>
    </html>
  `;
}

/* =========================================================
   HTTP HELPERS
========================================================= */

const json = (res, status, data) => {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Cache-Control': 'no-store',
  });

  res.end(JSON.stringify(data));
};

const readBody = (req) =>
  new Promise((resolve, reject) => {
    let body = '';

    req.on('data', (chunk) => {
      body += chunk;

      if (body.length > 2_000_000) {
        req.destroy();
      }
    });

    req.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (e) {
        reject(e);
      }
    });

    req.on('error', reject);
  });

/* =========================================================
   CONFIG VALIDATION
========================================================= */

function safeConfig(input) {
  if (!input || typeof input !== 'object') {
    throw new Error('Invalid configuration.');
  }

  const next = structuredClone(defaults);

  const merge = (base, src) => {
    for (const [key, value] of Object.entries(src || {})) {
      if (
        value &&
        typeof value === 'object' &&
        !Array.isArray(value) &&
        base[key] &&
        typeof base[key] === 'object' &&
        !Array.isArray(base[key])
      ) {
        merge(base[key], value);
      } else if (key in base) {
        base[key] = value;
      }
    }
  };

  merge(next, input);

  next.trustedUserIds = Array.isArray(
    input.trustedUserIds
  )
    ? input.trustedUserIds
        .map(String)
        .filter((x) => /^\d{17,20}$/.test(x))
    : next.trustedUserIds;

  next.applicationTypes = Array.isArray(
    input.applicationTypes
  )
    ? input.applicationTypes
        .map((a) => ({
          ...a,
          questions: Array.isArray(a.questions)
            ? a.questions.map(String).filter(Boolean)
            : [],
          roles: {
            onSubmit: a.roles?.onSubmit || [],
            onAccept: a.roles?.onAccept || [],
            onDeny: a.roles?.onDeny || [],
            removeOnAccept:
              a.roles?.removeOnAccept || [],
            removeOnDeny:
              a.roles?.removeOnDeny || [],
          },
        }))
        .filter((a) => a.id && a.name)
    : next.applicationTypes;

  return next;
}

/* =========================================================
   DASHBOARD SERVER
========================================================= */

async function handleDashboard(req, res) {
  const url = new URL(
    req.url || '/',
    `http://${req.headers.host || '127.0.0.1'}`
  );

  /* OPTIONS */

  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Methods':
        'GET,PUT,POST,DELETE,OPTIONS',
      'Access-Control-Allow-Headers':
        'Content-Type',
    });

    return res.end();
  }

  /* LOGIN */

  if (
    url.pathname === '/login' &&
    req.method === 'GET'
  ) {
    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
    });

    return res.end(authPage());
  }

  if (
    url.pathname === '/login/start' &&
    req.method === 'GET'
  ) {
    return oauthLogin(req, res);
  }

  if (
    url.pathname === '/oauth/callback' &&
    req.method === 'GET'
  ) {
    return oauthCallback(req, res, url);
  }

  /* LOGOUT */

  if (
    url.pathname === '/logout' &&
    req.method === 'GET'
  ) {
    res.writeHead(302, {
      Location: '/login',
      'Set-Cookie': clearCookie('skye_session'),
    });

    res.end();

    return;
  }

  /* PUBLIC HEALTH */

  if (
    url.pathname === '/api/health' &&
    req.method === 'GET'
  ) {
    return json(res, 200, {
      online: client.isReady(),
      tag: client.user?.tag || null,
      dashboard: true,
      port: dashboardPort,
      authRequired: true,
    });
  }

  /* EVERYTHING BELOW HERE REQUIRES AUTH */

  const user = authRequired(req, res);

  if (!user) {
    return;
  }

  /* CURRENT USER */

  if (
    url.pathname === '/api/me' &&
    req.method === 'GET'
  ) {
    return json(res, 200, {
      user,
      trusted: true,
    });
  }

  /* AUTHENTICATED HEALTH */

  if (
    url.pathname === '/api/health-auth' &&
    req.method === 'GET'
  ) {
    return json(res, 200, {
      online: client.isReady(),
      tag: client.user?.tag || null,
      dashboard: true,
      port: dashboardPort,
      authenticated: true,
      user,
    });
  }

  /* GET CONFIG */

  if (
    url.pathname === '/api/config' &&
    req.method === 'GET'
  ) {
    return json(res, 200, cfg);
  }

  /* SAVE CONFIG */

  if (
    url.pathname === '/api/config' &&
    req.method === 'PUT'
  ) {
    try {
      cfg = safeConfig(await readBody(req));

      save(cfg);

      return json(res, 200, cfg);
    } catch (e) {
      return json(res, 400, {
        error: e.message,
      });
    }
  }

  /* SUBMISSIONS */

  if (
    url.pathname === '/api/submissions' &&
    req.method === 'GET'
  ) {
    return json(
      res,
      200,
      allSubmissions()
        .slice()
        .reverse()
        .map((x) => ({
          id: x.id,
          username: x.username,
          type: x.type,
          status: x.status,
          submittedAt: x.submittedAt,
        }))
    );
  }

  /* PUBLISH PANEL */

  if (
    url.pathname === '/api/publish-panel' &&
    req.method === 'POST'
  ) {
    try {
      const { channelId } = await readBody(req);

      if (!client.isReady()) {
        return json(res, 503, {
          error: 'Discord bot is not ready yet.',
        });
      }

      const channel = await client.channels
        .fetch(String(channelId))
        .catch(() => null);

      if (!channel?.isTextBased()) {
        return json(res, 400, {
          error:
            'That channel could not be found or is not a text channel.',
        });
      }

      const sent = await channel.send({
        embeds: [panelEmbed()],
        components: panelComponents(),
      });

      return json(res, 200, {
        ok: true,
        messageId: sent.id,
      });
    } catch (e) {
      return json(res, 500, {
        error: e.message,
      });
    }
  }

  /* TRUSTED USERS */

  if (
    url.pathname === '/api/trusted' &&
    req.method === 'GET'
  ) {
    return json(res, 200, {
      users: cfg.trustedUserIds || [],
    });
  }

  if (
    url.pathname === '/api/trusted' &&
    req.method === 'POST'
  ) {
    try {
      const body = await readBody(req);

      const id = String(body.userId || '').trim();

      if (!/^\d{17,20}$/.test(id)) {
        return json(res, 400, {
          error: 'Enter a valid Discord user ID.',
        });
      }

      cfg.trustedUserIds = [
        ...new Set([
          ...(cfg.trustedUserIds || []),
          id,
        ]),
      ];

      save(cfg);

      return json(res, 200, {
        users: cfg.trustedUserIds,
      });
    } catch (e) {
      return json(res, 400, {
        error: e.message,
      });
    }
  }

  if (
    url.pathname === '/api/trusted' &&
    req.method === 'DELETE'
  ) {
    const id = String(
      url.searchParams.get('userId') || ''
    );

    if (id === user.id) {
      return json(res, 400, {
        error:
          'You cannot remove your own trusted access from this session.',
      });
    }

    cfg.trustedUserIds = (
      cfg.trustedUserIds || []
    ).filter((x) => x !== id);

    save(cfg);

    return json(res, 200, {
      users: cfg.trustedUserIds,
    });
  }

  /* RESET */

  if (
    url.pathname === '/api/reset' &&
    req.method === 'POST'
  ) {
    cfg = structuredClone(defaults);

    cfg.trustedUserIds = [
      user.id,
      ...bootstrapTrusted,
    ];

    save(cfg);

    return json(res, 200, cfg);
  }

  /* STATIC DASHBOARD FILES */

  if (req.method === 'GET') {
    const rel =
      url.pathname === '/'
        ? 'index.html'
        : url.pathname.replace(/^\//, '');

    const file = path.resolve(
      dashboardDist,
      rel
    );

    /*
     * Prevent ../ traversal outside dashboard/site.
     */
    if (
      file.startsWith(dashboardDist) &&
      fs.existsSync(file) &&
      fs.statSync(file).isFile()
    ) {
      const ext = path.extname(file);

      const types = {
        '.html': 'text/html; charset=utf-8',
        '.js': 'text/javascript; charset=utf-8',
        '.css': 'text/css; charset=utf-8',
        '.svg': 'image/svg+xml',
        '.png': 'image/png',
        '.jpg': 'image/jpeg',
        '.jpeg': 'image/jpeg',
        '.webp': 'image/webp',
        '.ico': 'image/x-icon',
      };

      res.writeHead(200, {
        'Content-Type':
          types[ext] ||
          'application/octet-stream',
      });

      return res.end(
        fs.readFileSync(file)
      );
    }
  }

  return json(res, 404, {
    error: 'Not found',
  });
}

/* =========================================================
   START DASHBOARD SERVER
========================================================= */

const dashboardServer = http.createServer(
  (req, res) => {
    handleDashboard(req, res).catch((e) => {
      console.error('Dashboard error:', e);

      if (!res.headersSent) {
        json(res, 500, {
          error:
            e.message || 'Dashboard error',
        });
      }
    });
  }
);

dashboardServer.on('error', (err) => {
  if (
    err.code === 'EADDRINUSE' &&
    dashboardPort ===
      Number(process.env.DASHBOARD_PORT || 8787)
  ) {
    dashboardPort =
      Number(process.env.DASHBOARD_PORT || 8787) + 1;

    dashboardServer.listen(
      dashboardPort,
      '0.0.0.0',
      () => {
        console.log(
          `Relive dashboard port 8787 was busy. Dashboard: http://127.0.0.1:${dashboardPort}`
        );
      }
    );
  } else {
    console.error(
      'Relive dashboard server error:',
      err
    );
  }
});

dashboardServer.listen(
  dashboardPort,
  '0.0.0.0',
  () => {
    console.log(
      `Relive dashboard: http://127.0.0.1:${dashboardPort}`
    );
  }
);

/* =========================================================
   DISCORD HELPERS
========================================================= */

const accent = () =>
  cfg.brand?.accent || 0x8FA7FF;

const appType = (id) =>
  cfg.applicationTypes.find(
    (a) => a.id === id
  );

const channelFor = (id) =>
  cfg.channels?.[id] || '';

const vars = (text, v = {}) =>
  String(text || '')
    .replaceAll('{id}', v.id || '')
    .replaceAll(
      '{current}',
      String(v.current || '')
    )
    .replaceAll(
      '{total}',
      String(v.total || '')
    )
    .replaceAll(
      '{question}',
      v.question || ''
    )
    .replaceAll(
      '{type}',
      v.type || ''
    )
    .replaceAll(
      '{reason}',
      v.reason
        ? `\n\n**Reason:** ${v.reason}`
        : ''
    );

function panelEmbed() {
  return new EmbedBuilder()
    .setColor(accent())
    .setTitle(
      cfg.panel.title
    )
    .setDescription(
      cfg.panel.description
    )
    .setFooter({
      text:
        cfg.panel.footer ||
        cfg.brand.name,
    })
    .setTimestamp();
}

function panelComponents() {
  const active =
    cfg.applicationTypes.filter(
      (a) => a.active !== false
    );

  const rows = [];
  let row = new ActionRowBuilder();

  active.forEach((a, i) => {
    if (i && i % 5 === 0) {
      rows.push(row);
      row = new ActionRowBuilder();
    }

    row.addComponents(
      new ButtonBuilder()
        .setCustomId(
          `relive_apply:${a.id}`
        )
        .setLabel(
          a.name.slice(0, 80)
        )
        .setEmoji(
          a.emoji || '📋'
        )
        .setStyle(
          ButtonStyle.Secondary
        )
    );
  });

  if (row.components.length) {
    rows.push(row);
  }

  return rows;
}

function reviewRows(
  id,
  disabled = false
) {
  return new ActionRowBuilder().addComponents(
    new ButtonBuilder()
      .setCustomId(
        `relive_accept:${id}`
      )
      .setLabel('Accept')
      .setEmoji('✅')
      .setStyle(ButtonStyle.Success)
      .setDisabled(disabled),

    new ButtonBuilder()
      .setCustomId(
        `relive_accept_reason:${id}`
      )
      .setLabel('Accept with Reason')
      .setEmoji('📝')
      .setStyle(ButtonStyle.Success)
      .setDisabled(disabled),

    new ButtonBuilder()
      .setCustomId(
        `relive_deny:${id}`
      )
      .setLabel('Deny')
      .setEmoji('⛔')
      .setStyle(ButtonStyle.Danger)
      .setDisabled(disabled),

    new ButtonBuilder()
      .setCustomId(
        `relive_deny_reason:${id}`
      )
      .setLabel('Deny with Reason')
      .setEmoji('📝')
      .setStyle(ButtonStyle.Danger)
      .setDisabled(disabled),

    new ButtonBuilder()
      .setCustomId(
        `Relive_details:${id}`
      )
      .setLabel('Details')
      .setEmoji('🔎')
      .setStyle(ButtonStyle.Secondary)
      .setDisabled(disabled)
  );
}

function permission(i) {
  return (
    i.memberPermissions?.has(
      PermissionsBitField.Flags.ManageGuild
    ) ||
    !cfg.reviewRoleId ||
    i.member?.roles?.cache?.has(
      cfg.reviewRoleId
    )
  );
}

async function applyRoles(
  guild,
  userId,
  ids,
  mode
) {
  if (!ids?.length) return;

  const member = await guild.members
    .fetch(userId)
    .catch(() => null);

  if (!member) return;

  for (const id of ids) {
    const role = await guild.roles
      .fetch(id)
      .catch(() => null);

    if (!role) continue;

    if (mode === 'add') {
      await member.roles
        .add(role)
        .catch(() => {});
    } else {
      await member.roles
        .remove(role)
        .catch(() => {});
    }
  }
}

function dmFooter() {
  return {
    text: 'Sent By Relive Support',
  };
}

function cancelRow() {
  return new ActionRowBuilder().addComponents(
    new ButtonBuilder()
      .setCustomId(
        'Relive_cancel_application'
      )
      .setLabel(
        'Cancel Application'
      )
      .setEmoji('🛑')
      .setStyle(ButtonStyle.Danger)
  );
}

function sourceRow() {
  return new ActionRowBuilder().addComponents(
    new ButtonBuilder()
      .setCustomId(
        'Relive_dm_source'
      )
      .setLabel(
        'Sent By Relive Support'
      )
      .setStyle(
        ButtonStyle.Secondary
      )
      .setDisabled(true)
  );
}

function confirmationRows(appId) {
  return [
    new ActionRowBuilder().addComponents(
      new ButtonBuilder()
        .setCustomId(
          `relive_dm_start:${appId}`
        )
        .setLabel(
          'Start Application'
        )
        .setEmoji('🟢')
        .setStyle(
          ButtonStyle.Success
        ),

      new ButtonBuilder()
        .setCustomId(
          'relive_cancel_application'
        )
        .setLabel(
          'Cancel Application'
        )
        .setEmoji('🔴')
        .setStyle(
          ButtonStyle.Danger
        )
    ),

    sourceRow(),
  ];
}

function confirmationEmbed(app) {
  return new EmbedBuilder()
    .setColor(accent())
    .setTitle(
      'Application started'
    )
    .setDescription(
      'Application has been started in your direct messages!'
    )
    .addFields({
      name: `${
        app.emoji || '📋'
      } ${app.name} Application`,
      value:
        'Are you sure you want to apply?\n\nOnce you start the application I will send you a series of questions. You will have **3 hours** to complete the application. If you do not complete the application in time, you will have to restart. If you wish to stop the application feel free to click the cancel button at any time.',
    })
    .setFooter(dmFooter());
}

function startedEmbed() {
  return new EmbedBuilder()
    .setColor(accent())
    .setTitle(
      'Application Started'
    )
    .setDescription(
      'Please answer the questions below, either by clicking on the dropdown menus or sending a message to the bot with your response.'
    )
    .setFooter(dmFooter());
}

function questionEmbed(
  app,
  index
) {
  return new EmbedBuilder()
    .setColor(accent())
    .setTitle(
      `${app.emoji || '📋'} ${app.name} Application`
    )
    .setDescription(
      `**${index + 1}/${app.questions.length} Question:** ${app.questions[index]}\n\n-# To answer this question, please send a message to the bot with your response.`
    )
    .setFooter(dmFooter());
}

/* =========================================================
   APPLICATION FLOW
========================================================= */

async function startApplication(i, app) {
  if (
    [...sessions.values()].some(
      (s) =>
        s.guildId === i.guildId &&
        s.userId === i.user.id
    )
  ) {
    return i.reply({
      content:
        'You already have an application in progress. Check your DMs.',
      ephemeral: true,
    });
  }

  const dm = await i.user
    .createDM()
    .catch(() => null);

  if (!dm) {
    return i.reply({
      content:
        'I could not DM you. Please enable DMs from server members and try again.',
      ephemeral: true,
    });
  }

  const s = {
    guildId: i.guildId,
    userId: i.user.id,
    appId: app.id,
    answers: [],
    index: 0,
    startedAt: null,
    state: 'confirm',
    dmChannelId: dm.id,
    confirmMessageId: null,
    currentQuestionMessageId: null,
  };

  sessions.set(
    i.user.id,
    s
  );

  await i.reply({
    content:
      `☁️ Check your DMs — your **${app.name}** application is ready to start.`,
    ephemeral: true,
  });

  const sent = await dm.send({
    embeds: [
      confirmationEmbed(app),
    ],
    components:
      confirmationRows(app.id),
  });

  s.confirmMessageId = sent.id;
}

async function beginApplication(
  s,
  dm,
  interaction
) {
  const app = appType(s.appId);

  if (!app) return;

  s.state = 'active';
  s.startedAt = Date.now();
  s.index = 0;
  s.answers = [];

  if (interaction?.message) {
    await interaction.message
      .edit({
        embeds: [
          startedEmbed(),
        ],
        components: [
          cancelRow(),
          sourceRow(),
        ],
      })
      .catch(() => {});
  } else {
    await dm.send({
      embeds: [
        startedEmbed(),
      ],
      components: [
        cancelRow(),
        sourceRow(),
      ],
    });
  }

  await askNext(s, dm);
}

async function askNext(s, dm) {
  const app = appType(s.appId);

  if (!app) return;

  if (
    s.index >= app.questions.length
  ) {
    return finish(s, dm);
  }

  const sent = await dm.send({
    embeds: [
      questionEmbed(
        app,
        s.index
      ),
    ],
    components: [
      cancelRow(),
      sourceRow(),
    ],
  });

  s.currentQuestionMessageId =
    sent.id;
}

async function cancelApplication(
  userId,
  interaction
) {
  const s = sessions.get(userId);

  if (!s) {
    return interaction.reply({
      content:
        'There is no active Relive application to cancel.',
      ephemeral: true,
    });
  }

  sessions.delete(userId);

  if (interaction.message) {
    const embed =
      EmbedBuilder.from(
        interaction.message.embeds[0] ||
          new EmbedBuilder()
      )
        .setColor(0x777F8E)
        .setTitle(
          'Application Cancelled'
        )
        .setDescription(
          'Your Relive application has been cancelled. You can start a new application from the server panel.'
        );

    await interaction.message
      .edit({
        embeds: [embed],
        components: [],
      })
      .catch(() => {});
  }

  return interaction.reply({
    content:
      'Application cancelled.',
    ephemeral: true,
  });
}

async function timedOut(s) {
  if (
    !s.startedAt ||
    Date.now() - s.startedAt <
      timeoutMs
  ) {
    return false;
  }

  sessions.delete(s.userId);

  const user = await client.users
    .fetch(s.userId)
    .catch(() => null);

  await user?.send({
    embeds: [
      new EmbedBuilder()
        .setColor(0x777F8E)
        .setTitle(
          'Application Timed Out'
        )
        .setDescription(
          'Your Relive application was not completed within **3 hours**. You can start again from the application panel.'
        )
        .setFooter(dmFooter()),
    ],
  }).catch(() => {});

  return true;
}

/* =========================================================
   SUBMIT APPLICATION
========================================================= */

async function finish(s, dm) {
  const app = appType(s.appId);

  if (!app) {
    sessions.delete(s.userId);
    return;
  }

  const id = nextId();

  const user = await client.users
    .fetch(s.userId)
    .catch(() => null);

  const username =
    user?.tag ||
    user?.username ||
    s.userId;

  const record = {
    id,
    guildId: s.guildId,
    userId: s.userId,
    username,
    type: app.name,
    appId: app.id,
    status: 'Pending',
    submittedAt:
      new Date().toISOString(),
    questions: app.questions,
    answers: s.answers,
    reviewChannelId: '',
    reviewMessageId: '',
    reviewedBy: '',
    reviewedByTag: '',
    reviewedAt: '',
    reviewReason: '',
  };

  addSubmission(record);

  /*
   * Add the application's onSubmit roles.
   */
  const guild = await client.guilds
    .fetch(s.guildId)
    .catch(() => null);

  if (guild) {
    await applyRoles(
      guild,
      s.userId,
      app.roles?.onSubmit,
      'add'
    );
  }

  /*
   * Send the completed application to the
   * application's configured channel.
   *
   * Example:
   * cfg.channels.support
   * cfg.channels.creator
   * cfg.channels.staff
   * cfg.channels.partnership
   */
  const reviewChannelId =
    channelFor(app.id);

  let reviewChannel = null;

  if (
    reviewChannelId &&
    client.isReady()
  ) {
    reviewChannel = await client.channels
      .fetch(reviewChannelId)
      .catch(() => null);
  }

  if (
    reviewChannel?.isTextBased()
  ) {
    const chunks = [];

    let current =
      `**${id} · ${app.name} Application**\n` +
      `Applicant: <@${s.userId}>\n\n`;

    for (
      let n = 0;
      n < app.questions.length;
      n++
    ) {
      const question =
        app.questions[n];

      const answer =
        s.answers[n] || '—';

      const line =
        `**${n + 1}. ${question}**\n${answer}\n\n`;

      /*
       * Discord embed field values and descriptions
       * have limits, so we split the application.
       */
      if (
        current.length +
          line.length >
        3900
      ) {
        chunks.push(current);
        current = '';
      }

      current += line;
    }

    if (current) {
      chunks.push(current);
    }

    const embeds = [];

    for (
      let n = 0;
      n < chunks.length;
      n++
    ) {
      embeds.push(
        new EmbedBuilder()
          .setColor(accent())
          .setTitle(
            n === 0
              ? `${app.emoji || '📋'} ${app.name} Application`
              : `${app.emoji || '📋'} ${app.name} Application — Part ${n + 1}`
          )
          .setDescription(chunks[n])
          .setFooter({
            text:
              n === 0
                ? `Application ID: ${id}`
                : `Application ID: ${id} · Part ${n + 1}`,
          })
      );
    }

    /*
     * Discord allows up to 10 embeds per message.
     * Send the first message with review buttons,
     * then any additional chunks separately.
     */
    let firstMessage = null;

    if (embeds.length) {
      firstMessage =
        await reviewChannel
          .send({
            embeds: [
              embeds[0],
            ],
            components: [
              reviewRows(id),
            ],
          })
          .catch(() => null);
    }

    for (
      let n = 1;
      n < embeds.length;
      n++
    ) {
      await reviewChannel
        .send({
          embeds: [embeds[n]],
        })
        .catch(() => {});
    }

    if (firstMessage) {
      updateSubmission(id, {
        reviewChannelId:
          reviewChannel.id,
        reviewMessageId:
          firstMessage.id,
      });
    }
  }

  /*
   * Tell the applicant their application was submitted.
   */
  const submittedMessage =
    vars(
      cfg.messages.submitted,
      {
        id,
        type: app.name,
      }
    );

  await dm.send({
    embeds: [
      new EmbedBuilder()
        .setColor(accent())
        .setTitle(
          'Application Submitted'
        )
        .setDescription(
          submittedMessage
        )
        .setFooter(dmFooter()),
    ],
  }).catch(() => {});

  sessions.delete(
    s.userId
  );
}

/* =========================================================
   REVIEW MODAL
========================================================= */

function reasonModal(
  id,
  accepted
) {
  const input =
    new TextInputBuilder()
      .setCustomId('reason')
      .setLabel(
        'Reason / feedback'
      )
      .setStyle(
        TextInputStyle.Paragraph
      )
      .setRequired(true)
      .setMaxLength(1000)
      .setPlaceholder(
        accepted
          ? 'Optional context for the applicant…'
          : 'Explain why the application was denied…'
      );

  return new ModalBuilder()
    .setCustomId(
      `relive_reason_submit:${
        accepted
          ? 'accept'
          : 'deny'
      }:${id}`
    )
    .setTitle(
      `${
        accepted
          ? 'Accept'
          : 'Deny'
      } Application with Reason`
    )
    .addComponents(
      new ActionRowBuilder().addComponents(
        input
      )
    );
}

/* =========================================================
   REVIEW APPLICATION
========================================================= */

async function review(
  i,
  id,
  status,
  reason = ''
) {
  if (!permission(i)) {
    return i.reply({
      content:
        'You do not have permission to review Relive applications.',
      ephemeral: true,
    });
  }

  const current =
    allSubmissions().find(
      (x) => x.id === id
    );

  if (!current) {
    return i.reply({
      content:
        'Application record not found.',
      ephemeral: true,
    });
  }

  if (
    current.status !== 'Pending'
  ) {
    return i.reply({
      content:
        `This application is already **${current.status}**.`,
      ephemeral: true,
    });
  }

  const patch = {
    status,
    reviewedBy:
      i.user.id,
    reviewedByTag:
      i.user.tag,
    reviewedAt:
      new Date().toISOString(),
    reviewReason:
      reason,
  };

  updateSubmission(
    id,
    patch
  );

  const app =
    appType(current.appId);

  const guild =
    await client.guilds
      .fetch(current.guildId)
      .catch(() => null);

  if (guild && app) {
    if (status === 'Accepted') {
      await applyRoles(
        guild,
        current.userId,
        app.roles?.onAccept,
        'add'
      );

      await applyRoles(
        guild,
        current.userId,
        app.roles?.removeOnAccept,
        'remove'
      );
    } else if (
      status === 'Denied'
    ) {
      await applyRoles(
        guild,
        current.userId,
        app.roles?.onDeny,
        'add'
      );

      await applyRoles(
        guild,
        current.userId,
        app.roles?.removeOnDeny,
        'remove'
      );
    }
  }

  const user =
    await client.users
      .fetch(current.userId)
      .catch(() => null);

  const msg =
    status === 'Accepted'
      ? cfg.messages.accepted
      : cfg.messages.denied;

  await user?.send(
    vars(msg, {
      id,
      reason,
      type:
        current.type,
    })
  ).catch(() => {});

  const targetMessage =
    i.message ||
    await (async () => {
      if (
        !current.reviewChannelId ||
        !current.reviewMessageId
      ) {
        return null;
      }

      const channel =
        await guild?.channels
          .fetch(
            current.reviewChannelId
          )
          .catch(() => null);

      return channel?.messages
        ?.fetch(
          current.reviewMessageId
        )
        .catch(() => null);
    })();

  if (targetMessage) {
    const old =
      targetMessage.embeds[0];

    const color =
      status === 'Accepted'
        ? 0x57C98B
        : 0xE06472;

    const existingFields =
      old?.fields || [];

    const embed =
      EmbedBuilder.from(old)
        .setColor(color)
        .setFields(
          ...existingFields.filter(
            (f) =>
              f.name !== 'Status' &&
              f.name !== 'Review'
          ),
          {
            name: 'Status',
            value:
              status === 'Accepted'
                ? '🟢 Accepted'
                : '🔴 Denied',
            inline: true,
          },
          {
            name: 'Review',
            value:
              `<@${i.user.id}>${
                reason
                  ? `\n${reason}`
                  : ''
              }`,
            inline: false,
          }
        )
        .setFooter({
          text:
            `Reviewed by ${i.user.tag}`,
        });

    await targetMessage
      .edit({
        embeds: [embed],
        components: [
          reviewRows(id, true),
        ],
      })
      .catch(() => {});
  }

  return i.reply({
    content:
      `${
        status === 'Accepted'
          ? '✅ Accepted'
          : '⛔ Denied'
      } **${id}**.`,
    ephemeral: true,
  });
}

/* =========================================================
   DISCORD READY
========================================================= */

client.once(
  'ready',
  () => {
    console.log(
      `Relive Applications online as ${client.user.tag}`
    );
  }
);

/* =========================================================
   DM APPLICATION ANSWERS
========================================================= */

client.on(
  'messageCreate',
  async (m) => {
    if (
      m.author.bot ||
      m.guild
    ) {
      return;
    }

    const s =
      sessions.get(
        m.author.id
      );

    if (
      !s ||
      s.state !== 'active'
    ) {
      return;
    }

    if (
      await timedOut(s)
    ) {
      return;
    }

    const content =
      m.content.trim();

    if (!content) {
      return;
    }

    /*
     * Keep the old cancel behavior too.
     */
    if (
      content.toLowerCase() ===
      'cancel'
    ) {
      sessions.delete(
        m.author.id
      );

      await m.channel
        .send({
          embeds: [
            new EmbedBuilder()
              .setColor(0x777F8E)
              .setTitle(
                'Application Cancelled'
              )
              .setDescription(
                'Your Relive application has been cancelled. You can start a new application from the server panel.'
              )
              .setFooter(
                dmFooter()
              ),
          ],
        })
        .catch(() => {});

      return;
    }

    s.answers.push(
      content
    );

    s.index++;

    await askNext(
      s,
      m.channel
    );
  }
);

/* =========================================================
   INTERACTIONS
========================================================= */

client.on(
  'interactionCreate',
  async (i) => {
    try {
      /* ================================================
         SLASH COMMANDS
      ================================================ */

      if (
        i.isChatInputCommand()
      ) {
        if (
          !i.memberPermissions?.has(
            PermissionsBitField.Flags.ManageGuild
          )
        ) {
          return i.reply({
            content:
              'You need Manage Server to use Relive admin commands.',
            ephemeral: true,
          });
        }

        /* /relive-panel */

        if (
          i.commandName ===
          'relive-panel'
        ) {
          await i.channel.send({
            embeds: [
              panelEmbed(),
            ],
            components:
              panelComponents(),
          });

          return i.reply({
            content:
              '☁️ Relive application panel posted.',
            ephemeral: true,
          });
        }

        /* /skye-config */

        if (
          i.commandName ===
          'relive-config'
        ) {
          const o =
            i.options;

          for (
            const k of [
              'support',
              'creator',
              'staff',
              'partnership',
            ]
          ) {
            const channel =
              o.getChannel(
                `${k}_channel`
              );

            if (channel) {
              cfg.channels[k] =
                channel.id;
            }
          }

          const role =
            o.getRole(
              'review_role'
            );

          if (role) {
            cfg.reviewRoleId =
              role.id;
          }

          save(cfg);

          return i.reply({
            ephemeral: true,
            content:
              `**Relive configuration saved.**\n` +
              `🛠️ ${
                cfg.channels.support
                  ? `<#${cfg.channels.support}>`
                  : '—'
              } · ` +
              `🎥 ${
                cfg.channels.creator
                  ? `<#${cfg.channels.creator}>`
                  : '—'
              } · ` +
              `🛡️ ${
                cfg.channels.staff
                  ? `<#${cfg.channels.staff}>`
                  : '—'
              } · ` +
              `🤝 ${
                cfg.channels.partnership
                  ? `<#${cfg.channels.partnership}>`
                  : '—'
              }\n` +
              `👮 Review role: ${
                cfg.reviewRoleId
                  ? `<@&${cfg.reviewRoleId}>`
                  : '—'
              }`,
          });
        }

        /* /skye-stats */

        if (
          i.commandName ===
          'relive-stats'
        ) {
          const all =
            allSubmissions();

          const pending =
            all.filter(
              (x) =>
                x.status ===
                'Pending'
            ).length;

          const accepted =
            all.filter(
              (x) =>
                x.status ===
                'Accepted'
            ).length;

          const denied =
            all.filter(
              (x) =>
                x.status ===
                'Denied'
            ).length;

          const changes =
            all.filter(
              (x) =>
                x.status ===
                'Changes Requested'
            ).length;

          return i.reply({
            ephemeral: true,
            embeds: [
              new EmbedBuilder()
                .setColor(
                  accent()
                )
                .setTitle(
                  '☁️ Relive Application Statistics'
                )
                .addFields(
                  {
                    name: 'Total',
                    value:
                      String(
                        all.length
                      ),
                    inline: true,
                  },
                  {
                    name: 'Pending',
                    value:
                      String(
                        pending
                      ),
                    inline: true,
                  },
                  {
                    name: 'Accepted',
                    value:
                      String(
                        accepted
                      ),
                    inline: true,
                  },
                  {
                    name: 'Denied',
                    value:
                      String(
                        denied
                      ),
                    inline: true,
                  },
                  {
                    name:
                      'Changes Requested',
                    value:
                      String(
                        changes
                      ),
                    inline: true,
                  }
                ),
            ],
          });
        }

        /* /relive-search */

        if (
          i.commandName ===
          'skye-search'
        ) {
          const q =
            i.options
              .getString(
                'query'
              )
              .toLowerCase();

          const status =
            i.options.getString(
              'status'
            );

          const hits =
            allSubmissions()
              .filter(
                (x) =>
                  (!status ||
                    x.status ===
                      status) &&
                  [
                    x.id,
                    x.username,
                    x.userId,
                    x.type,
                    x.appId,
                  ].some(
                    (v) =>
                      String(v)
                        .toLowerCase()
                        .includes(q)
                  )
              )
              .slice(-10)
              .reverse();

          return i.reply({
            ephemeral: true,
            content: hits.length
              ? hits
                  .map(
                    (x) =>
                      `• \`${x.id}\` — **${x.username}** — ${x.type} — ${x.status}`
                  )
                  .join('\n')
              : 'No applications found.',
          });
        }

        /* /relive-trust */

        if (
          i.commandName ===
          'relive-trust'
        ) {
          const u =
            i.options.getUser(
              'user'
            );

          cfg.trustedUserIds = [
            ...new Set([
              ...(cfg.trustedUserIds ||
                []),
              u.id,
            ]),
          ];

          save(cfg);

          return i.reply({
            ephemeral: true,
            content:
              `🔐 <@${u.id}> is now a trusted Relive dashboard user.`,
          });
        }

        /* /relive-untrust */

        if (
          i.commandName ===
          'relive-untrust'
        ) {
          const u =
            i.options.getUser(
              'user'
            );

          if (
            u.id === i.user.id
          ) {
            return i.reply({
              ephemeral: true,
              content:
                'You cannot remove your own dashboard access here.',
            });
          }

          cfg.trustedUserIds =
            (
              cfg.trustedUserIds ||
              []
            ).filter(
              (id) =>
                id !== u.id
            );

          save(cfg);

          return i.reply({
            ephemeral: true,
            content:
              `🔓 <@${u.id}> was removed from the trusted dashboard users.`,
          });
        }

        /* /skye-applicant */

        if (
          i.commandName ===
          'relive-applicant'
        ) {
          const u =
            i.options.getUser(
              'user'
            );

          const hits =
            allSubmissions()
              .filter(
                (x) =>
                  x.userId ===
                  u.id
              )
              .slice(-10)
              .reverse();

          return i.reply({
            ephemeral: true,
            content: hits.length
              ? hits
                  .map(
                    (x) =>
                      `• \`${x.id}\` — ${x.type} — ${x.status}`
                  )
                  .join('\n')
              : `No applications found for ${u.tag}.`,
          });
        }

        /* /relive-help */

        if (
          i.commandName ===
          'relive-help'
        ) {
          return i.reply({
            ephemeral: true,
            content:
              '**relive Applications**\n' +
              '`/relive-panel` post panel\n' +
              '`/relive-config` configure channels/review role\n' +
              '`/relive-stats` view totals\n' +
              '`/relive-search` search applications\n' +
              '`/relive-applicant` view a user’s applications',
          });
        }
      }

      /* ================================================
         CANCEL APPLICATION
      ================================================ */

      if (
        i.isButton() &&
        i.customId ===
          'relive_cancel_application'
      ) {
        return cancelApplication(
          i.user.id,
          i
        );
      }

      /* ================================================
         START APPLICATION FROM DM
      ================================================ */

      if (
        i.isButton() &&
        i.customId.startsWith(
          'relive_dm_start:'
        )
      ) {
        const s =
          sessions.get(
            i.user.id
          );

        const app =
          appType(
            i.customId.split(
              ':'
            )[1]
          );

        if (
          !s ||
          !app ||
          s.appId !==
            app.id
        ) {
          return i.reply({
            content:
              'This application session is no longer active. Please start again from the server panel.',
            ephemeral: true,
          });
        }

        await beginApplication(
          s,
          i.channel,
          i
        );

        return i.deferUpdate();
      }

      /* ================================================
         DISABLED SOURCE BUTTON
      ================================================ */

      if (
        i.isButton() &&
        i.customId ===
          'relive_dm_source'
      ) {
        return i.deferUpdate();
      }

      /* ================================================
         APPLICATION PANEL BUTTON
      ================================================ */

      if (
        i.isButton() &&
        i.customId.startsWith(
          'relive_apply:'
        )
      ) {
        const app =
          appType(
            i.customId.split(
              ':'
            )[1]
          );

        if (app) {
          return startApplication(
            i,
            app
          );
        }
      }

      /* ================================================
         ACCEPT WITH REASON
      ================================================ */

      if (
        i.isButton() &&
        i.customId.startsWith(
          'relive_accept_reason:'
        )
      ) {
        if (!permission(i)) {
          return i.reply({
            content:
              'You do not have permission to review applications.',
            ephemeral: true,
          });
        }

        return i.showModal(
          reasonModal(
            i.customId.split(
              ':'
            )[1],
            true
          )
        );
      }

      /* ================================================
         DENY WITH REASON
      ================================================ */

      if (
        i.isButton() &&
        i.customId.startsWith(
          'relive_deny_reason:'
        )
      ) {
        if (!permission(i)) {
          return i.reply({
            content:
              'You do not have permission to review applications.',
            ephemeral: true,
          });
        }

        return i.showModal(
          reasonModal(
            i.customId.split(
              ':'
            )[1],
            false
          )
        );
      }

      /* ================================================
         ACCEPT
      ================================================ */

      if (
        i.isButton() &&
        i.customId.startsWith(
          'relive_accept:'
        )
      ) {
        return review(
          i,
          i.customId.split(
            ':'
          )[1],
          'Accepted'
        );
      }

      /* ================================================
         DENY
      ================================================ */

      if (
        i.isButton() &&
        i.customId.startsWith(
          'relive_deny:'
        )
      ) {
        return review(
          i,
          i.customId.split(
            ':'
          )[1],
          'Denied'
        );
      }

      /* ================================================
         DETAILS
      ================================================ */

      if (
        i.isButton() &&
        i.customId.startsWith(
          'relive_details:'
        )
      ) {
        const id =
          i.customId.split(
            ':'
          )[1];

        const record =
          allSubmissions().find(
            (x) =>
              x.id === id
          );

        if (!record) {
          return i.reply({
            content:
              'Application not found.',
            ephemeral: true,
          });
        }

        const chunks = [];

        let current =
          `**${record.id} · ${record.type} · ${record.status}**\n` +
          `Applicant: <@${record.userId}>\n\n`;

        record.questions.forEach(
          (question, n) => {
            const line =
              `**${n + 1}. ${question}**\n` +
              `${record.answers[n] || '—'}\n\n`;

            if (
              current.length +
                line.length >
              1800
            ) {
              chunks.push(
                current
              );

              current = '';
            }

            current += line;
          }
        );

        if (current) {
          chunks.push(
            current
          );
        }

        await i.reply({
          ephemeral: true,
          content:
            chunks.shift() ||
            'No application details found.',
        });

        for (
          const chunk of chunks
        ) {
          await i.followUp({
            ephemeral: true,
            content: chunk,
          });
        }

        return;
      }

      /* ================================================
         REASON MODAL
      ================================================ */

      if (
        i.isModalSubmit() &&
        i.customId.startsWith(
          'relive_reason_submit:'
        )
      ) {
        const [
          ,
          kind,
          id,
        ] =
          i.customId.split(
            ':'
          );

        const reason =
          i.fields.getTextInputValue(
            'reason'
          );

        return review(
          i,
          id,
          kind === 'accept'
            ? 'Accepted'
            : 'Denied',
          reason
        );
      }
    } catch (e) {
      console.error(
        'Relive interaction error:',
        e
      );

      if (
        !i.replied &&
        !i.deferred
      ) {
        await i
          .reply({
            content:
              'Relive encountered an error while processing that action.'
            ephemeral: true,
          })
          .catch(() => {});
      }
    }
  }
);

/* =========================================================
   APPLICATION TIMEOUT CHECK
========================================================= */

setInterval(() => {
  for (
    const s of sessions.values()
  ) {
    timedOut(s).catch(() => {});
  }
}, 60_000);

/* =========================================================
   START DISCORD BOT
========================================================= */

if (!process.env.DISCORD_TOKEN) {
  console.error(
    'DISCORD_TOKEN is missing.'
  );
} else {
  client
    .login(
      process.env.DISCORD_TOKEN
    )
    .catch((err) => {
      console.error(
        'Discord login failed:',
        err
      );
    });
}