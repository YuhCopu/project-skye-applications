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
  TextInputStyle
} from 'discord.js';

import {
  load,
  save,
  allSubmissions,
  defaults,
  updateSubmission
} from './config.js';

const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMembers,
    GatewayIntentBits.DirectMessages,
    GatewayIntentBits.MessageContent
  ],
  partials: ['CHANNEL']
});

let cfg = load();

const sessions = new Map();
const dashboardSessions = new Map();
const oauthStates = new Map();

const timeoutMs = 3 * 60 * 60 * 1000;

function envList(name) {
  return String(process.env[name] || '')
    .split(',')
    .map(x => x.trim())
    .filter(Boolean);
}

const bootstrapTrusted = new Set(
  envList('TRUSTED_USER_IDS')
);

if (bootstrapTrusted.size) {
  cfg.trustedUserIds = [
    ...new Set([
      ...(cfg.trustedUserIds || []),
      ...bootstrapTrusted
    ])
  ];

  save(cfg);
}

const publicUrl = String(
  process.env.PUBLIC_URL || ''
).replace(/\/$/, '');

const oauthRedirect =
  process.env.DISCORD_OAUTH_REDIRECT ||
  'https://project-skye-applications.onrender.com/oauth/callback';

const oauthConfigured = Boolean(
  process.env.DISCORD_CLIENT_SECRET &&
  process.env.CLIENT_ID
);

function cookieMap(req) {
  const out = {};

  for (
    const part of String(
      req.headers.cookie || ''
    ).split(';')
  ) {
    const [key, ...value] =
      part.trim().split('=');

    if (key) {
      out[key] = decodeURIComponent(
        value.join('=')
      );
    }
  }

  return out;
}

function cookie(
  name,
  value,
  maxAge = 604800,
  secure = true
) {
  return (
    name +
    '=' +
    encodeURIComponent(value) +
    '; Path=/; HttpOnly; SameSite=Lax; Max-Age=' +
    maxAge +
    (secure ? '; Secure' : '')
  );
}

function clearCookie(name) {
  return (
    name +
    '=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0'
  );
}

function trusted(id) {
  return (
    cfg.trustedUserIds || []
  ).includes(id);
}

function sessionUser(req) {
  const token =
    cookieMap(req).skye_session;

  return token
    ? dashboardSessions.get(token)
    : null;
}

function authRequired(req, res) {
  const user = sessionUser(req);

  if (!user) {
    res.writeHead(302, {
      Location: '/login'
    });

    res.end();
    return null;
  }

  if (!trusted(user.id)) {
    res.writeHead(403, {
      'Content-Type':
        'text/html; charset=utf-8'
    });

    res.end(
      '<html><body style="font-family:system-ui;background:#090b0f;color:#e8ecf5;display:grid;place-items:center;height:100vh;margin:0"><main style="max-width:520px;padding:30px;border:1px solid #272d39;border-radius:14px;background:#0e1218"><h2>Skye Dashboard</h2><p>Your Discord account is authenticated, but it is not registered as a trusted dashboard user.</p><p>Ask the Skye owner to add your Discord user ID to the trusted users list.</p><a href="/logout" style="color:#aebfff">Sign out</a></main></body></html>'
    );

    return null;
  }

  return user;
}

function oauthLogin(req, res) {
  if (!oauthConfigured) {
    res.writeHead(503, {
      'Content-Type':
        'text/html; charset=utf-8'
    });

    return res.end(
      '<h2>Discord login is not configured.</h2><p>Set DISCORD_CLIENT_SECRET and CLIENT_ID first.</p>'
    );
  }

  const state =
    crypto.randomBytes(24).toString('hex');

  oauthStates.set(state, {
    expires:
      Date.now() + 10 * 60 * 1000,
    redirect: oauthRedirect
  });

  const params =
    new URLSearchParams({
      client_id: process.env.CLIENT_ID,
      response_type: 'code',
      redirect_uri: oauthRedirect,
      scope: 'identify'
    });

  res.writeHead(302, {
    Location:
      'https://discord.com/oauth2/authorize?' +
      params.toString(),

    'Set-Cookie': cookie(
      'skye_oauth_state',
      state,
      600,
      true
    )
  });

  res.end();
}

async function oauthCallback(
  req,
  res,
  url
) {
  const state =
    url.searchParams.get('state') || '';

  const oauthState =
    oauthStates.get(state);

  if (
    !state ||
    !oauthState ||
    oauthState.expires < Date.now()
  ) {
    if (state) {
      oauthStates.delete(state);
    }

    res.writeHead(400, {
      'Content-Type': 'text/plain'
    });

    return res.end(
      'Invalid or expired OAuth state.'
    );
  }

  oauthStates.delete(state);

  const code =
    url.searchParams.get('code');

  if (!code) {
    res.writeHead(400, {
      'Content-Type': 'text/plain'
    });

    return res.end(
      'Discord OAuth was cancelled or failed.'
    );
  }

  const tokenRes = await fetch(
    'https://discord.com/api/oauth2/token',
    {
      method: 'POST',

      headers: {
        'Content-Type':
          'application/x-www-form-urlencoded'
      },

      body: new URLSearchParams({
        client_id:
          process.env.CLIENT_ID,

        client_secret:
          process.env.DISCORD_CLIENT_SECRET,

        grant_type:
          'authorization_code',

        code,

        redirect_uri:
          oauthState.redirect
      })
    }
  );

  if (!tokenRes.ok) {
    console.error(
      'Discord token exchange failed:',
      await tokenRes.text().catch(() => '')
    );

    res.writeHead(502, {
      'Content-Type': 'text/plain'
    });

    return res.end(
      'Discord token exchange failed.'
    );
  }

  const token =
    await tokenRes.json();

  const meRes = await fetch(
    'https://discord.com/api/users/@me',
    {
      headers: {
        Authorization:
          'Bearer ' +
          token.access_token
      }
    }
  );

  if (!meRes.ok) {
    res.writeHead(502, {
      'Content-Type': 'text/plain'
    });

    return res.end(
      'Could not read your Discord account.'
    );
  }

  const me =
    await meRes.json();

  const session =
    crypto.randomBytes(32).toString('hex');

  dashboardSessions.set(
    session,
    {
      id: me.id,
      username: me.username,
      global_name:
        me.global_name ||
        me.username,
      avatar:
        me.avatar || null,
      createdAt: Date.now()
    }
  );

  res.writeHead(302, {
    Location: '/',
    'Set-Cookie': cookie(
      'skye_session',
      session,
      604800,
      true
    )
  });

  res.end();
}

function authPage() {
  return `
<html>
<head>
<title>Skye Dashboard Login</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
</head>

<body style="font-family:system-ui;background:#090b0f;color:#e8ecf5;display:grid;place-items:center;height:100vh;margin:0">

<main style="width:min(420px,calc(100% - 32px));padding:30px;border:1px solid #272d39;border-radius:16px;background:#0e1218;text-align:center">

<div style="font-size:38px">☁️</div>

<h1>Skye Applications</h1>

<p style="color:#7f899b">
Private dashboard. Discord authentication is required.
</p>

<a href="/login/start"
style="display:block;padding:12px;border-radius:8px;background:#aebfff;color:#080a0e;text-decoration:none;font-weight:700">
Continue with Discord
</a>

</main>
</body>
</html>
`;
}

let dashboardPort = Number(
  process.env.PORT ||
  process.env.DASHBOARD_PORT ||
  8787
);

const dashboardDist =
  path.resolve(
    path.dirname(
      fileURLToPath(import.meta.url)
    ),
    '../../dashboard/site'
  );

function json(res, status, data) {
  res.writeHead(status, {
    'Content-Type':
      'application/json; charset=utf-8',

    'Access-Control-Allow-Origin':
      '*',

    'Cache-Control':
      'no-store'
  });

  res.end(
    JSON.stringify(data)
  );
}

function readBody(req) {
  return new Promise(
    (resolve, reject) => {
      let body = '';

      req.on('data', chunk => {
        body += chunk;

        if (body.length > 2000000) {
          req.destroy();
        }
      });

      req.on('end', () => {
        try {
          resolve(
            body
              ? JSON.parse(body)
              : {}
          );
        } catch (error) {
          reject(error);
        }
      });

      req.on('error', reject);
    }
  );
}

function safeConfig(input) {
  if (
    !input ||
    typeof input !== 'object'
  ) {
    throw new Error(
      'Invalid configuration.'
    );
  }

  const next =
    structuredClone(defaults);

  for (
    const [key, value]
    of Object.entries(input)
  ) {
    if (key in next) {
      next[key] = value;
    }
  }

  next.trustedUserIds =
    Array.isArray(
      input.trustedUserIds
    )
      ? input.trustedUserIds
          .map(String)
          .filter(
            id =>
              /^\d{17,20}$/.test(id)
          )
      : next.trustedUserIds;

  return next;
}

async function handleDashboard(
  req,
  res
) {
  const url = new URL(
    req.url || '/',
    'http://' +
      (
        req.headers.host ||
        '127.0.0.1'
      )
  );

  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Methods':
        'GET,PUT,POST,DELETE,OPTIONS',

      'Access-Control-Allow-Headers':
        'Content-Type'
    });

    return res.end();
  }

  if (url.pathname === '/login') {
    res.writeHead(200, {
      'Content-Type':
        'text/html; charset=utf-8'
    });

    return res.end(
      authPage()
    );
  }

  if (
    url.pathname === '/login/start'
  ) {
    return oauthLogin(
      req,
      res
    );
  }

  if (
    url.pathname === '/oauth/callback'
  ) {
    return oauthCallback(
      req,
      res,
      url
    );
  }

  if (url.pathname === '/logout') {
    res.writeHead(302, {
      Location: '/login',
      'Set-Cookie':
        clearCookie(
          'skye_session'
        )
    });

    return res.end();
  }

  if (
    url.pathname === '/api/health'
  ) {
    return json(res, 200, {
      online: client.isReady(),
      tag:
        client.user?.tag ||
        null,
      dashboard: true,
      port: dashboardPort
    });
  }

  const user =
    authRequired(
      req,
      res
    );

  if (!user) {
    return;
  }

  if (
    url.pathname === '/api/me'
  ) {
    return json(res, 200, {
      user,
      trusted: true
    });
  }

  if (
    url.pathname === '/api/config' &&
    req.method === 'GET'
  ) {
    return json(
      res,
      200,
      cfg
    );
  }

  if (
    url.pathname === '/api/config' &&
    req.method === 'PUT'
  ) {
    try {
      cfg =
        safeConfig(
          await readBody(req)
        );

      save(cfg);

      return json(
        res,
        200,
        cfg
      );
    } catch (error) {
      return json(
        res,
        400,
        {
          error:
            error.message
        }
      );
    }
  }

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
    );
  }

  if (
    url.pathname === '/api/trusted' &&
    req.method === 'GET'
  ) {
    return json(
      res,
      200,
      {
        users:
          cfg.trustedUserIds || []
      }
    );
  }

  if (
    url.pathname === '/api/trusted' &&
    req.method === 'POST'
  ) {
    const body =
      await readBody(req);

    const id =
      String(
        body.userId || ''
      ).trim();

    if (
      !/^\d{17,20}$/.test(id)
    ) {
      return json(
        res,
        400,
        {
          error:
            'Enter a valid Discord user ID.'
        }
      );
    }

    cfg.trustedUserIds = [
      ...new Set([
        ...(cfg.trustedUserIds || []),
        id
      ])
    ];

    save(cfg);

    return json(
      res,
      200,
      {
        users:
          cfg.trustedUserIds
      }
    );
  }

  if (
    url.pathname === '/api/trusted' &&
    req.method === 'DELETE'
  ) {
    const id =
      String(
        url.searchParams.get(
          'userId'
        ) || ''
      );

    if (id === user.id) {
      return json(
        res,
        400,
        {
          error:
            'You cannot remove your own trusted access.'
        }
      );
    }

    cfg.trustedUserIds =
      (
        cfg.trustedUserIds || []
      ).filter(
        x => x !== id
      );

    save(cfg);

    return json(
      res,
      200,
      {
        users:
          cfg.trustedUserIds
      }
    );
  }

  if (
    url.pathname === '/api/reset' &&
    req.method === 'POST'
  ) {
    cfg =
      structuredClone(
        defaults
      );

    cfg.trustedUserIds = [
      user.id,
      ...bootstrapTrusted
    ];

    save(cfg);

    return json(
      res,
      200,
      cfg
    );
  }

  if (req.method === 'GET') {
    const relative =
      url.pathname === '/'
        ? 'index.html'
        : url.pathname.replace(
            /^\//,
            ''
          );

    const file =
      path.resolve(
        dashboardDist,
        relative
      );

    if (
      file.startsWith(
        dashboardDist
      ) &&
      fs.existsSync(file) &&
      fs.statSync(file).isFile()
    ) {
      const ext =
        path.extname(file);

      const types = {
        '.html':
          'text/html; charset=utf-8',

        '.js':
          'text/javascript; charset=utf-8',

        '.css':
          'text/css; charset=utf-8',

        '.svg':
          'image/svg+xml',

        '.png':
          'image/png',

        '.ico':
          'image/x-icon'
      };

      res.writeHead(200, {
        'Content-Type':
          types[ext] ||
          'application/octet-stream'
      });

      return res.end(
        fs.readFileSync(file)
      );
    }
  }

  return json(
    res,
    404,
    {
      error: 'Not found'
    }
  );
}

const dashboardServer =
  http.createServer(
    (req, res) => {
      handleDashboard(
        req,
        res
      ).catch(error => {
        console.error(
          'Dashboard error:',
          error
        );

        json(
          res,
          500,
          {
            error:
              error.message ||
              'Dashboard error'
          }
        );
      });
    }
  );

dashboardServer.on(
  'error',
  error => {
    console.error(
      'Dashboard server error:',
      error
    );
  }
);

dashboardServer.listen(
  dashboardPort,
  '0.0.0.0',
  () => {
    console.log(
      'Skye dashboard listening on port ' +
      dashboardPort
    );
  }
);

function accent() {
  return (
    cfg.brand?.accent ||
    0x8fa7ff
  );
}

function appType(id) {
  return (
    cfg.applicationTypes || []
  ).find(
    app => app.id === id
  );
}

function panelEmbed() {
  return new EmbedBuilder()
    .setColor(accent())
    .setTitle(
      cfg.panel?.title ||
      'Skye Applications'
    )
    .setDescription(
      cfg.panel?.description ||
      'Choose an application below.'
    )
    .setFooter({
      text:
        cfg.panel?.footer ||
        cfg.brand?.name ||
        'Skye Applications'
    });
}

function panelComponents() {
  const apps =
    (
      cfg.applicationTypes || []
    ).filter(
      app => app.active !== false
    );

  const rows = [];
  let row =
    new ActionRowBuilder();

  for (
    const app of apps
  ) {
    if (
      row.components.length >= 5
    ) {
      rows.push(row);
      row =
        new ActionRowBuilder();
    }

    row.addComponents(
      new ButtonBuilder()
        .setCustomId(
          'skye_apply:' +
          app.id
        )
        .setLabel(
          String(
            app.name || 'Apply'
          ).slice(0, 80)
        )
        .setEmoji(
          app.emoji || '📋'
        )
        .setStyle(
          ButtonStyle.Secondary
        )
    );
  }

  if (row.components.length) {
    rows.push(row);
  }

  return rows;
}

function cancelRow() {
  return new ActionRowBuilder()
    .addComponents(
      new ButtonBuilder()
        .setCustomId(
          'skye_cancel_application'
        )
        .setLabel(
          'Cancel Application'
        )
        .setEmoji('🛑')
        .setStyle(
          ButtonStyle.Danger
        )
    );
}

function sourceRow() {
  return new ActionRowBuilder()
    .addComponents(
      new ButtonBuilder()
        .setCustomId(
          'skye_dm_source'
        )
        .setLabel(
          'Sent By Skye Support'
        )
        .setStyle(
          ButtonStyle.Secondary
        )
        .setDisabled(true)
    );
}

function confirmationEmbed(app) {
  return new EmbedBuilder()
    .setColor(accent())
    .setTitle(
      'Application Started'
    )
    .setDescription(
      'Are you sure you want to apply?'
    )
    .addFields({
      name:
        (
          app.emoji ||
          '📋'
        ) +
        ' ' +
        (
          app.name ||
          'Application'
        ),

      value:
        'Once you start the application I will send you a series of questions. You will have **3 hours** to complete the application.'
    });
}

function questionEmbed(
  app,
  index
) {
  const questions =
    app.questions || [];

  return new EmbedBuilder()
    .setColor(accent())
    .setTitle(
      (
        app.emoji ||
        '📋'
      ) +
      ' ' +
      (
        app.name ||
        'Application'
      )
    )
    .setDescription(
      '**' +
      (index + 1) +
      '/' +
      questions.length +
      ' Question:** ' +
      questions[index]
    )
    .setFooter({
      text:
        'Sent By Skye Support'
    });
}

async function startApplication(
  interaction,
  app
) {
  if (
    sessions.has(
      interaction.user.id
    )
  ) {
    return interaction.reply({
      content:
        'You already have an application in progress. Check your DMs.',
      ephemeral: true
    });
  }

  const dm =
    await interaction.user
      .createDM()
      .catch(() => null);

  if (!dm) {
    return interaction.reply({
      content:
        'I could not DM you. Please enable DMs and try again.',
      ephemeral: true
    });
  }

  const session = {
    userId:
      interaction.user.id,

    guildId:
      interaction.guildId,

    appId:
      app.id,

    answers: [],

    index: 0,

    startedAt: null,

    state: 'confirm',

    dmChannelId:
      dm.id
  };

  sessions.set(
    interaction.user.id,
    session
  );

  await interaction.reply({
    content:
      '☁️ Check your DMs to start your application.',
    ephemeral: true
  });

  await dm.send({
    embeds: [
      confirmationEmbed(app)
    ],

    components: [
      new ActionRowBuilder()
        .addComponents(
          new ButtonBuilder()
            .setCustomId(
              'skye_dm_start:' +
              app.id
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
              'skye_cancel_application'
            )
            .setLabel(
              'Cancel Application'
            )
            .setEmoji('🔴')
            .setStyle(
              ButtonStyle.Danger
            )
        ),

      sourceRow()
    ]
  });
}

async function beginApplication(
  session,
  interaction
) {
  const app =
    appType(
      session.appId
    );

  if (!app) {
    return;
  }

  session.state =
    'active';

  session.startedAt =
    Date.now();

  session.index = 0;
  session.answers = [];

  await interaction.update({
    embeds: [
      new EmbedBuilder()
        .setColor(accent())
        .setTitle(
          'Application Started'
        )
        .setDescription(
          'Please answer each question by sending your response here.'
        )
    ],

    components: [
      cancelRow(),
      sourceRow()
    ]
  });

  await askNext(
    session,
    interaction.channel
  );
}

async function askNext(
  session,
  channel
) {
  const app =
    appType(
      session.appId
    );

  if (!app) {
    return;
  }

  const questions =
    app.questions || [];

  if (
    session.index >=
    questions.length
  ) {
    return finishApplication(
      session,
      channel
    );
  }

  await channel.send({
    embeds: [
      questionEmbed(
        app,
        session.index
      )
    ],

    components: [
      cancelRow(),
      sourceRow()
    ]
  });
}

async function finishApplication(
  session,
  channel
) {
  const app =
    appType(
      session.appId
    );

  const id =
    'SKY-' +
    Date.now()
      .toString(36)
      .toUpperCase();

  const questions =
    app?.questions || [];

  const submission = {
    id,

    appId:
      session.appId,

    type:
      app?.name ||
      'Application',

    guildId:
      session.guildId,

    userId:
      session.userId,

    username:
      (
        await client.users
          .fetch(
            session.userId
          )
          .catch(() => null)
      )?.tag ||
      session.userId,

    questions,

    answers:
      session.answers,

    status:
      'Pending',

    submittedAt:
      new Date().toISOString()
  };

  if (
    typeof cfg.submissions !==
    'undefined'
  ) {
    if (
      !Array.isArray(
        cfg.submissions
      )
    ) {
      cfg.submissions = [];
    }

    cfg.submissions.push(
      submission
    );

    save(cfg);
  }

  sessions.delete(
    session.userId
  );

  await channel.send({
    embeds: [
      new EmbedBuilder()
        .setColor(
          0x57c98b
        )
        .setTitle(
          'Application Submitted'
        )
        .setDescription(
          'Your application has been submitted successfully. Thank you!'
        )
        .setFooter({
          text:
            'Sent By Skye Support'
        })
    ],

    components: [
      sourceRow()
    ]
  });

  const reviewChannelId =
    cfg.channels?.[
      session.appId
    ] ||
    cfg.channels?.support;

  if (!reviewChannelId) {
    return;
  }

  const reviewChannel =
    await client.channels
      .fetch(
        reviewChannelId
      )
      .catch(() => null);

  if (
    !reviewChannel ||
    !reviewChannel.isTextBased()
  ) {
    return;
  }

  const embed =
    new EmbedBuilder()
      .setColor(accent())
      .setTitle(
        '📋 New Application'
      )
      .addFields(
        {
          name: 'Application',
          value:
            app?.name ||
            'Application',
          inline: true
        },
        {
          name: 'Applicant',
          value:
            '<@' +
            session.userId +
            '>',
          inline: true
        },
        {
          name: 'Status',
          value:
            '🟡 Pending',
          inline: true
        }
      )
      .setFooter({
        text:
          'Application ID: ' +
          id
      });

  for (
    let index = 0;
    index < questions.length;
    index++
  ) {
    embed.addFields({
      name:
        String(index + 1) +
        '. ' +
        questions[index],

      value:
        String(
          session.answers[index] ||
          'No answer'
        ).slice(0, 1024)
    });
  }

  const message =
    await reviewChannel.send({
      embeds: [embed],

      components: [
        reviewRows(id)
      ]
    });

  updateSubmission(
    id,
    {
      reviewChannelId:
        reviewChannel.id,

      reviewMessageId:
        message.id
    }
  );
}

function reviewRows(
  id,
  disabled = false
) {
  return new ActionRowBuilder()
    .addComponents(
      new ButtonBuilder()
        .setCustomId(
          'skye_accept:' +
          id
        )
        .setLabel('Accept')
        .setEmoji('✅')
        .setStyle(
          ButtonStyle.Success
        )
        .setDisabled(disabled),

      new ButtonBuilder()
        .setCustomId(
          'skye_accept_reason:' +
          id
        )
        .setLabel(
          'Accept with Reason'
        )
        .setStyle(
          ButtonStyle.Success
        )
        .setDisabled(disabled),

      new ButtonBuilder()
        .setCustomId(
          'skye_deny:' +
          id
        )
        .setLabel('Deny')
        .setEmoji('⛔')
        .setStyle(
          ButtonStyle.Danger
        )
        .setDisabled(disabled),

      new ButtonBuilder()
        .setCustomId(
          'skye_deny_reason:' +
          id
        )
        .setLabel(
          'Deny with Reason'
        )
        .setStyle(
          ButtonStyle.Danger
        )
        .setDisabled(disabled),

      new ButtonBuilder()
        .setCustomId(
          'skye_details:' +
          id
        )
        .setLabel('Details')
        .setStyle(
          ButtonStyle.Secondary
        )
        .setDisabled(disabled)
    );
}

function hasReviewPermission(
  interaction
) {
  return (
    interaction.memberPermissions?.has(
      PermissionsBitField.Flags.ManageGuild
    ) ||
    !cfg.reviewRoleId ||
    interaction.member?.roles?.cache?.has(
      cfg.reviewRoleId
    )
  );
}

function reasonModal(
  id,
  accepted
) {
  const input =
    new TextInputBuilder()
      .setCustomId(
        'reason'
      )
      .setLabel(
        'Reason'
      )
      .setStyle(
        TextInputStyle.Paragraph
      )
      .setRequired(true)
      .setMaxLength(1000);

  return new ModalBuilder()
    .setCustomId(
      'skye_reason:' +
      (
        accepted
          ? 'accept'
          : 'deny'
      ) +
      ':' +
      id
    )
    .setTitle(
      accepted
        ? 'Accept Application'
        : 'Deny Application'
    )
    .addComponents(
      new ActionRowBuilder()
        .addComponents(input)
    );
}

async function handleReview(
  interaction,
  id,
  status,
  reason = ''
) {
  if (
    !hasReviewPermission(
      interaction
    )
  ) {
    return interaction.reply({
      content:
        'You do not have permission to review applications.',
      ephemeral: true
    });
  }

  const submission =
    allSubmissions()
      .find(
        x => x.id === id
      );

  if (!submission) {
    return interaction.reply({
      content:
        'Application not found.',
      ephemeral: true
    });
  }

  if (
    submission.status !==
    'Pending'
  ) {
    return interaction.reply({
      content:
        'This application has already been reviewed.',
      ephemeral: true
    });
  }

  updateSubmission(
    id,
    {
      status,
      reviewReason:
        reason || '',
      reviewedBy:
        interaction.user.id,
      reviewedAt:
        new Date().toISOString()
    }
  );

  const color =
    status === 'Accepted'
      ? 0x57c98b
      : 0xe06472;

  const embed =
    EmbedBuilder.from(
      interaction.message
        .embeds[0]
    )
      .setColor(color)
      .addFields({
        name: 'Status',
        value:
          status === 'Accepted'
            ? '🟢 Accepted'
            : '🔴 Denied',
        inline: true
      });

  if (reason) {
    embed.addFields({
      name: 'Reason',
      value:
        reason.slice(0, 1024)
    });
  }

  embed.setFooter({
    text:
      'Reviewed by ' +
      interaction.user.tag
  });

  await interaction.message.edit({
    embeds: [embed],
    components: [
      reviewRows(
        id,
        true
      )
    ]
  });

  const user =
    await client.users
      .fetch(
        submission.userId
      )
      .catch(() => null);

  if (user) {
    await user.send({
      embeds: [
        new EmbedBuilder()
          .setColor(color)
          .setTitle(
            status === 'Accepted'
              ? 'Application Accepted'
              : 'Application Denied'
          )
          .setDescription(
            reason ||
            (
              status === 'Accepted'
                ? 'Your application has been accepted.'
                : 'Your application has been denied.'
            )
          )
          .setFooter({
            text:
              'Sent By Skye Support'
          })
      ]
    }).catch(() => {});
  }

  return interaction.reply({
    content:
      (
        status === 'Accepted'
          ? '✅ Application accepted.'
          : '⛔ Application denied.'
      ),

    ephemeral: true
  });
}

client.once(
  'ready',
  () => {
    console.log(
      'Skye Applications online as ' +
      client.user.tag
    );
  }
);

client.on(
  'messageCreate',
  async message => {
    if (
      message.author.bot ||
      message.guild
    ) {
      return;
    }

    const session =
      sessions.get(
        message.author.id
      );

    if (
      !session ||
      session.state !==
        'active'
    ) {
      return;
    }

    if (
      session.startedAt &&
      Date.now() -
        session.startedAt >
        timeoutMs
    ) {
      sessions.delete(
        message.author.id
      );

      await message.channel.send({
        content:
          '⏰ Your application timed out after 3 hours. Please start again from the application panel.'
      });

      return;
    }

    const answer =
      message.content.trim();

    if (!answer) {
      return;
    }

    session.answers.push(
      answer
    );

    session.index++;

    await askNext(
      session,
      message.channel
    );
  }
);

client.on(
  'interactionCreate',
  async interaction => {
    try {
      if (
        interaction.isButton()
      ) {
        if (
          interaction.customId ===
          'skye_dm_source'
        ) {
          return interaction.deferUpdate();
        }

        if (
          interaction.customId ===
          'skye_cancel_application'
        ) {
          const session =
            sessions.get(
              interaction.user.id
            );

          if (!session) {
            return interaction.reply({
              content:
                'You do not have an active application.',
              ephemeral: true
            });
          }

          sessions.delete(
            interaction.user.id
          );

          return interaction.update({
            embeds: [
              new EmbedBuilder()
                .setColor(
                  0x777f8e
                )
                .setTitle(
                  'Application Cancelled'
                )
                .setDescription(
                  'Your application has been cancelled.'
                )
            ],
            components: []
          });
        }

        if (
          interaction.customId.startsWith(
            'skye_apply:'
          )
        ) {
          const app =
            appType(
              interaction.customId
                .split(':')[1]
            );

          if (!app) {
            return interaction.reply({
              content:
                'That application is unavailable.',
              ephemeral: true
            });
          }

          return startApplication(
            interaction,
            app
          );
        }

        if (
          interaction.customId.startsWith(
            'skye_dm_start:'
          )
        ) {
          const session =
            sessions.get(
              interaction.user.id
            );

          if (!session) {
            return interaction.reply({
              content:
                'Your application session expired. Please start again.',
              ephemeral: true
            });
          }

          return beginApplication(
            session,
            interaction
          );
        }

        if (
          interaction.customId.startsWith(
            'skye_accept_reason:'
          )
        ) {
          if (
            !hasReviewPermission(
              interaction
            )
          ) {
            return interaction.reply({
              content:
                'You do not have permission to review applications.',
              ephemeral: true
            });
          }

          const id =
            interaction.customId
              .split(':')[1];

          return interaction.showModal(
            reasonModal(
              id,
              true
            )
          );
        }

        if (
          interaction.customId.startsWith(
            'skye_deny_reason:'
          )
        ) {
          if (
            !hasReviewPermission(
              interaction
            )
          ) {
            return interaction.reply({
              content:
                'You do not have permission to review applications.',
              ephemeral: true
            });
          }

          const id =
            interaction.customId
              .split(':')[1];

          return interaction.showModal(
            reasonModal(
              id,
              false
            )
          );
        }

        if (
          interaction.customId.startsWith(
            'skye_accept:'
          )
        ) {
          return handleReview(
            interaction,
            interaction.customId
              .split(':')[1],
            'Accepted'
          );
        }

        if (
          interaction.customId.startsWith(
            'skye_deny:'
          )
        ) {
          return handleReview(
            interaction,
            interaction.customId
              .split(':')[1],
            'Denied'
          );
        }

        if (
          interaction.customId.startsWith(
            'skye_details:'
          )
        ) {
          const id =
            interaction.customId
              .split(':')[1];

          const submission =
            allSubmissions()
              .find(
                x => x.id === id
              );

          if (!submission) {
            return interaction.reply({
              content:
                'Application not found.',
              ephemeral: true
            });
          }

          let text =
            '**Application ' +
            id +
            '**\n\n';

          for (
            let i = 0;
            i <
              submission.questions.length;
            i++
          ) {
            text +=
              '**' +
              (
                i + 1
              ) +
              '. ' +
              submission.questions[i] +
              '**\n' +
              (
                submission.answers[i] ||
                'No answer'
              ) +
              '\n\n';
          }

          return interaction.reply({
            content:
              text.slice(
                0,
                3900
              ),

            ephemeral: true
          });
        }
      }

      if (
        interaction.isModalSubmit()
      ) {
        if (
          interaction.customId.startsWith(
            'skye_reason:'
          )
        ) {
          const parts =
            interaction.customId
              .split(':');

          const kind =
            parts[1];

          const id =
            parts[2];

          const reason =
            interaction.fields
              .getTextInputValue(
                'reason'
              );

          return handleReview(
            interaction,
            id,
            kind === 'accept'
              ? 'Accepted'
              : 'Denied',
            reason
          );
        }
      }

      if (
        interaction.isChatInputCommand()
      ) {
        if (
          !interaction.memberPermissions?.has(
            PermissionsBitField.Flags.ManageGuild
          )
        ) {
          return interaction.reply({
            content:
              'You need Manage Server to use Skye commands.',
            ephemeral: true
          });
        }

        if (
          interaction.commandName ===
          'skye-panel'
        ) {
          await interaction.channel.send({
            embeds: [
              panelEmbed()
            ],

            components:
              panelComponents()
          });

          return interaction.reply({
            content:
              '☁️ Skye application panel posted.',
            ephemeral: true
          });
        }

        if (
          interaction.commandName ===
          'skye-stats'
        ) {
          const submissions =
            allSubmissions();

          const pending =
            submissions.filter(
              x =>
                x.status ===
                'Pending'
            ).length;

          const accepted =
            submissions.filter(
              x =>
                x.status ===
                'Accepted'
            ).length;

          const denied =
            submissions.filter(
              x =>
                x.status ===
                'Denied'
            ).length;

          return interaction.reply({
            ephemeral: true,

            embeds: [
              new EmbedBuilder()
                .setColor(
                  accent()
                )
                .setTitle(
                  '☁️ Skye Statistics'
                )
                .addFields(
                  {
                    name:
                      'Total',
                    value:
                      String(
                        submissions.length
                      ),
                    inline: true
                  },
                  {
                    name:
                      'Pending',
                    value:
                      String(
                        pending
                      ),
                    inline: true
                  },
                  {
                    name:
                      'Accepted',
                    value:
                      String(
                        accepted
                      ),
                    inline: true
                  },
                  {
                    name:
                      'Denied',
                    value:
                      String(
                        denied
                      ),
                    inline: true
                  }
                )
            ]
          });
        }

        if (
          interaction.commandName ===
          'skye-help'
        ) {
          return interaction.reply({
            ephemeral: true,

            content:
              '**Skye Applications**\n\n' +
              '`/skye-panel` — post the application panel\n' +
              '`/skye-stats` — view application statistics\n' +
              '`/skye-help` — show this help message'
          });
        }
      }
    } catch (error) {
      console.error(
        'Interaction error:',
        error
      );

      if (
        !interaction.replied &&
        !interaction.deferred
      ) {
        await interaction.reply({
          content:
            'Skye encountered an error while processing that action.',
          ephemeral: true
        }).catch(() => {});
      }
    }
  }
);

setInterval(
  () => {
    for (
      const session
      of sessions.values()
    ) {
      if (
        session.startedAt &&
        Date.now() -
          session.startedAt >
          timeoutMs
      ) {
        sessions.delete(
          session.userId
        );
      }
    }

    for (
      const [state, data]
      of oauthStates
    ) {
      if (
        data.expires <
        Date.now()
      ) {
        oauthStates.delete(
          state
        );
      }
    }
  },
  60 * 1000
);

client.login(
  process.env.DISCORD_TOKEN
);