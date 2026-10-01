# Skye Applications

A minimal Discord-first application system with a local control dashboard.

## Start the bot + dashboard

Open PowerShell in the `bot` folder:

```powershell
npm install
npm run deploy
npm start
```

The bot will print the dashboard URL, normally:

`http://127.0.0.1:8787`

If port 8787 is already occupied, Skye automatically uses 8788 and prints the exact URL.

## Environment

Copy `.env.example` to `.env` and set:

```env
DISCORD_TOKEN=your_bot_token
CLIENT_ID=your_application_client_id
GUILD_ID=your_server_id
DASHBOARD_PORT=8787
```

## Discord flow

1. Run `/skye-config` to set application channels and the review role.
2. Run `/skye-panel` to post the application panel.
3. Applicant clicks an application type.
4. Skye sends a clean DM confirmation embed with Start Application, Cancel Application, and a disabled Sent By Skye Support button.
5. Start edits the confirmation into an Application Started embed.
6. Every question is shown in its own embed with a Cancel Application button.
7. Applicants have 3 hours to finish.
8. Completed applications are posted to the configured review channel.
9. Staff can Accept, Accept with Reason, Deny, Deny with Reason, or view Details.

## Dashboard

The dashboard is served by the Discord bot. It is not a separate web backend.

It directly reads/writes `bot/data/config.json`, so dashboard saves affect the real bot configuration.

Dashboard features:
- Overview and live submission counts
- Application type editor
- Add/remove/reorder questions by editing the real config
- Enable/disable application types
- Submission search
- Panel settings
- Channel IDs and review role
- Editable DM messages
- Post the Discord panel from the dashboard
- Animated save state: Loading. / Loading.. / Loading...

## Useful commands

- `/skye-panel` — post the application panel
- `/skye-config` — configure channels and review role
- `/skye-stats` — application totals
- `/skye-search` — search applications
- `/skye-applicant` — view a user's applications
- `/skye-help` — command help


## Public dashboard + Discord login

The dashboard supports Discord OAuth2 and a trusted-user allowlist. A public URL alone does not grant dashboard access.

### Local
1. Create a Discord OAuth2 client secret.
2. Add `http://127.0.0.1:8787/oauth/callback` as an OAuth redirect URI.
3. Put your Discord user ID in `TRUSTED_USER_IDS`.
4. Run `npm install` and `npm start`.
5. Open the dashboard URL printed by Skye and choose **Continue with Discord**.

### Free public hosting with Render
Render supports free Node web services, but free services sleep after 15 minutes of inactivity and their local filesystem is ephemeral. Treat the included JSON files as prototype storage; use a database/persistent storage before production.

Set: `DISCORD_TOKEN`, `CLIENT_ID`, `GUILD_ID`, `DISCORD_CLIENT_SECRET`, `PUBLIC_URL`, `DISCORD_OAUTH_REDIRECT`, `TRUSTED_USER_IDS`, and `DASHBOARD_PORT=10000`. Add the exact OAuth redirect URI to your Discord application.

Use `/skye-trust @User` and `/skye-untrust @User` to manage dashboard access.
