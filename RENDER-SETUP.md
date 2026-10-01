# Skye public dashboard setup

## 1. Create a Discord OAuth client secret
In the Discord Developer Portal, open the same application used by the Skye bot. On OAuth2, add the exact redirect URL:

`https://YOUR-SERVICE.onrender.com/oauth/callback`

Keep the client secret private.

## 2. Deploy to Render
Create a **Web Service** from this repository and use:

- Build command: `npm install`
- Start command: `npm start`
- Health check: `/api/health`
- Plan: Free

The included `render.yaml` contains these settings.

## 3. Environment variables
Set:

- `DISCORD_TOKEN`
- `CLIENT_ID`
- `GUILD_ID`
- `DISCORD_CLIENT_SECRET`
- `PUBLIC_URL=https://YOUR-SERVICE.onrender.com`
- `DISCORD_OAUTH_REDIRECT=https://YOUR-SERVICE.onrender.com/oauth/callback`
- `TRUSTED_USER_IDS=YOUR_DISCORD_USER_ID`
- `DASHBOARD_PORT=10000`

## 4. Trusted access
The `TRUSTED_USER_IDS` value is the bootstrap allowlist. After signing in, trusted users can add/remove dashboard users in Settings.

You can also use Discord:

`/skye-trust @User`

or

`/skye-untrust @User`

Only users with Manage Server can use those bot commands.

## Important free-hosting limitation
Render's Free web services sleep after 15 minutes without inbound traffic and local filesystem data is ephemeral. That means the bot can go offline while sleeping and JSON-stored data should not be treated as permanent production storage.
