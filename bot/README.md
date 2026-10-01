# Skye Applications Bot

A Discord-native application system for Skye.

## What it does
- Application panel with configurable application types
- DM-only questionnaire flow that asks every configured question
- Automatic `SKYE-000001` IDs
- Separate submission channels per application type
- Review role pinging
- Clean review cards with **Accept**, **Accept with Reason**, **Deny**, **Deny with Reason**, and **Details**
- Reason dialogs are native Discord modals
- Applicant DM notifications
- Configurable role automation
- Local JSON persistence; no web backend/API required

## Setup
1. Install Node.js 18+.
2. `cd bot && npm install`
3. Copy `.env.example` to `.env` and fill in the bot token, client ID, and server ID.
4. `npm run deploy`
5. `npm start`
6. In Discord use `/skye-config`, then `/skye-panel`.

The bot needs the Server Members Intent and Message Content Intent enabled in the Discord Developer Portal.
Applicants must allow DMs from server members.
