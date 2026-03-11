# Don't Lie To Me - AI-Powered SMS Scam Detection

**Microsoft Hackathon 2026 | Azure Ecosystem**

A unified system to identify scammers and help users stay safe. When a person receives an SMS from an unknown number, the AI finds red flags in the message and checks the sender's number against a scam database.

## Quick Start

**Requirements:** Node.js 22+ (tested on Node 24)

```bash
npm install
npm run dev
```

Open **http://localhost:5173** in your browser.

## How It Works

1. **Paste an SMS** - Enter the suspicious message and optionally the sender's phone number
2. **AI Analysis** - 30+ pattern checks detect urgency tactics, phishing links, impersonation, financial requests, and more
3. **Database Lookup** - Phone number is checked against a pre-seeded database of known scam and legitimate numbers
4. **Online Search** - If the number isn't in the database, simulated online sources are searched for reports
5. **Risk Score** - All signals are combined into a 0-100% risk score with actionable recommendations

## Demo Features

- **8 pre-loaded scam templates** - Click any demo card to instantly test (bank fraud, IRS threat, delivery scam, phishing, prize scam, romance scam, toll payment, + legitimate comparison)
- **16 seeded phone numbers** - 12 known scam numbers + 4 verified legitimate numbers
- **Risk gauge visualization** - Color-coded SVG gauge from green (safe) to red (critical)
- **Red flag breakdown** - Each detected pattern shown with severity, description, and matched text
- **Scammer database browser** - View and search all known numbers with report counts
- **Report new numbers** - Community reporting form to flag new scam numbers

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 19 + TypeScript + Microsoft Fluent UI v9 |
| Backend | Node.js + Express |
| Database | SQLite (Node.js built-in `node:sqlite`) |
| Build | Vite 6 |
| AI Engine | Rule-based pattern matching (no API keys needed) |

## Project Structure

```
server/              # Backend API
  database/          # SQLite connection, schema, seed data
  engine/            # Scam detection (patterns, scoring, online search)
  routes/            # REST API endpoints
src/                 # React frontend
  components/        # UI components (analyzer, gauge, flags, etc.)
  pages/             # Tab pages (Analyze, Database, About)
  api/               # API client
```

## API Endpoints

- `POST /api/analyze` - Analyze a message (main endpoint)
- `GET /api/numbers` - List known scam/legitimate numbers
- `GET /api/numbers/templates` - Get demo message templates
- `GET /api/numbers/stats` - Dashboard statistics
- `POST /api/report` - Report a new scam number

## Team

Built for the Microsoft Hackathon 2026 - namashworks/dont_lie_to_me_azure
