# Redhook — AI Phishing Triage Engine

> DecodeLabs Cybersecurity Internship · Project 3 · Batch 2026

A professional-grade phishing triage platform built as part of the DecodeLabs Cybersecurity Industrial Training Kit. Redhook simulates a real SOC analyst workflow — paste any suspicious email and get an AI-powered threat verdict in seconds.

---

## Features

- **AI Threat Scoring** — Claude-powered analysis scores emails 0–100 with verdict classification (Malicious / Suspicious / Likely Safe)
- **URL Dissection** — Breaks apart domains left-to-right to expose lookalike roots and malicious subdomains
- **Automated Annotation** — Highlights urgency triggers, financial instructions, secrecy demands, and suspicious CTAs directly in the email body
- **Attack Type Tagging** — Classifies BEC, Credential Phishing, Mass Phishing, TOAD Callback, Spear Phishing
- **Case Management** — Sortable, filterable case log with status tracking
- **Threat Intelligence** — 7-day volume timeline, attack vector distribution, and IOC watchlist
- **Triage Report Export** — Download a structured `.txt` report for each analysis
- **Rule-based Fallback** — Works without an API key using heuristic detection

---

## Getting Started

### 1. Clone the repo

```bash
git clone https://github.com/your-username/redhook.git
cd redhook
```

### 2. Install dependencies

```bash
npm install
```

### 3. Set up your API key

```bash
cp .env.example .env
```

Open `.env` and replace `your_api_key_here` with your free Gemini API key from [aistudio.google.com](https://aistudio.google.com) → Get API Key.

> **Note:** The app works without an API key — it falls back to rule-based heuristic detection automatically.

### 4. Run the app

```bash
npm run dev
```

Open [http://localhost:5173](http://localhost:5173) in your browser.

---

## Project Structure

```
redhook/
├── src/
│   ├── App.jsx        # Full application (single-file React)
│   └── main.jsx       # Entry point
├── index.html
├── vite.config.js
├── package.json
├── .env.example       # Template for API key setup
└── .gitignore
```

---

## Tech Stack

- **React 18** with hooks
- **Vite** for bundling
- **Anthropic Claude API** for AI-powered triage
- Zero UI library dependencies — all custom components with inline styles

---

## Built By

Made as part of the **DecodeLabs Industrial Training Kit** — Cybersecurity Track, Batch 2026.
