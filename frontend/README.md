# IR-Agent Frontend

React/Vite frontend for the IR-Agent cybersecurity incident response demo.

The interface shows a SOC-style dashboard for security events, demo incident risks, ML model status, and an assistant panel connected to the IR-Agent backend.

## What It Does

- Shows a demo log database with 100 security events.
- Marks 7 events as suspicious and groups them into 2 demo incidents.
- Displays event status as `Норма` or `Риск`.
- Shows incident details: affected hosts, findings, MITRE count, recommendations.
- Exports an example audit report as a `.doc` file.
- Connects to the IR-Agent backend for ML/model status and agent queries.

## Demo Flow

1. Open the frontend.
2. Click `Скан логов`.
3. The app loads 100 demo logs.
4. The model simulation highlights 7 risky events.
5. Open the `Риски` or `Модель` section.
6. Click an incident and export the audit report.

## Requirements

- Node.js 18+
- npm
- Optional: running IR-Agent backend on `http://127.0.0.1:9000`

The frontend still works with the local demo dataset if the backend is unavailable.

## Install

```powershell
npm install
```

## Run

```powershell
npm run dev
```

Default local URL:

```text
http://localhost:5173
```

If port `5173` is busy:

```powershell
npm run dev -- --host 0.0.0.0 --port 5174 --strictPort
```

## Build

```powershell
npm run build
```

## Backend Proxy

Vite proxies these paths to the IR-Agent backend:

```text
/ingest  -> http://127.0.0.1:9000
/ml      -> http://127.0.0.1:9000
/agent   -> http://127.0.0.1:9000
/health  -> http://127.0.0.1:9000
```

The backend project used during development:

```text
https://github.com/qbert2004/Ir_agent
```

## Backend LLM Setup

For the assistant panel to answer through the backend, configure the backend `.env`:

```env
LLM_PROVIDER=google
GOOGLE_API_KEY=your_google_ai_studio_key
GOOGLE_AI_MODEL=models/gemma-4-31b-it
```

Then restart the backend so it reloads `.env`.

## Scripts

```text
npm run dev      Start Vite dev server
npm run build    Build production bundle
npm run lint     Run ESLint
npm run preview  Preview production build
```

## Notes

- This repository contains only the frontend.
- Backend source code is not included here.
- Demo incidents are generated in the frontend for presentation/testing.
- Real production use should connect the scan flow to SIEM, Windows Event Log, Sysmon, or another log collector.
