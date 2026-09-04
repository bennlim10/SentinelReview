# SentinelReview frontend

Local Next.js interface for the SentinelReview FastAPI service. It submits public
GitHub repository and pull-request coordinates to the real analysis endpoint and
renders normalized deterministic findings plus optional AI reviews when present.

## Local setup

```bash
pnpm install
cp .env.example .env.local
pnpm dev
```

The default API URL is `http://localhost:8000`. Open `http://localhost:3000` after
the development server starts.

## Checks

```bash
pnpm exec tsc --noEmit
pnpm lint
pnpm build
```
