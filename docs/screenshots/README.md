# Desktop dashboard screenshot

This PNG captures the actual RootSecOps desktop interface running locally, with
synthetic API responses supplied by Playwright. No real deployment,
credentials, private targets, or scan results are shown.

It demonstrates the interface, not measured vulnerability coverage or
production usage.

To reproduce from `frontend/`:

```sh
npm ci
npx playwright install chromium
NEXT_PUBLIC_API_URL=http://127.0.0.1:3301/api/v1 npm run build
npm run test:ui
```

The test starts a loopback-only UI on port 3300, supplies sample data in the
browser test context, checks desktop interactions and viewport overflow, and writes
the desktop screenshot here. No mock authentication route is added to the
application.

To use an existing Chrome installation instead of downloading Chromium, run
`PLAYWRIGHT_CHANNEL=chrome npm run test:ui`.
