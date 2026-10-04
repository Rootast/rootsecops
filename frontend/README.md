# RootSecOps frontend

Next.js App Router, React, TypeScript, Tailwind CSS, and Recharts. Node.js 22.

From this directory:

```sh
npm ci
cp .env.example .env.local
npm run dev
```

Open http://localhost:3000/login. A running Django backend and an account are
required for normal use. See [backend development](../backend/README.md).

`NEXT_PUBLIC_API_URL` is public configuration embedded at build time, not a
secret. Changing it requires rebuilding. Docker Compose constructs it from
`API_DOMAIN`; the production browser talks directly to the API virtual host.

```sh
npm run lint
npm run build
```

Screenshot fixtures are synthetic and are not scanner results.
See [screenshot notes](../docs/screenshots/README.md).
