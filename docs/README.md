# Architecture and API

RootSecOps separates interactive requests from scanner execution.

## Components

| Component | Responsibility |
| --- | --- |
| Next.js / React UI | Login, dashboard, scan submission, results, tool/user administration |
| Django REST API | Authentication, access control, uploads, scan records and configuration |
| PostgreSQL | Users, tasks, normalized results, scanner configuration and tool state |
| Redis | Celery message broker and result backend |
| Celery worker | Preprocessing, scanner commands, normalization and persistence |
| Celery Beat | Scheduled tool version/database checks |
| Nginx | Separate frontend/API virtual hosts, HTTP/HTTPS, request size limits |

Application logs are structured JSON on stdout and rotating local files.
No external log indexing service is required.

## Pipeline

1. An authenticated user submits an artifact.
2. Django validates input, stores uploads where applicable, creates an owned
   task, and queues a Celery job.
3. Preprocessing generates SBOMs, clones repositories, or exports an image's
   filesystem, depending on artifact type and tool requirements.
4. Enabled scanners execute with timeouts and per-tool coordination.
5. Normalizers combine findings into vulnerabilities, secrets,
   misconfigurations, malware, metadata, and SBOM sections.
6. The browser polls progress and fetches normalized results.

The pipeline records individual failures and continues where possible.
`SUCCESS` currently means orchestration finished, not that every scanner passed.
Consult `errors`, `toolStatus`, and task logs.

## API overview

Base path: `/api/v1`. Protected endpoints accept
`Authorization: Bearer <access-token>`. Never put tokens in URLs.

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/auth/login/` | Username/password to JWT pair |
| POST | `/auth/refresh/` | Refresh the access token |
| POST | `/auth/logout/` | Logout / refresh-token revocation |
| GET | `/auth/me/` | Current user |
| GET | `/dashboard/` | User-scoped scan overview |
| POST | `/scans/` | Create an image, repository, Dockerfile, or file scan |
| GET | `/scans/{uuid}/status/` | Progress and logs |
| GET | `/scans/{uuid}/results/` | Normalized results |
| GET | `/tools/` | Tool status |
| GET/POST | `/admin/users/` | Administrator user management |
| GET | `/admin/tools/` | Administrator tool inventory |
| PATCH/DELETE | `/admin/tools/{name}/` | Scanner configuration |
| POST | `/admin/tools/{name}/actions/` | Tool maintenance action |
| POST | `/admin/yara-rules/` | Rule upload |

Routes and serializers in `backend/scanner_engine/` are the source of truth.
Health endpoint: backend `/health/`, exposed by Nginx as API `/healthz`.

Example scan body (JSON, no file upload):

```json
{
  "asset_type": "docker",
  "target": "alpine:latest",
  "options": {"generate_sbom": true, "deep_scan": true}
}
```

File/Dockerfile uploads use multipart fields `asset_type`, `target`, `file`,
and JSON-encoded `options`. See [file analysis](../FILE_UPLOAD_GUIDE.md).

## Repository map

```text
backend/
  config/                 Django and Celery configuration
  scanner_engine/
    core/                 Orchestration, adapters, preprocessing, normalization
    management/commands/  Administrator bootstrap, tools and rule seeding
    migrations/           Database schema
frontend/src/
  app/                    Login, dashboard, admin and compatibility API routes
  components/             Shared UI components
  lib/                    API, auth and sample data types
deploy/
  host-nginx/             Ubuntu host Nginx installer and template
  nginx/                  Optional bundled gateway
scripts/                  Setup and explicit database maintenance
docs/screenshots/         Sanitized UI captures
.github/                  CI and contribution templates
```

## Extending scanners

Implement a `BaseScanner` adapter under `core/scanners/`, register its supported
inputs in `core/registry.py`, and add normalization plus focused fixture tests.
Use argument lists, documented exit codes, bounded execution, and structured
errors. A findings exit code must not be confused with a broken invocation.

`SCANNER_MOCK_MODE` and frontend sample fixtures exist for development.
They are not a security verdict and must not be used to validate real scans.

## Operational boundaries

Read [security policy](../SECURITY.md) and [deployment guide](../DEPLOY_UBUNTU.md).
Image extraction rejects unsafe archive paths. This is a safeguard, not a
resource isolation boundary. Run untrusted workloads on isolated infrastructure.
