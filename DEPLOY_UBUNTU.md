# Deploy RootSecOps on Ubuntu

Use a dedicated scanning host. Read [SECURITY.md](SECURITY.md) before accepting
untrusted input or granting Docker access. Commands below run from the
repository root. Use `sudo docker` if your account cannot access Docker;
membership in the Docker group grants root-equivalent privileges.

## 1. Configuration

Install Docker Engine + Compose v2 using the
[official Ubuntu instructions](https://docs.docker.com/engine/install/ubuntu/).
Python 3 is needed for configuration generation.

```sh
python3 scripts/configure.py --front-domain rootsecops.test --api-domain api.rootsecops.test
```

Replace the names with your own hostnames. Both `FRONT_DOMAIN` and `API_DOMAIN`
must be bare names, **without** a protocol, port, or path.
No domain is hardcoded into the application.

Review `.env` locally. The generated administrator username is `admin`;
its password is random. Change `ADMIN_EMAIL` if needed. Keep secrets private.
The backend reapplies the configured administrator password at startup.

Direct frontend/API ports bind only to loopback. If 3000 is occupied, set
`FRONTEND_PORT=3001`. Do not stop an unrelated application to free its port.
Do not expose 3000/3001/8000 to the internet.

The documented public deployment uses ports 80/443. The compiled browser API
URL does not include a custom public port, so changing public ports alone is
not sufficient to support arbitrary port pairs.

## 2. Name resolution

DNS is optional for a private installation. On **every client** (including your
Mac if that is where the browser runs), add both names to its hosts file:

```text
SERVER_IP rootsecops.test api.rootsecops.test
```

Replace `SERVER_IP` with the server's reachable IP address.
On macOS/Linux the file is `/etc/hosts`. An entry on the server does not update
clients. Tests on the server can use `curl --resolve` instead.

## Host Nginx

Use this path when Nginx already owns ports 80/443. Do not enable the
`bundled-gateway` profile at the same time.

```sh
docker compose up -d --build
sudo apt-get install -y nginx openssl
sudo bash deploy/host-nginx/install.sh "$(pwd)/.env"
```

The installer renders a site from your environment, generates a self-signed
certificate covering both hostnames, validates Nginx, and reloads it.
It manages `/etc/nginx/sites-available/rootsecops.conf` and its
enabled symlink. Back up an existing file at that path before installation.

The installer does not remove unrelated virtual hosts. Review duplicate
`server_name` or listener warnings if another site uses the same names.
Nginx serves both HTTP and HTTPS; there is no forced redirect.

Certificate: `/etc/nginx/ssl/rootsecops/tls.crt`.
The private key must remain private.

## Bundled gateway alternative

If ports 80/443 are free:

```sh
docker compose --profile bundled-gateway up -d --build
```

The certificate is stored in the `tls_certs` volume. Export only the public
certificate for client trust:

```sh
docker compose cp gateway:/etc/nginx/certs/tls.crt ./rootsecops-local.crt
```

Trust the certificate on each client for both UI and API hostnames.
A browser bypass on the UI alone may not authorize API fetches.
For public deployments, provision a certificate from a trusted issuer instead.
Never turn off certificate validation globally.

## Image filesystem scanning

The default stack does not expose the host's Docker socket. Registry/SBOM
analysis can work without it, but Docker filesystem export cannot.

On a dedicated Linux scanner host, explicitly opt in:

```sh
export DOCKER_GID="$(stat -c '%g' /var/run/docker.sock)"
docker compose -f docker-compose.yml -f deploy/compose.docker-socket.yml up -d --build
docker compose exec -T worker docker version
```

Use both `-f` arguments and the same `DOCKER_GID` for future recreate operations;
otherwise Compose may remove the mount. The override is designed for Linux;
Docker Desktop socket ownership must be checked separately.

Verify create/export access without executing the image:

```sh
docker compose exec -T worker sh -eu -c '
  cid=$(docker create --pull=missing alpine:latest)
  trap '\''docker rm -f "$cid" >/dev/null'\'' EXIT
  docker export "$cid" >/dev/null
  echo "Docker filesystem export: OK"
'
```

This creates then removes a disposable container without starting it.
Socket access is root-equivalent even with a read-only filesystem and dropped
capabilities. Do not use `chmod 666 /var/run/docker.sock`.

## Database provisioning

Wait until the worker is running, then perform explicit maintenance without
active scans:

```sh
bash scripts/update-databases.sh
```

This initializes **both** Trivy databases (vulnerabilities and Java) and Grype.
It stops on failure. Databases live in the persistent `scanner_var` volume.
Trivy scan-time database downloads are disabled, and Compose disables Grype
auto-update. Re-run maintenance regularly on a connected host.

Local database scanning is not the same as a fully air-gapped pipeline:
image retrieval, Git clones, OSV, and tool version checks may use the network.
For an isolated environment, preload images and matching databases/rules,
disable online integrations and crawlers, and validate the complete workload
with egress blocked. Database imports must match the installed scanner schema.

Additional malware/rule maintenance:

```sh
docker compose exec -T worker freshclam --datadir=/var/lib/clamav --log=/tmp/freshclam.log
docker compose exec -T worker python manage.py seed_yara_rules
```

Review downloaded YARA repositories, licenses, and compilation compatibility.
Configure active rules through Admin. KICS requires query assets matching its
binary version; set its local database path to the queries directory.
Disable tools you do not intend to provision.

## Verify

These commands use the example domains. Substitute yours:

```sh
docker compose ps
curl -I --resolve rootsecops.test:80:127.0.0.1 http://rootsecops.test/login
curl -kI --resolve rootsecops.test:443:127.0.0.1 https://rootsecops.test/login
curl -k --resolve api.rootsecops.test:443:127.0.0.1 https://api.rootsecops.test/healthz
docker compose exec -T worker grype db status
docker compose logs --tail=100 backend worker
```

`-k` is for this local self-signed certificate diagnostic only.
Login and run a small authorized scan. Inspect each tool's status and logs;
a successful HTTP response or completed pipeline does not validate scanner coverage.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| CORS contains `http://http://` | Remove protocols from `FRONT_DOMAIN` and `API_DOMAIN`; recreate affected services. |
| Port already allocated | Change the loopback port in `.env`; recreate frontend and rerun the host Nginx installer. |
| Empty HTTP reply / TLS unrecognized name | Check enabled Nginx virtual hosts, names, and which process owns 80/443. Hosts-file entries alone do not configure Nginx. |
| Login: no active account | Use the credentials from your private `.env`; updating them requires recreating backend. |
| Docker permission denied | Check socket mount and numeric group inside worker, not just the SSH user's groups. |
| Docker client API too old | Rebuild the backend/worker images. The Dockerfile includes a modern Docker CLI. Do not mask incompatibility with a forced API version. |
| Trivy cannot skip on first run | Initialize vulnerability **and Java** databases in the same worker cache. |
| Grype database invalid during update | Let the update finish before scanning; verify `grype db status`. |
| DNS error on 127.0.0.11 | Diagnose Docker/host DNS and registry access. Retrying the scan does not create the database. |
| Cache directory permission denied | Inspect volume ownership against worker `id`. Fresh volumes inherit image ownership; migrated volumes need deliberate repair. Do not make them world-writable. |
| Scanner missing / no CVEs | Check binary, database freshness, tool errors, supported package ecosystem, and selected scanner policy. |

## Changes and backups

The default Compose project and database names are `rootsecops`, and the
host Nginx installer manages `rootsecops.conf`. These defaults are for fresh
installations. For an existing deployment, keep its project name and database
credentials until a deliberate migration: changing the Compose project name
creates a separate set of volumes rather than moving your data. Review
existing Nginx sites before installing another virtual host for the same domains.
Browser sessions need a fresh login after the application's storage namespace changes.

Changing `API_DOMAIN` requires `docker compose build frontend`, recreating
frontend/backend/worker/beat, and regenerating the Nginx configuration.
Refresh hosts entries and trust a replacement self-signed certificate if names change.

Back up PostgreSQL and required persistent volumes before upgrades.
Changing `POSTGRES_PASSWORD` does not rotate an already-initialized PostgreSQL
user automatically; coordinate a database password change.
`docker compose down` keeps volumes. **Do not use `down -v` unless you intend
to permanently delete stored scans, accounts, and databases.**
