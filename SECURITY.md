# Security policy

RootSecOps orchestrates third-party scanners. It is not a guarantee that an
artifact is safe, and this repository does not claim an independent security audit.

## Reporting a vulnerability

Use **Security > Advisories > Report a vulnerability** on this repository when
private reporting is available. Do not post exploit details, credentials, or
sensitive reports in public issues. If private reporting is unavailable, open
a minimal issue asking the maintainer for a private contact channel, with no
technical disclosure until that channel is established.

Include affected versions, impact, a minimal synthetic reproduction, and any
suggested mitigation. There is no guaranteed response-time SLA.

## Deployment boundaries

- Keep the application behind a trusted network/VPN and authenticated reverse
  proxy. Apply rate limits, request limits, network egress policy, and backups.
- Use HTTPS for credentials and JWTs. HTTP support is intended for local or
  trusted test networks. Self-signed certificates must be trusted on every client.
- Docker socket access is optional and is effectively root access to the Docker
  host. Use a dedicated disposable scanning host. A read-only socket mount is
  not an authorization boundary. Never make the socket world-writable.
- File analysis is static. The component named "sandbox" stages files and invokes
  tools; it is not a VM, an execution detonation chamber, or strong isolation.
- Scanners parse attacker-controlled files. Limit CPU, memory, disk, execution
  time, archive sizes, and network reachability for the workload you accept.
- Raw reports and logs may contain secrets or private paths. Restrict access,
  define retention, and never publish runtime volumes or scan outputs.
- Browser tokens are stored in localStorage. Protect against XSS, use short
  session lifetimes, and restrict browser access to trusted users.
- Bootstrap administrator credentials are reapplied from environment variables
  on backend startup. Rotate the environment value as well as the account.
- A completed job may contain failed/skipped tools. Inspect tool status and
  logs; zero findings are not a clean bill of health.
- Vulnerability databases must be provisioned and refreshed deliberately.
  Old or unavailable databases reduce coverage. OSV may need network access.
- Bootstrap downloads third-party releases/installers. Review them, pin versions
  and verify provenance for your deployment before running on sensitive hosts.

## Updates

Security fixes target the current main branch. No older release maintenance
schedule is promised. Review dependencies and scanner advisories regularly.
