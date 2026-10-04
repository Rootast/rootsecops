# Contributing to RootSecOps

Thanks for helping improve RootSecOps. Small, well-tested fixes are welcome.

## Before you start

- Search existing issues and describe the problem before a large change.
- For vulnerabilities, follow [SECURITY.md](SECURITY.md), not a public issue.
- Use synthetic images, files, and credentials in examples. Do not attach real
  scan reports, private source code, tokens, or deployment configuration.
- Keep changes focused. Avoid unrelated formatting and dependency upgrades.

## Development

See [backend setup](backend/README.md) and [frontend setup](frontend/README.md).
Use Python 3.13 and Node.js 22. Run these checks before opening a pull request:

```sh
python3 -m unittest discover -s scripts/tests
cd backend
python manage.py check
python manage.py test scanner_engine
cd ../frontend
npm ci
npm run lint
NEXT_PUBLIC_API_URL=http://localhost:8000/api/v1 npm run build
```

Backend unit/API tests use a temporary SQLite database and mock scanner
subprocesses. They do not prove that external scanner services are configured.
Changes to adapters should include fixtures for findings, empty results,
malformed output, missing binaries, and the tool's documented exit codes.

## Pull requests

Describe what changed, why, how it was tested, and any deployment implications.
For UI changes, include screenshots with sanitized sample data. Add documentation
when environment variables, command flags, or public behavior change.

Contributions are made under the project's [MIT License](LICENSE). Third-party
tools and data keep their own licenses. Be respectful and constructive in
issues and reviews.
