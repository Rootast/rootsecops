# RootSecOps backend

Django REST Framework, Celery, and scanner adapters. Python 3.13.

For the full stack, use the root [deployment guide](../DEPLOY_UBUNTU.md).
For API/UI development without external scanner execution:

```sh
cd backend
python3.13 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python manage.py migrate
python manage.py seed_scanners
python manage.py createsuperuser
SCANNER_MOCK_MODE=true python manage.py runserver 127.0.0.1:8000
```

This uses SQLite and inline execution by default. Mock mode produces sample
findings, not real analysis. Docker Compose uses PostgreSQL and asynchronous
workers with mock mode disabled.

Django reads process environment variables, not a dotenv file automatically.
Compose supplies them from the root configuration. For local development,
export your environment explicitly; do not put real credentials into shell history.

Checks:

```sh
python manage.py check
python manage.py test scanner_engine
```

See [architecture and API](../docs/README.md) and [security](../SECURITY.md).
