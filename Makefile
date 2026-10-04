.PHONY: setup-tools backend-dev frontend-dev docker-up docker-build docker-down test lint update-db seed

setup-tools:
	./scripts/bootstrap_tools.sh

backend-dev:
	cd backend && . .venv/bin/activate && python manage.py runserver 127.0.0.1:8000

frontend-dev:
	cd frontend && npm run dev

docker-build:
	docker compose build

docker-up:
	docker compose up

docker-down:
	docker compose down

test:
	cd backend && . .venv/bin/activate && python manage.py test scanner_engine

lint:
	cd frontend && npm run lint

seed:
	cd backend && . .venv/bin/activate && python manage.py seed_scanners && python manage.py seed_yara_rules

update-db:
	bash scripts/update-databases.sh
