.PHONY: env up down logs demo local-up local-e2e test test-backend test-frontend test-e2e lint

PYTHON ?= python3

env:
	$(PYTHON) scripts/ensure_env.py

up: env
	docker compose up --build -d
	@echo "Platform running:"
	@echo "  Frontend: http://localhost:5173"
	@echo "  Backend API: http://localhost:8000/docs"

down:
	docker compose down

logs:
	docker compose logs -f

demo: env
	docker compose run --rm --no-deps backend python -m app.streaming.generator --demo-burst

local-up:
	$(PYTHON) scripts/run_local_stack.py

local-e2e:
	$(PYTHON) scripts/run_local_stack.py --e2e

test: test-backend test-frontend

test-backend:
	cd backend && pytest --cov=app/privacy --cov=app/detection --cov-report=term-missing

test-frontend:
	cd frontend && npm test -- --run

test-e2e:
	cd frontend && npx playwright test

lint:
	cd backend && ruff check app tests
	cd frontend && npm run lint
