# Thin wrapper: all task logic lives in scripts/tasks.py so it also runs on
# Windows without make (`python scripts/tasks.py <task>`).
PYTHON ?= python3
TASKS := setup lint typecheck test check fmt dev-backend dev-frontend up down gen-key demo-phase0

.PHONY: help $(TASKS)

help:
	@$(PYTHON) scripts/tasks.py

$(TASKS):
	@$(PYTHON) scripts/tasks.py $@
