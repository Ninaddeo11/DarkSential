# Thin wrapper: all task logic lives in scripts/tasks.py so it also runs on
# Windows without make (`python scripts/tasks.py <task>`).
PYTHON ?= python3
TASKS := setup lint gen-types typecheck test check fmt dev-backend dev-frontend up down gen-key export-reqs demo-phase0 demo-phase1 demo-phase2 demo-phase3 demo-phase4 demo-phase5 ablation docker-test docker-test-nft docker-test-mqtt lab-up lab-down lab-status lab-attack lab-smoke docker-demo-phase1 docker-demo-phase2

.PHONY: help $(TASKS)

help:
	@$(PYTHON) scripts/tasks.py

$(TASKS):
	@$(PYTHON) scripts/tasks.py $@
