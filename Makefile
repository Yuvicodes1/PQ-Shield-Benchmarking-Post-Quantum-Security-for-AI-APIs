.PHONY: setup test train sweep smoke-sweep analyze figures docker-build docker-run clean

setup:
	python3 -m venv .venv
	.venv/bin/pip install --upgrade pip
	.venv/bin/pip install -r requirements.txt
	bash scripts/install_oqs.sh

train:
	.venv/bin/python -m model.train

test:
	.venv/bin/python -m pytest -q

# Full A/B/C/control x {10,100,1000} x 5-repetition matrix (30-45 min on a
# single core; scale --requests-per-concurrency down further if needed).
sweep:
	.venv/bin/python -m bench.orchestrator \
		--configs control,classical,hybrid,full-pqc \
		--concurrency 10,100,1000 \
		--repetitions 5 \
		--requests-per-concurrency 5 \
		--min-requests 50

# Fast sanity-check sweep (seconds, not minutes) -- for development only.
smoke-sweep:
	.venv/bin/python -m bench.orchestrator \
		--configs control,classical,hybrid,full-pqc \
		--concurrency 5 --repetitions 1 --requests-per-concurrency 2 --min-requests 5 \
		--raw-dir /tmp/smoke_raw --summary-out /tmp/smoke_summary.json

analyze:
	.venv/bin/python -m analysis.aggregate
	.venv/bin/python -m analysis.tradeoff_matrix

figures:
	.venv/bin/python -m analysis.figures
	.venv/bin/python -m analysis.plot_metrics

webapp:
	bash scripts/run_webapp.sh

docker-build:
	docker build -t pq-shield .

docker-run:
	docker run --rm -p 8000:8000 pq-shield

clean:
	rm -rf results/raw/*.csv results/*.json outputs/*.png .pytest_cache __pycache__
