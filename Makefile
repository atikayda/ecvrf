.PHONY: test test-python test-go test-rust test-ts test-cross vectors clean cli

PYTHON := $(if $(wildcard python/.venv/bin/python3),$(CURDIR)/python/.venv/bin/python3,python3)

test: test-python test-go test-rust test-ts test-cross

cli:
	mkdir -p scripts/.bin
	cd go && go build -o ../scripts/.bin/ecvrf-go ./cmd/ecvrf-cli
	cd rust && cargo build --example cli --release
	cd typescript && npm run build

test-python:
	cd python && $(PYTHON) ecvrf.py

test-go:
	cd go && go test ./...

test-rust:
	cd rust && cargo test

test-ts:
	cd typescript && npm test

test-cross:
	bash scripts/cross-validate.sh

vectors:
	cd python && $(PYTHON) generate.py

clean:
	cd go && go clean
	cd rust && cargo clean
	rm -rf typescript/dist
	rm -rf scripts/.bin
