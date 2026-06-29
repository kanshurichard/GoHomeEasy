.PHONY: test test-js test-go test-python smoke

GOCACHE ?= $(CURDIR)/.cache/go-build
NODE_BIN ?= node
PYTHON_BIN ?= python3

test: test-js test-go test-python

test-js:
	$(NODE_BIN) --test

test-go:
	GOCACHE="$(GOCACHE)" go test ./...

test-python:
	$(PYTHON_BIN) -m unittest discover -s pytests -p 'test_*.py' -v

smoke:
	@if [ -z "$(ENDPOINT)" ] || [ -z "$(READ_TOKEN)" ] || [ -z "$(WRITE_TOKEN)" ]; then \
		echo "Usage: make smoke ENDPOINT=https://example.com READ_TOKEN=... WRITE_TOKEN=..." >&2; \
		exit 1; \
	fi
	./scripts/smoke-test.sh "$(ENDPOINT)" "$(READ_TOKEN)" "$(WRITE_TOKEN)"
