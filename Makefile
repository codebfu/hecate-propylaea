.PHONY: help prerequisites build test lint clean docker-build docker-up docker-down

CARGO ?= cargo
COMPOSE ?= docker compose -f docker/docker-compose.yml

help:
	@echo "Hecate Propylaea targets:"
	@echo "  prerequisites  Fetch Rust dependencies (requires ../hecate)"
	@echo "  build          Release build"
	@echo "  test           Run tests"
	@echo "  lint           clippy -D warnings"
	@echo "  clean          cargo clean"
	@echo "  docker-build   Build image (context: parent dir)"
	@echo "  docker-up      Start compose stack"
	@echo "  docker-down    Stop compose stack"

prerequisites:
	@test -d ../hecate/crates/protocol || (echo "Missing ../hecate — clone hecate next to this repo" && exit 1)
	@command -v $(CARGO) >/dev/null || (echo "Rust/cargo not found" && exit 1)
	-$(CARGO) fetch

build: prerequisites
	$(CARGO) build --release

test: prerequisites
	$(CARGO) test

lint: prerequisites
	$(CARGO) clippy -- -D warnings

clean:
	$(CARGO) clean

docker-build:
	docker build -f docker/Dockerfile -t hecate-propylaea:local ..

docker-up:
	$(COMPOSE) up -d

docker-down:
	$(COMPOSE) down
