# StarMap 星图 — 本地开发命令
#
# 与 CI（.github/workflows/ci.yml）保持一致：本地 `make ci` 通过 = CI 基本会过。

APP        := starmap
CMD        := ./cmd/starmap
VERSION    := $(shell grep -oE 'Version = "[^"]+"' internal/version/version.go | head -1 | cut -d'"' -f2)
COMMIT     := $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)
LDFLAGS    := -s -w -X starmap/internal/version.Version=$(VERSION) -X starmap/internal/version.Commit=$(COMMIT)
MIN_COVER  := 65

.PHONY: help
help:
	@echo "make build     构建单二进制"
	@echo "make run       本地启动（监听 configs/config.yaml）"
	@echo "make test      全量测试"
	@echo "make race      竞态检测（需要 gcc/cgo）"
	@echo "make cover     覆盖率报告 + 门禁"
	@echo "make fuzz      跑一轮模糊测试（各 60s）"
	@echo "make bench     性能基线"
	@echo "make lint      格式检查 + vet"
	@echo "make ci        完整流水线（lint + race + cover）"
	@echo "make clean     清理产物"

.PHONY: build
build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(APP)$(shell go env GOEXE) $(CMD)
	@echo "已构建 $(APP) $(VERSION)+$(COMMIT)"

.PHONY: run
run:
	go run $(CMD) -config configs/config.yaml

.PHONY: test
test:
	go test ./...

.PHONY: race
race:
	CGO_ENABLED=1 go test -race -count=1 ./...

.PHONY: cover
cover:
	go test ./... -coverpkg=./internal/...,./cmd/... -coverprofile=coverage.out
	go tool cover -func=coverage.out | tail -1
	bash scripts/coverage-gate.sh coverage.out $(MIN_COVER)
	@go tool cover -html=coverage.out -o coverage.html && echo "报告: coverage.html"

.PHONY: fuzz
fuzz:
	go test ./internal/parser/ -run '^$$' -fuzz=FuzzExtractForwarded -fuzztime=60s
	go test ./internal/ledger/ -run '^$$' -fuzz=FuzzParseCSV -fuzztime=60s

.PHONY: bench
bench:
	go test ./internal/topology/ -bench=. -benchmem -run '^$$'

.PHONY: lint
lint:
	@out=$$(gofmt -l cmd internal test testdata 2>/dev/null); \
	if [ -n "$$out" ]; then echo "未格式化:"; echo "$$out"; exit 1; fi
	go vet ./...

.PHONY: ci
ci: lint race cover

.PHONY: clean
clean:
	rm -f coverage.out coverage-all.out coverage.html $(APP) $(APP).exe
	rm -rf dist
