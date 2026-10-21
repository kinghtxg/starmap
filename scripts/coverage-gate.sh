#!/usr/bin/env bash
# 覆盖率门禁（CI 用）。
#
# 用法：scripts/coverage-gate.sh coverage.out 65
#   参数1 覆盖率文件（go test -coverprofile 产物）
#   参数2 全仓最低覆盖率（百分比整数）
#
# 两级门禁：
#   1. 全仓合并覆盖率不低于阈值（防整体退化）；
#   2. 核心包各自不低于下界（防"拿便宜包的平均分掩盖核心逻辑没测"）。
#
# 只拦"明显退化"，不做像素级卡点——门禁太严会逼人写无意义断言，反而降低测试质量。
set -euo pipefail

PROFILE="${1:-coverage.out}"
MIN_TOTAL="${2:-69}"

if [[ ! -f "$PROFILE" ]]; then
  echo "找不到覆盖率文件: $PROFILE" >&2
  exit 1
fi

# ---------- 1. 全仓总覆盖率 ----------
total=$(go tool cover -func="$PROFILE" | tail -1 | grep -oE '[0-9]+\.[0-9]+' | tail -1)
echo "全仓覆盖率: ${total}% (门槛 ${MIN_TOTAL}%)"

fail=0
if awk -v a="$total" -v b="$MIN_TOTAL" 'BEGIN{exit !(a<b)}'; then
  echo "::error::全仓覆盖率 ${total}% 低于门槛 ${MIN_TOTAL}%"
  fail=1
fi

# ---------- 2. 核心包各自下界 ----------
# 包名:最低覆盖率
CORE_TARGETS=(
  "starmap/internal/parser:65"
  "starmap/internal/topology:65"
  "starmap/internal/detect:75"
  "starmap/internal/ledger:80"
  "starmap/internal/review:75"
  "starmap/internal/store:60"
  "starmap/internal/api:55"
  "starmap/internal/auth:75"
  "starmap/internal/logging:70"
  "starmap/internal/metrics:85"
)

for target in "${CORE_TARGETS[@]}"; do
  pkg="${target%%:*}"
  min="${target##*:}"
  out=$(go test -count=1 -cover "$pkg" 2>/dev/null | grep -oE 'coverage: [0-9]+\.[0-9]+' | grep -oE '[0-9]+\.[0-9]+' || echo "0.0")
  echo "  ${pkg}: ${out}% (门槛 ${min}%)"
  if awk -v a="$out" -v b="$min" 'BEGIN{exit !(a<b)}'; then
    echo "::error::${pkg} 覆盖率 ${out}% 低于门槛 ${min}%"
    fail=1
  fi
done

if [[ "$fail" -ne 0 ]]; then
  echo "覆盖率门禁未通过" >&2
  exit 1
fi

echo "覆盖率门禁通过"
