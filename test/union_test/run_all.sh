#!/usr/bin/env bash
# 依次跑所有 union_test 用例，汇总
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

total_pass=0
total_fail=0

for f in [0-9][0-9]_*.sh; do
  out=$(bash "$f" 2>&1)
  rc=$?
  printf '%s\n' "$out"
  # 提取每个脚本末尾的 PASS/FAIL
  pass_line=$(printf '%s\n' "$out" | grep -E 'PASS=[0-9]+ FAIL=[0-9]+' | tail -1)
  if [[ -n "$pass_line" ]]; then
    p=$(printf '%s\n' "$pass_line" | sed -E 's/.*PASS=([0-9]+).*/\1/')
    fl=$(printf '%s\n' "$pass_line" | sed -E 's/.*FAIL=([0-9]+).*/\1/')
    total_pass=$((total_pass + p))
    total_fail=$((total_fail + fl))
  else
    total_fail=$((total_fail + 1))
  fi
  echo
done

echo "=============================="
echo "UNION TOTAL: PASS=$total_pass FAIL=$total_fail"
echo "=============================="
[[ $total_fail -eq 0 ]]
