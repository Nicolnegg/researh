#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RESEARCH_DIR="$(cd "${ROOT_DIR}/../.." && pwd)"

if [[ -z "${C2BC_BIN:-}" ]]; then
  if command -v c2bc >/dev/null 2>&1; then
    C2BC_BIN="c2bc"
  elif [[ -x "${ROOT_DIR}/venv/bin/c2bc" ]]; then
    C2BC_BIN="${ROOT_DIR}/venv/bin/c2bc"
  else
    C2BC_BIN="${ROOT_DIR}/tools/c2binsec/c2bc"
  fi
fi

if [[ -z "${PYABDUCE:-}" ]]; then
  if command -v pyabduce >/dev/null 2>&1; then
    export PYABDUCE="pyabduce"
  elif [[ -x "${ROOT_DIR}/venv/bin/pyabduce" ]]; then
    export PYABDUCE="${ROOT_DIR}/venv/bin/pyabduce"
  elif [[ -x "${ROOT_DIR}/tools/pyabduce/pyabduce" ]]; then
    export PYABDUCE="${ROOT_DIR}/tools/pyabduce/pyabduce"
  fi
fi

if [[ -d "${ROOT_DIR}/tools/pulseutils" ]]; then
  export PYTHONPATH="${ROOT_DIR}/tools/pulseutils${PYTHONPATH:+:${PYTHONPATH}}"
fi

if [[ -z "${BINSEC:-}" ]]; then
  if command -v binsec >/dev/null 2>&1; then
    export BINSEC="binsec"
  elif [[ -x "${RESEARCH_DIR}/binsec/_opam/bin/binsec" ]]; then
    export BINSEC="${RESEARCH_DIR}/binsec/_opam/bin/binsec"
  fi
fi

if [[ -z "${BINSEC:-}" ]]; then
  echo "[error] binsec not found. Set BINSEC or add binsec to PATH." >&2
  exit 1
fi

BENCHES=(
  bench_ct_sort
  bench_ct_sort_multiplex
  bench_ct_sort_negative
)

FAILED=()

for b in "${BENCHES[@]}"; do
  echo "=============================="
  echo "[ct-sort] $b"
  echo "=============================="
  if ! "${C2BC_BIN}" -i "${b}.c" --ct --ct-secret secret_in0,secret_in1,secret_in2 --ct-public public_tag; then
    echo "[error] c2bc failed for ${b}"
    FAILED+=("${b}:c2bc")
    continue
  fi
  if ! "./${b}.dir/${b}.abduce-run.bash" \
    --with-inequalities \
    --policy-report "${b}.report.json" \
    "$@"; then
    echo "[error] abduce failed for ${b}"
    FAILED+=("${b}:abduce")
    continue
  fi
done

if [[ ${#FAILED[@]} -gt 0 ]]; then
  echo "=============================="
  echo "[ct-sort] completed with failures:"
  printf ' - %s\n' "${FAILED[@]}"
  exit 1
fi

echo "=============================="
echo "[ct-sort] all benchmarks completed"
