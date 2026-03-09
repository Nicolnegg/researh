#!/usr/bin/env bash
export PYTHONHASHSEED="${PYTHONHASHSEED:-0}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
local_pyabduce=""
local_tools_root=""
local_pythonpath="${PYTHONPATH:-}"
for rel in "../../../../tools" "../../../tools"; do
  cand="${script_dir}/${rel}/pyabduce/pyabduce"
  if [[ -x "$cand" ]]; then
    local_pyabduce="$cand"
    local_tools_root="${script_dir}/${rel}"
    break
  fi
done
if [[ -d "${local_tools_root}/pulseutils" ]]; then
  local_pythonpath="${local_tools_root}/pulseutils${local_pythonpath:+:${local_pythonpath}}"
elif [[ -d "${local_tools_root}/fistic/local/pulseutils" ]]; then
  local_pythonpath="${local_tools_root}/fistic/local/pulseutils${local_pythonpath:+:${local_pythonpath}}"
fi
if [[ -z "${PYABDUCE:-}" && -n "$local_pyabduce" ]]; then
  if PYTHONPATH="${local_pythonpath}" "$local_pyabduce" --help >/dev/null 2>&1; then
    PYABDUCE="$local_pyabduce"
    export PYTHONPATH="${local_pythonpath}"
  fi
fi
if [[ "${ABDUCE_PAPER_MODE:-0}" = "1" ]]; then
  set -- --paper-mode "$@"
fi
if [[ "${ABDUCE_HIDE_BINSEC_TIMES:-1}" = "1" ]]; then
  set -o pipefail
  "${PYABDUCE:-pyabduce}" --binsec-config example.dir/example.binsec.config --binsec-memory example.dir/example.binsec.memory --binsec-binary example.dir/example.bin --binsec-addr 0x80498fa --literals example.dir/example.abd.literals.txt --binsec-directives example.dir/example.abd.directives.txt --binsec-timeout 60 $@ 2>&1 | sed '/\* binsec times:/d'
  exit "${PIPESTATUS[0]}"
fi
exec "${PYABDUCE:-pyabduce}" --binsec-config example.dir/example.binsec.config --binsec-memory example.dir/example.binsec.memory --binsec-binary example.dir/example.bin --binsec-addr 0x80498fa --literals example.dir/example.abd.literals.txt --binsec-directives example.dir/example.abd.directives.txt --binsec-timeout 60 $@
