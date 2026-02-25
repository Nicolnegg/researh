#!/usr/bin/env bash
export PYTHONHASHSEED="${PYTHONHASHSEED:-0}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
local_pyabduce="${script_dir}/../../../tools/pyabduce/pyabduce"
if [[ -z "${PYABDUCE:-}" && -x "$local_pyabduce" ]]; then
  PYABDUCE="$local_pyabduce"
fi
if [[ "${ABDUCE_PAPER_MODE:-0}" = "1" ]]; then
  set -- --paper-mode "$@"
fi
exec "${PYABDUCE:-pyabduce}" --binsec-config example.dir/example.binsec.config --binsec-memory example.dir/example.binsec.memory --binsec-binary example.dir/example.bin --binsec-addr 0x080498ee --literals example.dir/example.abd.literals.txt --binsec-directives example.dir/example.abd.directives.txt --binsec-timeout 60 $@
