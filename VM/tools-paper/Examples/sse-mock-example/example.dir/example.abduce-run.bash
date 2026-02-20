#!/usr/bin/env bash
export PYTHONHASHSEED="${PYTHONHASHSEED:-0}"
if [[ "${ABDUCE_PAPER_MODE:-0}" = "1" ]]; then
  set -- --paper-mode "$@"
fi
exec "${PYABDUCE:-pyabduce}" --binsec-config example.dir/example.binsec.config --binsec-memory example.dir/example.binsec.memory --binsec-binary example.dir/example.bin --binsec-addr 0x80498fa --literals example.dir/example.abd.literals.txt --binsec-directives example.dir/example.abd.directives.txt --binsec-timeout 60 $@
