#!/usr/bin/env bash
echo "[c2bc] expect unreachable"
tmp_script="$(mktemp)"
trap 'rm -f "$tmp_script"' EXIT
cat "example.dir/example.binsec.config" "example.dir/example.binsec.memory" > "$tmp_script"
exec "${BINSEC:-binsec}" -sse -sse-script "$tmp_script" "example.dir/example.bin" "$@"
