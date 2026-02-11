#!/usr/bin/env bash
echo "[c2bc] expect model"
tmp_script="$(mktemp)"
trap 'rm -f "$tmp_script"' EXIT
cat "example.dir/example.robust.config" "example.dir/example.robust.memory" > "$tmp_script"
exec binsec -sse -sse-script "$tmp_script" "example.dir/example.bin" "$@"
