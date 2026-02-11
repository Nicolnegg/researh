#!/usr/bin/env bash
echo "[c2bc] expect unreachable"
exec binsec -file example.dir/example.bin -config example.dir/example.robust.config -sse-memory example.dir/example.robust.memory $@
