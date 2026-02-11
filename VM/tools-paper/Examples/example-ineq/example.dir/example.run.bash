#!/usr/bin/env bash
echo "[c2bc] expect unreachable"
exec binsec -file example.dir/example.bin -config example.dir/example.binsec.config -sse-memory example.dir/example.binsec.memory $@
