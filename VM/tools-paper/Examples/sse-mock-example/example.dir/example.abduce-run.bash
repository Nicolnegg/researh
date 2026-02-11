#!/usr/bin/env bash
exec pyabduce --binsec-config example.dir/example.binsec.config --binsec-memory example.dir/example.binsec.memory --binsec-binary example.dir/example.bin --binsec-addr 0x8049885 --literals example.dir/example.abd.literals.txt --binsec-directives example.dir/example.abd.directives.txt --binsec-timeout 60 $@
