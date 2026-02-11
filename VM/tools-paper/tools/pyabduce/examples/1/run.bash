#!/usr/bin/env bash
exec ./pyabduce --binsec-config examples/1/binsec.conf --binsec-memory examples/1/binsec.mem --binsec-binary examples/1/f17.bin --binsec-addr 0x2e2 --literals examples/1/literals.txt --max-depth 4 --binsec-directives examples/1/directives.txt $@
