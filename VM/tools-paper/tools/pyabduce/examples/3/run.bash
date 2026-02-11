#!/usr/bin/env bash
exec ./pyabduce --binsec-config examples/3/binsec.conf --binsec-memory examples/3/binsec.mem --binsec-binary examples/3/f17.bin --binsec-addr 0x32e --literals examples/3/literals.txt --max-depth 4 --binsec-directives examples/3/directives.txt $@
