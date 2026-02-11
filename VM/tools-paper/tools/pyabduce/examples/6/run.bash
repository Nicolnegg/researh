#!/usr/bin/env bash
exec ./pyabduce --binsec-config examples/6/binsec.conf --binsec-memory examples/6/binsec.mem --binsec-binary examples/6/f34.bin --binsec-addr 0x2fa --literals examples/6/literals.txt --max-depth 4 --binsec-directives examples/6/directives.txt --binsec-robust --robust-config examples/6/robust.conf $@
