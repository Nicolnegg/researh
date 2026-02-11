#!/usr/bin/env bash
exec ./pyabduce --binsec-config examples/4/binsec.conf --binsec-memory examples/4/binsec.mem --binsec-binary examples/4/f6.bin --binsec-addr 0x2fa --literals examples/4/literals.txt --max-depth 4 --binsec-directives examples/4/directives.txt $@
