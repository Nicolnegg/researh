#!/usr/bin/env bash
exec ./pyabduce --binsec-config examples/5/binsec.conf --binsec-memory examples/5/binsec.mem --binsec-binary examples/5/f28.bin --binsec-addr 0x2fe --literals examples/5/literals.txt --max-depth 4 --binsec-directives examples/5/directives.txt $@
