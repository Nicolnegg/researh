#!/usr/bin/env bash
exec ./pyabduce --binsec-config examples/2/binsec.conf --binsec-memory examples/2/binsec.mem --binsec-binary examples/2/f30.bin --binsec-addr 0x2fe --literals examples/2/literals.txt --max-depth 4 --binsec-directives examples/2/directives.txt $@
