#!/bin/sh
# argv[1]: output directory. Run as root.
mkdir -p "$1"
cp .github/reuse-hijack.py /tmp/reuse-hijack.py
python3 /tmp/reuse-hijack.py > "$1/hijack.txt" 2>&1
cat "$1/hijack.txt"
