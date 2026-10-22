#!/bin/sh
# synthetic download CGI for bench sample B-003.
# QUERY_STRING is expected as: file=report.txt
FILE=$(echo "$QUERY_STRING" | sed -n 's/^file=//p')

if [ -z "$FILE" ]; then
    echo "Content-Type: text/plain"
    echo
    echo "missing file parameter"
    exit 1
fi

# L-003: no canonicalization, no '../' rejection before the read
cat "/tmp/uploads/$FILE"
