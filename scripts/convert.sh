#!/bin/bash
# convert.sh - Convert kernel BPF verifier test files to JSON
#
# Usage: ./convert.sh <input.c> [output.json]
#
# Examples:
#   ./convert.sh array_access.c                    # outputs to stdout
#   ./convert.sh array_access.c array_access.json  # outputs to file
#   
# Batch convert all files in a directory:
#   for f in verifier/*.c; do ./convert.sh "$f" "json/$(basename "$f" .c).json"; done

set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <input.c> [output.json]" >&2
    exit 1
fi

INPUT="$1"
OUTPUT="${2:-/dev/stdout}"

if [ ! -f "$INPUT" ]; then
    echo "Error: Input file '$INPUT' not found" >&2
    exit 1
fi

# Get the directory where this script lives
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Compile with the specified test file
gcc -D TEST_FILE="\"$INPUT\"" \
    -o /tmp/convert_tests_$$ \
    "$SCRIPT_DIR/convert_tests.c" 2>&1

# Run and capture output
/tmp/convert_tests_$$ > "$OUTPUT" 2>&1

# Cleanup
rm -f /tmp/convert_tests_$$

if [ "$OUTPUT" != "/dev/stdout" ]; then
    # Validate JSON
    if command -v python3 &> /dev/null; then
        COUNT=$(python3 -c "import json; d=json.load(open('$OUTPUT')); print(len(d))" 2>/dev/null) || {
            echo "Error: Output is not valid JSON" >&2
            exit 1
        }
        echo "Converted $COUNT test cases to $OUTPUT" >&2
    fi
fi