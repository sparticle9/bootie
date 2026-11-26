#!/bin/sh
# merge-key-files OUT [IN ...]
# Filter every readable authorized_keys-style input, concatenate in order, and
# deduplicate exact lines across all sources. Missing/unreadable inputs are
# ignored so optional discovery sources can be passed unconditionally.
set -eu

[ "$#" -ge 1 ] || {
    echo "usage: merge-key-files OUT [IN ...]" >&2
    exit 2
}
out=$1
shift
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
tmp="$out.merge.tmp"
: > "$tmp"
for f do
    [ -r "$f" ] || continue
    "$here/keyfilter.sh" < "$f" >> "$tmp"
done
awk '!seen[$0]++' "$tmp" > "$out"
rm -f "$tmp"
