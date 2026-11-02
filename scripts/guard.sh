#!/usr/bin/env bash
# CI guard: fail when a pull request changes a protected path (see
# scripts/protected-paths.txt) unless the PR carries the
# `allow-guard-change` label.
#
# Usage: ALLOW_GUARD_CHANGE=true|false scripts/guard.sh <base-sha> <head-sha>
set -euo pipefail

base=${1:?usage: guard.sh <base-sha> <head-sha>}
head=${2:?usage: guard.sh <base-sha> <head-sha>}
allow=${ALLOW_GUARD_CHANGE:-false}
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
list="$root/scripts/protected-paths.txt"

# shellcheck source=scripts/protected-lib.sh
. "$root/scripts/protected-lib.sh"

hits=()
# --no-renames lists both sides of a rename, so moving a protected file away
# is caught too.
while IFS= read -r file; do
	[ -n "$file" ] || continue
	if pattern=$(protected_match "$list" "$file"); then
		hits+=("$file (matches '$pattern')")
	fi
done < <(git diff --name-only --no-renames "$base...$head")

if [ "${#hits[@]}" -eq 0 ]; then
	echo "guard: no protected path changed"
	exit 0
fi

echo "guard: protected paths changed in this PR:"
printf '  - %s\n' "${hits[@]}"

if [ "$allow" = "true" ]; then
	echo "guard: label 'allow-guard-change' present, allowing (human review required)"
	exit 0
fi

echo "::error title=Protected paths changed::Add the 'allow-guard-change' label after a human reviewed these changes."
exit 1
