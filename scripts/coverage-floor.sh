#!/usr/bin/env bash
# Enforce a minimum statement coverage on critical packages.
# Usage: scripts/coverage-floor.sh <coverprofile>
#
# For each package in FLOOR_PKGS:
#   - only doc.go (no code yet)  -> skipped, with a notice;
#   - code but no *_test.go      -> FAIL (untested code is not exempt);
#   - otherwise coverage must be >= COVERAGE_FLOOR percent.
set -euo pipefail

profile=${1:?usage: coverage-floor.sh <coverprofile>}
floor=${COVERAGE_FLOOR:-85}
module=$(go list -m)
read -r -a pkgs <<<"${FLOOR_PKGS:-internal/crypto internal/vault}"

status=0
for pkg in "${pkgs[@]}"; do
	code=$(find "$pkg" -maxdepth 1 -type f -name '*.go' ! -name '*_test.go' ! -name 'doc.go' | wc -l)
	tests=$(find "$pkg" -maxdepth 1 -type f -name '*_test.go' | wc -l)

	if [ "$code" -eq 0 ]; then
		echo "coverage: $pkg has no code yet, floor not enforced"
		continue
	fi
	if [ "$tests" -eq 0 ]; then
		echo "coverage: FAIL $pkg has code but no tests" >&2
		status=1
		continue
	fi

	# Profile lines: <importpath>/<file>:<start>,<end> <numStmts> <count>.
	# Deduplicate blocks (keep the max count) and only count files that live
	# directly in the package directory, not in sub-packages.
	pct=$(awk -v prefix="$module/$pkg/" '
		NR == 1 { next }
		index($1, prefix) == 1 {
			rest = substr($1, length(prefix) + 1)
			if (index(rest, "/") > 0) next
			stmts[$1] = $2
			if ($3 > hits[$1]) hits[$1] = $3
		}
		END {
			for (b in stmts) { total += stmts[b]; if (hits[b] > 0) covered += stmts[b] }
			if (total == 0) { print "0.0"; exit }
			printf "%.1f", 100 * covered / total
		}' "$profile")

	if awk -v p="$pct" -v f="$floor" 'BEGIN { exit !(p + 0 >= f + 0) }'; then
		echo "coverage: ok   $pkg ${pct}% (floor ${floor}%)"
	else
		echo "coverage: FAIL $pkg ${pct}% < floor ${floor}%" >&2
		status=1
	fi
done

exit "$status"
