#!/bin/sh
# Lint only issues introduced since HEAD (pre-commit). On the very first
# commit there is no HEAD to compare against, so lint the whole module.
set -eu

if git rev-parse --verify --quiet HEAD >/dev/null; then
	exec golangci-lint run --new-from-rev=HEAD ./...
fi

echo "lint-new: no HEAD yet (first commit), running full lint" >&2
exec golangci-lint run ./...
