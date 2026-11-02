#!/usr/bin/env bash
# Shared matcher for scripts/protected-paths.txt. Sourced by
# scripts/guard.sh (CI) and .claude/hooks/protect-files.sh (agent hook) so
# both gates use exactly the same rules.
#
# Bash only: zsh does not treat an unquoted parameter as a glob inside
# [[ == ]], which would silently stop matching. Fail closed instead.
if [ -z "${BASH_VERSION:-}" ]; then
	echo "protected-lib.sh: must be sourced from bash" >&2
	return 2
fi

# protected_patterns <list-file>: print the active patterns of the list.
protected_patterns() {
	grep -v -e '^[[:space:]]*#' -e '^[[:space:]]*$' "$1"
}

# protected_match <list-file> <repo-relative-path>: exit 0 and print the
# matching pattern when the path is protected, exit 1 otherwise.
protected_match() {
	local list=$1 path=${2#./} pattern
	while IFS= read -r pattern; do
		# $pattern is unquoted on purpose in the elif below: it is a glob.
		# shellcheck disable=SC2053
		if [[ $pattern == */ ]]; then
			if [[ $path == "$pattern"* || $path == "${pattern%/}" ]]; then
				printf '%s\n' "$pattern"
				return 0
			fi
		elif [[ $path == $pattern ]]; then
			printf '%s\n' "$pattern"
			return 0
		fi
	done < <(protected_patterns "$list")
	return 1
}
