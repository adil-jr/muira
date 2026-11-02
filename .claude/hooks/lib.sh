#!/usr/bin/env bash
# Shared helpers for the Claude Code guard hooks. Sourced, never executed.
#
# Both hooks FAIL CLOSED: any unexpected error exits 2 (block). settings.json
# also sets "onFailure": "block" as a second layer.

# block <reason>: print the reason for Claude and block the tool call.
block() {
	printf 'BLOCKED by %s: %s\n' "${HOOK_NAME:-guard hook}" "$1" >&2
	printf 'Do not work around this gate. Stop and explain to the human; for protected files, propose a diff for the human to apply.\n' >&2
	exit 2
}

# ask <reason>: let the human confirm the tool call.
ask() {
	jq -n --arg r "$1" '{hookSpecificOutput: {hookEventName: "PreToolUse",
		permissionDecision: "ask", permissionDecisionReason: $r}}'
	exit 0
}

trap 'block "internal hook error at line $LINENO (failing closed)"' ERR
set -E -o pipefail

command -v jq >/dev/null 2>&1 || block "jq is not installed (failing closed)"

HOOK_INPUT=$(cat) || block "could not read hook input"
jq -e . >/dev/null 2>&1 <<<"$HOOK_INPUT" || block "hook input is not valid JSON"

PROJECT_ROOT=${CLAUDE_PROJECT_DIR:-$(jq -r '.cwd // empty' <<<"$HOOK_INPUT")}
[ -n "$PROJECT_ROOT" ] || block "cannot determine the project root"
PROJECT_ROOT=$(realpath -m -- "$PROJECT_ROOT")
PROTECTED_LIST="$PROJECT_ROOT/scripts/protected-paths.txt"
[ -r "$PROTECTED_LIST" ] || block "missing $PROTECTED_LIST"
# shellcheck source=scripts/protected-lib.sh
. "$PROJECT_ROOT/scripts/protected-lib.sh" || block "cannot load protected-lib.sh"

# Files outside the repository that can switch the gates off: user-level
# Claude Code settings (disableAllHooks), global git config (core.hooksPath)
# and the global mise config.
GLOBAL_PROTECTED=(
	"$HOME/.claude/settings.json"
	"$HOME/.claude/settings.local.json"
	"$HOME/.gitconfig"
	"$HOME/.config/git/"
	"$HOME/.config/mise/"
)

# classify_path <path>: print "protected:<why>", "ask:<why>" or "free".
# Relative paths are resolved against the project root; symlinks are
# resolved so a link pointing at a protected file is caught.
classify_path() {
	local p=$1 abs rel g match
	p=${p//\$\{CLAUDE_PROJECT_DIR\}/$PROJECT_ROOT}
	p=${p//\$CLAUDE_PROJECT_DIR/$PROJECT_ROOT}
	p=${p//\$\{HOME\}/$HOME}
	p=${p//\$HOME/$HOME}
	# A literal "~/" prefix (the shell would have expanded it).
	case $p in \~/*) p="$HOME/${p:2}" ;; esac
	[[ $p == /* ]] || p="$PROJECT_ROOT/$p"
	abs=$(realpath -m -- "$p")

	for g in "${GLOBAL_PROTECTED[@]}"; do
		if [[ $abs == "$g" || ($g == */ && ($abs == "$g"* || $abs == "${g%/}")) ]]; then
			echo "protected:$g can disable the gates"
			return
		fi
	done

	if [[ $abs != "$PROJECT_ROOT" && $abs != "$PROJECT_ROOT/"* ]]; then
		echo free
		return
	fi
	rel=${abs#"$PROJECT_ROOT"}
	rel=${rel#/}

	case $rel in
	go.mod | go.sum | go.work | go.work.sum)
		echo "ask:$rel changes dependencies; the allowlist is in .golangci.yml (depguard)"
		return
		;;
	esac

	if [ -z "$rel" ]; then
		echo "protected:the project root contains protected paths"
		return
	fi
	if match=$(protected_match "$PROTECTED_LIST" "$rel"); then
		echo "protected:$rel matches protected pattern '$match'"
		return
	fi
	# A directory that contains a protected path (e.g. .git, scripts/..).
	while IFS= read -r match; do
		if [[ $match == "$rel/"* ]]; then
			echo "protected:$rel contains protected path '$match'"
			return
		fi
	done < <(protected_patterns "$PROTECTED_LIST")
	echo free
}
