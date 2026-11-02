#!/usr/bin/env bash
# PreToolUse hook for Edit|Write|MultiEdit|NotebookEdit.
# Blocks (exit 2) edits to protected paths (scripts/protected-paths.txt) and
# to global files that can disable the gates; asks the human before editing
# go.mod/go.sum/go.work. Fails closed.
HOOK_NAME=protect-files
# shellcheck source=.claude/hooks/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh" || exit 2

target=$(jq -r '.tool_input.file_path // .tool_input.notebook_path // empty' <<<"$HOOK_INPUT")
[ -n "$target" ] || block "no file_path/notebook_path in tool input"

verdict=$(classify_path "$target")
case $verdict in
protected:*) block "${verdict#protected:}" ;;
ask:*) ask "${verdict#ask:}" ;;
esac
exit 0
