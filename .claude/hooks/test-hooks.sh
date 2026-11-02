#!/usr/bin/env bash
# Regression tests for the Claude Code guard hooks: feed sample PreToolUse
# JSON through stdin and check the verdict (block = exit 2, ask = JSON
# permissionDecision "ask", allow = exit 0 without output).
#
# Usage: .claude/hooks/test-hooks.sh   (from anywhere inside the repo)
set -uo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$here/../.." && pwd)
export CLAUDE_PROJECT_DIR=$root
pass=0
fail=0

# run <hook> <json>: print the verdict.
run() {
	local out code
	out=$("$here/$1" <<<"$2" 2>/dev/null)
	code=$?
	if [ "$code" -eq 2 ]; then
		echo block
	elif [ "$code" -eq 0 ] && grep -q '"permissionDecision": *"ask"' <<<"$out"; then
		echo ask
	elif [ "$code" -eq 0 ] && [ -z "$out" ]; then
		echo allow
	else
		echo "error($code)"
	fi
}

# expect <verdict> <hook> <json> <label>
expect() {
	local got
	got=$(run "$2" "$3")
	if [ "$got" = "$1" ]; then
		pass=$((pass + 1))
		printf 'ok    %-5s %-15s %s\n' "$got" "$2" "$4"
	else
		fail=$((fail + 1))
		printf 'FAIL  want %s got %s  %s  %s\n' "$1" "$got" "$2" "$4"
	fi
}

edit() { # edit <tool> <path>
	local field=file_path
	[ "$1" = NotebookEdit ] && field=notebook_path
	jq -nc --arg t "$1" --arg f "$field" --arg p "$2" \
		'{hook_event_name: "PreToolUse", tool_name: $t, tool_input: {($f): $p}}'
}
bash_cmd() { # bash_cmd <command>
	jq -nc --arg c "$1" '{hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: {command: $c}}'
}
e() { expect "$1" protect-files.sh "$(edit "$2" "$3")" "$2 $3"; }
b() { expect "$1" guard-bash.sh "$(bash_cmd "$2")" "$2"; }

echo "== protect-files.sh (Edit|Write|MultiEdit|NotebookEdit)"
e block Edit "$root/.golangci.yml"
e block Write "$root/.golangci.yaml"
e block Edit "$root/lefthook.yml"
e block Write "$root/lefthook-local.yml"
e block Edit "$root/Makefile"
e block Edit "$root/mise.toml"
e block Write "$root/mise.local.toml"
e block Write "$root/.config/mise/config.toml"
e block Write "$root/.tool-versions"
e block Edit "$root/scripts/commit-msg.sh"
e block Write "$root/.github/workflows/ci.yml"
e block Edit "$root/.claude/settings.json"
e block Write "$root/.claude/settings.local.json"
e block Edit "$root/.claude/settings.local.json"
e block Write "$root/testdata/gcm.rsp"
e block Edit "$root/CLAUDE.md"
e block MultiEdit "$root/internal/../Makefile"
e block NotebookEdit "$root/testdata/x.ipynb"
e block Write "$root/.git/hooks/pre-commit"
e block Write "$HOME/.claude/settings.json"
e block Edit "$HOME/.gitconfig"
e ask Edit "$root/go.mod"
e ask Edit "$root/go.sum"
e ask Write "$root/go.work"
e allow Write "$root/internal/crypto/aead.go"
e allow Edit "$root/docs/ROADMAP.md"
e allow Edit "$root/README.md"
e allow Write "/tmp/scratch/notes.txt"

echo "== guard-bash.sh (Bash)"
b block 'git commit --no-verify -m "feat: x"'
b block 'git commit -n -m "feat: x"'
b block 'git commit -am "feat: x" -n'
b block 'git commit -anm "feat: x"'
b block 'LEFTHOOK=0 git commit -m "feat: x"'
b block 'export LEFTHOOK_EXCLUDE=lint'
b block 'git config core.hooksPath /dev/null'
b block 'git -c core.hooksPath=/dev/null commit -m "feat: x"'
b block 'git config --unset hooks.foo'
b block 'mise exec -- lefthook uninstall'
b block 'git push origin main'
b block 'git push origin HEAD:main'
b block 'git push --force origin +main'
b block 'git push --all'
b block 'mise use golangci-lint@1.64.0'
b block 'mise unuse shellcheck'
b block 'mise set FOO=bar'
b block 'mise settings set experimental true'
b block 'mise config set tools.go 1.20'
b block 'MISE_ENV=dev make lint'
b block 'MISE_GO_VERSION=1.20 make test'
b block 'export MISE_CONFIG_FILE=/tmp/x.toml'
b block 'mise -E dev exec -- golangci-lint run'
b block 'mise exec golangci-lint@1.64.0 -- golangci-lint run'
b block 'echo x > Makefile'
b block 'echo x >> .golangci.yml'
b block 'printf x | tee scripts/commit-msg.sh'
b block "sed -i 's/85/50/' scripts/coverage-floor.sh"
b block 'mv lefthook.yml /tmp/'
b block 'rm -rf testdata'
b block 'rm -rf .git'
b block 'rm -rf .'
b block 'cp /tmp/evil.yml .github/workflows/ci.yml'
b block 'chmod -x .claude/hooks/guard-bash.sh'
# The hook sees the raw command text, so the variable must stay unexpanded.
# shellcheck disable=SC2016
b block 'cd /tmp && rm -rf "$CLAUDE_PROJECT_DIR/scripts"'
b block 'find scripts -name "*.sh" -delete'
b block 'git checkout -- Makefile'
b block 'git rm CLAUDE.md'
b block 'echo "{}" > ~/.claude/settings.json'
# disableAllHooks: true in local settings outranks the project settings.
b block "echo '{\"disableAllHooks\": true}' > .claude/settings.local.json"
b block 'jq ".disableAllHooks = true" .claude/settings.json | tee .claude/settings.local.json'
b block "cp /tmp/off.json .claude/settings.local.json"
b block "claude -p --settings '{\"disableAllHooks\": true}' 'edit Makefile'"
b block 'claude --setting-sources user -p "edit Makefile"'
b allow 'claude --version'
# Patches can write any path: the agent never applies them.
b block 'git apply /tmp/fix.patch'
b block 'git apply --check /tmp/fix.patch'
b block 'git -C . am < 0001-fix.patch'
b block 'patch -p1 < fix.diff'
b block 'cat fix.diff | patch -p1'
b block 'mise exec -- patch -p1 -i fix.diff'
b allow 'git format-patch -1 HEAD -o /tmp/patches'
b allow 'git diff > /tmp/change.patch'
b allow 'git log --patch -1'
b ask "sed -i 's/v1/v2/' go.mod"
b allow 'git commit -m "feat(crypto): add Argon2id key derivation"'
b allow 'git push origin feat/crypto'
b allow 'git status --short'
b allow 'git diff Makefile'
b allow 'cat Makefile .golangci.yml'
b allow 'cp Makefile /tmp/Makefile.bak'
b allow 'make lint test'
b allow 'mise exec -- go test -race ./...'
b allow 'mise ls --current'
b allow 'mise install'
b allow 'go test ./... 2>&1 > /tmp/out.txt'
b allow 'echo hi >&2'
b allow 'rm -f internal/vault/zz_violation.go'
b allow 'sed -n 1,20p Makefile'
b allow 'go get golang.org/x/crypto@latest'

echo
echo "passed: $pass  failed: $fail"
[ "$fail" -eq 0 ]
