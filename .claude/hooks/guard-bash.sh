#!/usr/bin/env bash
# PreToolUse hook for Bash. BEST EFFORT: it parses shell text with simple
# heuristics and can be fooled (interpreters, eval, variables, `cd` before a
# relative path, ...). The real gate is CI: the `guard` job plus branch
# protection, and lefthook/golangci-lint running again in CI.
#
# Blocks (exit 2):
#   - hook bypasses: --no-verify, `git commit -n`, LEFTHOOK* variables,
#     core.hooksPath, `git config` touching hooks, `lefthook uninstall`;
#   - config rewrites without editing files: `mise use|unuse|set|unset`,
#     `mise settings set|unset|add`, `mise config set`, `mise -E/--env`,
#     `mise exec tool@version`, and any MISE_* variable assignment;
#   - `git push` to main (or --all/--mirror);
#   - writes to protected paths through >, >>, tee, sed -i, perl -i, mv, rm,
#     cp, install, ln, rsync, dd of=, chmod, chown, truncate, touch, unlink,
#     shred, find -delete/-exec, git rm|mv|restore|checkout;
#   - patch application (git apply, git am, patch): a diff can name any path,
#     so the agent never applies patches; the human does, outside Claude Code;
#   - nested `claude --settings/--setting-sources` (can drop project hooks).
HOOK_NAME=guard-bash
# shellcheck source=.claude/hooks/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh" || exit 2

cmd=$(jq -r '.tool_input.command // empty' <<<"$HOOK_INPUT")
[ -n "$cmd" ] || exit 0
flat=$(tr '\n\t' '  ' <<<"$cmd")

has() { grep -Eq -- "$1" <<<"$flat"; }
hasi() { grep -Eiq -- "$1" <<<"$flat"; }

# --- Whole-command checks ----------------------------------------------------
has '--no-verify' && block "--no-verify bypasses git hooks"
has '(^|[^A-Za-z0-9_])LEFTHOOK[A-Za-z0-9_]*=' && block "LEFTHOOK* variables can disable or redirect git hooks"
has '(^|[^A-Za-z0-9_])MISE_[A-Za-z0-9_]*=' && block "MISE_* variables can override pinned tool versions or mise config"
hasi 'core\.hookspath' && block "core.hooksPath redirects git hooks away from lefthook"
has 'lefthook([[:space:]]+[^[:space:]]+)*[[:space:]]+uninstall' && block "lefthook uninstall removes the git hooks"
# A nested Claude Code run can drop these hooks: --settings takes precedence
# over project and local settings (e.g. {"disableAllHooks": true}), and
# --setting-sources can leave the project settings out.
has '(^|[^A-Za-z0-9_./-])claude([[:space:]]+[^[:space:]]+)*[[:space:]]+--(settings|setting-sources)([[:space:]=]|$)' &&
	block "nested claude with --settings/--setting-sources can disable the project hooks"

# strip_token <word>: remove shell quotes around a word.
strip_token() {
	local t=$1
	t=${t//\"/}
	t=${t//\'/}
	printf '%s' "$t"
}

# check_path <word> <action>: block/ask if the word names a protected path.
check_path() {
	local word verdict
	word=$(strip_token "$1")
	[ -n "$word" ] || return 0
	[[ $word == -* ]] && return 0
	verdict=$(classify_path "$word")
	case $verdict in
	protected:*) block "$2 ${verdict#protected:}" ;;
	ask:*) ask "$2 ${verdict#ask:}" ;;
	esac
}

# --- Per simple-command checks ----------------------------------------------
# Split on newlines and command separators; keep redirections in place.
segments=$(sed -E 's/(\|\||&&|;|\||\$\(|`|\(|\))/\n/g' <<<"$cmd")

set -f # no glob expansion while splitting words
while IFS= read -r seg; do
	[[ $seg =~ [^[:space:]] ]] || continue

	# Redirection targets: > file, >> file, >| file, 2> file, &> file.
	while IFS= read -r redir; do
		[ -n "$redir" ] || continue
		target=$(sed -E 's/^>>?\|?[[:space:]]*//' <<<"$redir")
		check_path "$target" "redirection into protected path:"
	done < <(grep -oE '>>?\|?[[:space:]]*[^[:space:]>&|;]+' <<<"$seg" || true)

	read -r -a words <<<"$seg"
	n=${#words[@]}
	for ((i = 0; i < n; i++)); do
		w=$(strip_token "${words[i]}")
		w=${w##*/} # /bin/rm -> rm
		rest=("${words[@]:i+1}")

		case $w in
		rm | rmdir | mv | chmod | chown | chgrp | truncate | touch | tee | unlink | shred)
			for a in "${rest[@]}"; do check_path "$a" "$w on protected path:"; done
			;;
		sed | perl)
			inplace=false
			for a in "${rest[@]}"; do
				[[ $a =~ ^-[A-Za-z]*i|^--in-place ]] && inplace=true
			done
			if $inplace; then
				for a in "${rest[@]}"; do check_path "$a" "$w -i on protected path:"; done
			fi
			;;
		cp | install | ln | rsync)
			# Only the destination (last argument) is written.
			if ((${#rest[@]} > 0)); then
				check_path "${rest[-1]}" "$w into protected path:"
			fi
			;;
		dd)
			for a in "${rest[@]}"; do
				[[ $a == of=* ]] && check_path "${a#of=}" "dd into protected path:"
			done
			;;
		find)
			if [[ " ${rest[*]} " =~ \ -(delete|exec|execdir|ok)\  ]]; then
				for a in "${rest[@]}"; do
					[[ $a == -* || $a == '!' || $a == '(' ]] && break
					check_path "$a" "find -delete/-exec on protected path:"
				done
			fi
			;;
		mise)
			# Global flags before the subcommand.
			j=0
			while ((j < ${#rest[@]})); do
				a=$(strip_token "${rest[j]}")
				case $a in
				-E | --env | --env=* | -E*) block "mise -E/--env loads alternative config files" ;;
				-C | --cd) ((j += 2)) ;;
				-*) ((j += 1)) ;;
				*) break ;;
				esac
			done
			sub=$(strip_token "${rest[j]:-}")
			sub2=$(strip_token "${rest[j + 1]:-}")
			case "$sub $sub2" in
			"use "* | "u "* | "unuse "* | "set "* | "unset "*)
				block "mise $sub rewrites mise configuration; versions are pinned in mise.toml"
				;;
			"settings set" | "settings unset" | "settings add" | "config set")
				block "mise $sub $sub2 rewrites mise configuration"
				;;
			"exec "* | "x "* | "run "* | "r "*)
				for ((k = j + 1; k < ${#rest[@]}; k++)); do
					a=$(strip_token "${rest[k]}")
					[[ $a == -- ]] && break
					[[ $a == *@* ]] && block "mise $sub $a overrides the version pinned in mise.toml"
				done
				;;
			esac
			;;
		git)
			# Skip git global options to find the subcommand.
			j=0
			while ((j < ${#rest[@]})); do
				a=$(strip_token "${rest[j]}")
				case $a in
				-c)
					[[ ${rest[j + 1]:-} == *[Hh][Oo][Oo][Kk]* ]] && block "git -c touching hook settings"
					((j += 2))
					;;
				-C | --git-dir | --work-tree | --namespace) ((j += 2)) ;;
				-*) ((j += 1)) ;;
				*) break ;;
				esac
			done
			sub=$(strip_token "${rest[j]:-}")
			args=("${rest[@]:j+1}")
			case $sub in
			commit)
				skip=false
				for a in "${args[@]}"; do
					a=$(strip_token "$a")
					if $skip; then
						skip=false
						continue
					fi
					# The value of -m/-F/-C/-c is not a flag.
					[[ $a == -[mFCc] ]] && skip=true && continue
					[[ $a =~ ^-[A-Za-z]*n[A-Za-z]*$ ]] && block "git commit -n skips the pre-commit and commit-msg hooks"
				done
				;;
			config)
				[[ " ${args[*]} " == *[Hh][Oo][Oo][Kk]* ]] && block "git config touching hooks"
				;;
			push)
				for a in "${args[@]}"; do
					a=$(strip_token "$a")
					[[ $a == --all || $a == --mirror ]] && block "git push $a would push main"
					[[ $a =~ (^|[:+/])main$ ]] && block "pushing to main is not allowed; the human pushes and merges"
				done
				;;
			rm | mv | restore | checkout)
				for a in "${args[@]}"; do check_path "$a" "git $sub on protected path:"; done
				;;
			apply | am)
				block "git $sub writes whatever paths the patch names, including protected ones; the human applies patches outside Claude Code"
				;;
			esac
			;;
		patch)
			block "patch writes whatever paths the diff names, including protected ones; the human applies patches outside Claude Code"
			;;
		esac
	done
done <<<"$segments"

exit 0
