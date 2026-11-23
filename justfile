set shell := ["bash", "-euo", "pipefail", "-c"]
set positional-arguments

# List the recipes.
default:
    @just --list

# Install the pinned tools from mise.toml. There is no package manager.
install:
    mise install

# Lefthook re-stages the fixes (`stage_fixed`).
# Format the given files, or the whole repository when none are given.
fmt *files:
    #!/usr/bin/env bash
    set -euo pipefail
    if (( $# )); then
        bun fmt -- "$@"
    else
        bun fmt
    fi

# Fail if any file needs formatting.
fmt-check:
    bun fmt --check

# The hook only passes files the core lint job covers, and this repository has
# no JavaScript or TypeScript to lint.
lint *files:
    #!/usr/bin/env bash
    set -euo pipefail
    if (( $# )); then
        exit 0
    fi

# Staged secret scan; gitleaks never prints a finding value.
[private]
secrets-staged:
    mise exec -- gitleaks git --staged --redact --no-banner

# Reject env files, private keys, kubeconfigs and files over 5 MB.
forbidden-files *files:
    #!/usr/bin/env bash
    set -euo pipefail
    bun scripts/forbidden-files.ts "$@"

# This repository has no workflows, so there is nothing for actionlint or
# zizmor to read.
workflows *files:
    #!/usr/bin/env bash
    set -euo pipefail
    exit 0

# shellcheck over the given scripts; this repository has none.
shellcheck *files:
    #!/usr/bin/env bash
    set -euo pipefail
    if (( $# )); then
        exit 0
    fi

# Check the agent skill files: frontmatter, recipes and the .claude symlinks.
agent-files:
    bun scripts/agent-files.ts

# Advisory Conventional Commit check (C2.4); never fails the commit.
commit-msg file:
    bun scripts/commit-msg.ts {{ quote(file) }}

# Effective author and committer emails are the owner's GitHub no-reply address.
privacy-identity:
    bun scripts/git-hook.ts privacy-identity

# The exact staged blobs.
privacy-staged:
    bun scripts/git-hook.ts privacy-staged

# Refuse a push to main, refuse unsigned commits, scan the exact pushed range.
[private]
hook-pre-push:
    mise exec -- bun scripts/git-hook.ts pre-push

# Fast subset for pre-push (C7.10): the formatting gate, under 30 s.
pre-push-check:
    just fmt-check

# Refresh the pinned tools when mise.toml changed (post-checkout, post-merge).
deps-refresh:
    bun scripts/deps-refresh.ts mise.toml

# Refuses a global or foreign core.hooksPath; migrates only `.githooks`.
# Enable the shared Lefthook hooks without changing global Git settings.
hooks:
    #!/usr/bin/env bash
    set -euo pipefail

    if ! mise exec -- lefthook version >/dev/null 2>&1; then
        printf 'lefthook is not installed; run `mise install` first.\n' >&2
        exit 1
    fi

    global=$(git config --global --get core.hooksPath || true)
    if [[ -n "$global" ]]; then
        printf 'A global core.hooksPath is set (%s); lefthook install refuses it.\n' "$global" >&2
        printf 'Remove it yourself, or use `lefthook install --force` only if you really mean it.\n' >&2
        exit 1
    fi

    existing=$(git config --get core.hooksPath || true)
    case "$existing" in
        ""|.githooks) ;;
        *)
            printf 'core.hooksPath is %s; integrate it manually.\n' "$existing" >&2
            exit 1
            ;;
    esac

    if [[ "$existing" == ".githooks" ]]; then
        git config --unset-all --local core.hooksPath
    fi

    mise exec -- lefthook install
    # A failed remote fetch only warns in 2.2.2 and still exits 0, so assert the
    # shared jobs loaded before declaring success.
    dump=$(mise exec -- lefthook dump)
    if ! grep -q 'name: core-' <<<"$dump" || ! grep -q 'name: owner-' <<<"$dump"; then
        printf 'The shared hook config did not load; check access to the .github repository.\n' >&2
        exit 1
    fi
    hookdir=$(git rev-parse --path-format=absolute --git-path hooks)
    if [[ ! -x "$hookdir/pre-commit" || ! -x "$hookdir/pre-push" ]]; then
        printf 'Lefthook did not write the pre-commit and pre-push shims.\n' >&2
        exit 1
    fi
    mise exec -- lefthook validate
    printf 'Shared Lefthook hooks installed; no global settings changed.\n'

# Everything a pull request in this repository must pass.
check: fmt-check agent-files
