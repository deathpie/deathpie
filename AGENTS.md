# Agent instructions

This repository is the public GitHub profile README for `deathpie`. It holds two files: the
profile text in `README.md` and the project icon in `favicon.svg`. GitHub renders `README.md` on
the account's profile page.

## Layout

- `README.md`: the profile text. Keep it short; it is a landing page, not a project.
- `favicon.svg`: the T3 Code project icon.
- `lefthook.yml`: loads the shared hook jobs from `deathpie/.github` at `hooks-v2`. The
  `core-policy` job refuses a push to `main` and refuses unsigned commits.
- `docs/exceptions.md`: rules this repository cannot meet, with reasons and revisit dates.

## Commands

- `just` lists the recipes.
- `just fmt` formats the repository; `just fmt-check` reports files that need it.
- `just agent-files` checks `.agents/skills` against `.claude/skills` (empty here).
- `just check` is the gate: `fmt-check` and `agent-files`.
- `just hooks` installs the shared Lefthook hooks into `.git/hooks` for every worktree of this
  clone; it never changes global Git settings.

## Invariants

- The repository has no code and no CI. `just check` is the whole gate.
- Do not add personal identifiers, email addresses, hostnames or tokens to the README.

## Never

- Push to `main`. It is a public repository with a ruleset: work on a branch and merge a pull
  request.
- Skip hooks (C7.11): never set `LEFTHOOK=0`, never pass `--no-verify`, and never add a
  `lefthook-local.yml`. The `pre-push` hook and the ruleset are the gate.
- Change GitHub settings, repository visibility or access from a workflow, script or agent run.
