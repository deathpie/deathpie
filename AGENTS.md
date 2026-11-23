# Agent instructions

This repository is the public GitHub profile README for `deathpie`. It holds two files: the
profile text in `README.md` and the project icon in `favicon.svg`. GitHub renders `README.md` on
the account's profile page.

## Layout

- `README.md`: the profile text. Keep it short; it is a landing page, not a project.
- `favicon.svg`: the T3 Code project icon.
- `docs/exceptions.md`: rules this repository cannot meet, with reasons and revisit dates.

## Commands

- `just` lists the recipes.
- `just fmt` formats the repository; `just fmt-check` reports files that need it.
- `just agent-files` checks `.agents/skills` against `.claude/skills` (empty here).
- `just check` is the gate: `fmt-check` and `agent-files`.

## Invariants

- The repository has no code and no CI. `just check` is the whole gate.
- Do not add personal identifiers, email addresses, hostnames or tokens to the README.

## Never

- Push to `main`. It is a public repository with a ruleset: work on a branch and merge a pull
  request.
- Change GitHub settings, repository visibility or access from a workflow, script or agent run.
