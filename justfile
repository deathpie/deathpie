set shell := ["bash", "-euo", "pipefail", "-c"]

# List the recipes.
default:
    @just --list

# Format the repository.
fmt:
    bun fmt

# Fail if any file needs formatting.
fmt-check:
    bun fmt --check

# Check the agent skill files: frontmatter, recipes and the .claude symlinks.
agent-files:
    bun scripts/agent-files.ts

# Everything a pull request in this repository must pass.
check: fmt-check agent-files
