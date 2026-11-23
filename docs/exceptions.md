# Exceptions

Rules from [`standards/core.md`](https://github.com/deathpie/.github/blob/main/standards/core.md)
and [`standards/owner.md`](https://github.com/deathpie/.github/blob/main/standards/owner.md) that
this repository cannot meet, with the reason and the date to revisit.

| Rule       | Reason                                                                                                                                                                                 | Revisit    |
| ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- |
| C1.6       | The repository is a two-file profile README with no code, so there is no work to license. The owner standard keeps it license-free until it grows code.                                | 2027-02-23 |
| C2.2, C5.1 | The repository is text-only and the owner standard gives it no CI, so there is no required check and no median to report. The pull request itself is the gate.                         | 2027-02-23 |
| C7.5       | `install`, `lint`, `typecheck`, `test` and `hooks` have nothing to run: there is no code, no dependency manifest and no workflow. `fmt`, `fmt-check`, `agent-files` and `check` exist. | 2027-02-23 |
