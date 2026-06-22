# Project Rules

This file is shared by Codex (`AGENTS.md`) and Claude Code (`CLAUDE.md`); keep the two identical.

## Formatting (read before editing any `.rs`)

The crates are **edition 2024**, `rustfmt.toml` enables **nightly-only** options, and the committed tree is **not** rustfmt-clean. Consequences:

- Any broad format run reformats unrelated, pre-existing code and creates large churn.
- Plain `rustfmt <file>` also **recurses into every submodule** a `mod.rs` declares — formatting one `mod.rs` can rewrite dozens of files.
- Stable rustfmt silently drops the nightly options and reformats differently again.

Rules:

- Do **not** run `cargo fmt`, `cargo fmt --all`, or bare `rustfmt <file>` / `rustfmt --edition 2024 <file>`.
- Prefer matching the surrounding style by hand and not invoking a formatter at all.
- If you must format, run it **only on the exact files you changed**, pinned to nightly, skipping child modules, edition 2024:

  ```
  rustfmt +nightly --unstable-features --skip-children --edition 2024 <only-the-files-you-edited>
  ```

  Then review `git diff` and discard any reformatting outside your own logical change. Never pass a directory, and never format files you didn't edit.
