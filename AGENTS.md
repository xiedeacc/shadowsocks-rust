# Project Rules

- Do not run repository-wide formatters such as `cargo fmt --all` for routine changes. Format only the files touched by the current task, for example `rustfmt --edition 2024 <changed-rust-files>`, and avoid unrelated formatting churn.
