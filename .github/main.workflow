workflow "Rust CI" {
  on = "pull_request"
  resolves = ["rust-ci"]
}

action "rust-ci" {
  uses = "icepuma/rust-action@master"
  args = "cargo fmt -- --check && cargo clippy -- -Dwarnings && cargo test"
}
