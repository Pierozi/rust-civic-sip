build:
	clear
	cargo build
	RUST_BACKTRACE=full RUST_BACKTRACE=1 cargo test

run:
	RUST_BACKTRACE=full RUST_BACKTRACE=1 cargo run --example exchange_code

sca:
	cargo fmt -- --check
	cargo clippy -- -Dwarnings
