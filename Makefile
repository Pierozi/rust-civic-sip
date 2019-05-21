build:
	clear
	cargo build
	cargo test

run:
	RUST_BACKTRACE=full RUST_BACKTRACE=1 cargo run
