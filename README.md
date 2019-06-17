# Rust CIVIC SIP API

![badge](https://action-badges.now.sh/Pierozi/rust-civic-sip?action=rust-ci)
[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![BSD-3-Clause licensed][license-image]

Rust Wrapper for the Civic hosted SIP API. (see [docs.civic.com](https://docs.civic.com))

NON OFFICIAL Rust library based on the official Node.js wrapper (see [npm-civic-sip-api](https://github.com/civicteam/npm-civic-sip-api))


## Installation
Add the following to Cargo.toml:

```toml
civic_sip = "0.1"
```

### How to use

```rust
extern crate civic_sip as civic;
use civic::{CivicSip, CivicSipConfig};

let config: CivicSipConfig = CivicSipConfig {
    app_id: dotenv!("CIVIC_APP_ID"),
    app_secret: dotenv!("CIVIC_APP_SECRET"),
    private_key: dotenv!("CIVIC_PRIVATE_KEY"),
    proxy: None,
};

let sip: CivicSip = CivicSip::new(config);
let data: serde_json::Value = sip.exchange_code("AC JWT Token return by CIVIC Frontend oAuth").unwrap();
```

## License

**civic-sip** is distributed under the terms of either the BSD-3-Clause license.
See [LICENSE](LICENSE) for details.

[crate-image]: https://img.shields.io/crates/v/civic_sip.svg
[crate-link]: https://crates.io/crates/civic_sip
[docs-image]: https://docs.rs/civic_sip/badge.svg
[docs-link]: https://docs.rs/civic_sip/
[license-image]: https://img.shields.io/crates/l/civic_sip.svg

