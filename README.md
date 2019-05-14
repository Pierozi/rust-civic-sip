# Rust CIVIC SIP API

![unstable]
[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![BSD-3-Clause licensed][license-image]

Rust Wrapper for the Civic hosted SIP API. (see [docs.civic.com](https://docs.civic.com))

NON OFFICIAL Rust library based on the official Node.js wrapper (see [npm-civic-sip-api](https://github.com/civicteam/npm-civic-sip-api))


## Installation
Add the following to Cargo.toml:

```toml
civic-sip = "0.1"
```

### How to use

```rust
extern civic-sip as civic;
use civic::{CivicSip, CivicSipConfig};

let config: CivicSipConfig = CivicSipConfig {
    app_id: dotenv!("CIVIC_APP_ID"),
    app_secret: dotenv!("CIVIC_APP_SECRET"),
    private_key: dotenv!("CIVIC_PRIVATE_KEY"),
};

let sip: CivicSip = CivicSip::new(config);

return sip.exchange_code("AC Token build on frontend CIVIC oAuth");
```

## License

**civic-sip** is distributed under the terms of either the BSD-3-Clause license.
See [LICENSE](LICENSE) for details.

[unstable]: https://img.shields.io/badge/version-unstable-red.svg
[crate-image]: https://img.shields.io/crates/v/civic-sip.svg
[crate-link]: https://crates.io/crates/civic-sip
[docs-image]: https://docs.rs/civic-sip/badge.svg
[docs-link]: https://docs.rs/civic-sip/
[license-image]: https://img.shields.io/crates/l/civic-sip.svg

