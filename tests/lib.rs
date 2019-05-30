extern crate civic_sip as civic;
use civic::{CivicSip, CivicSipConfig};

#[test]
fn encode() {
    let config: CivicSipConfig = CivicSipConfig {
        app_id: "aaa123",
        app_secret: "879946CE682C0B584B3ACDBC7C169473",
        private_key: "00f3477d335a09e64ca05aa1c38032370eecf574d91289aa99adda183236bfc11b",
        public_key: "043caad45d7d3115550fab08bf86c97dd232804c4d06479259049446a3c06e8a924cd27606dea622197ccef87b1bd065152d9bd11574db3230614b778040b0f8df",
    };
    let sip: CivicSip = CivicSip::new(config);

    assert_eq!(
        sip.exchange_code("AC Token build on frontend CIVIC oAuth"),
        "Foo Bar Baz"
    );
}
