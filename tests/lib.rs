extern crate civic_sip as civic;
use civic::{CivicSip, CivicSipConfig};

#[test]
fn encode() {
    let config: CivicSipConfig = CivicSipConfig {
        app_id: "aaa123",
        app_secret: "879946CE682C0B584B3ACDBC7C169473",
        private_key: "bf5efd7bdde29dc28443614bfee78c3d6ee39c71e55a0437eee02bf7e3647721",
    };
    let sip: CivicSip = CivicSip::new(config);

    assert_eq!(
        sip.exchange_code("AC Token build on frontend CIVIC oAuth"),
        "Foo Bar Baz"
    );
}
