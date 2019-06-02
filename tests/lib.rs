extern crate civic_sip as civic;
use civic::{CivicSip, CivicSipConfig};

#[test]
fn encode() {
    let config: CivicSipConfig = CivicSipConfig {
        app_id: "aaa123",
        app_secret: "879946CE682C0B584B3ACDBC7C169473",
        private_key: "00f3477d335a09e64ca05aa1c38032370eecf574d91289aa99adda183236bfc11b",
    };
    let sip: CivicSip = CivicSip::new(config);

    let code = sip.exchange_code("AC Token build on frontend CIVIC oAuth");

    /*assert_eq!(
        sip.exchange_code("AC Token build on frontend CIVIC oAuth"),
        "Foo Bar Baz"
    );*/
}
