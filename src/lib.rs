extern crate frank_jwt as jwt;
extern crate openssl;
extern crate chrono;
extern crate uuid;

use uuid::Uuid;
use chrono::Utc;
use openssl::pkey::PKey;
use serde::{Serialize, Deserialize};
use serde_json::json;
use hex;

use sha2::Sha256;
use hmac::{Hmac, Mac};
// Create alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

const CIVIC_SIP_API_URL: &'static str = "https://api.civic.com/sip/";
const CIVIC_SIP_API_PUB: &'static str = "049a45998638cfb3c4b211d72030d9ae8329a242db63bfb0076a54e7647370a8ac5708b57af6065805d5a6be72332620932dbb35e8d318fce18e7c980a0eb26aa1";
const CIVIC_JWT_EXPIRATION: i64 = 180; // 3 min

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    company: String,
}

/// CIVIC Application configuration
pub struct CivicSipConfig {
    pub app_id: &'static str,
    pub app_secret: &'static str,
    pub private_key: &'static str,
    pub public_key: &'static str,
}

pub struct CivicSip {
    config: CivicSipConfig
}

impl CivicSip {
    pub fn new(config: CivicSipConfig) -> CivicSip {
        CivicSip { config }
    }

    /// Exchange the authorization code wrapped in a JWT token for the requested user data
    /// # Arguments
    ///
    /// secp256r1 and NIST P-256 are the same @https://www.ietf.org/rfc/rfc5480.txt
    ///
    /// * `jwt_token` - A string containing the authorization code (AC)
    ///
    pub fn exchange_code(&self, jwt_token: &str) -> String {
        let body = json!({
            "authToken": jwt_token,
            "processPayload": true,
        });
        let authorization: String = self.make_authorization_header(body);
        return authorization;
    }

    /// Create the value of Authorization header for the call of CIVIC API
    /// The token format: Civic requestToken.extToken
    /// where requestToken certifies the service path, method
    /// and audience, and extToken certifies the request body.
    ///
    /// The token is signed by the application private_key and secret.
    ///
    fn make_authorization_header(&self, body: serde_json::Value) -> String {
        let mut context: openssl::bn::BigNumContext = openssl::bn::BigNumContext::new().unwrap();
        let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
        let private_number = openssl::bn::BigNum::from_hex_str(&self.config.private_key).unwrap();
        let public_point = openssl::ec::EcPoint::from_bytes(
            &group,
            hex::decode(&self.config.public_key).unwrap().as_slice(),
            &mut context
        ).unwrap();
        let eckey = openssl::ec::EcKey::from_private_components(
            &group,
            &private_number,
            &public_point
        ).unwrap();
        let private_key = eckey.private_key_to_pem().unwrap();

        let payload = json!({
            "jti": Uuid::new_v4(),
            "iat": Utc::now().timestamp_millis() / 1000,
            "exp": (Utc::now().timestamp_millis() + CIVIC_JWT_EXPIRATION) / 1000,
            "iss": self.config.app_id,
            "aud": CIVIC_SIP_API_URL,
            "sub": self.config.app_id,
            "data": {
                "method": "POST",
                "path": "scopeRequest/authCode",
            },
        });
        let header = json!({
            "alg": "ES256",
            "typ": "JWT"
        });

        let jwt_token = match frank_jwt::encode(header, &private_key, &payload, frank_jwt::Algorithm::ES256) {
            Ok(token) => token,
            Err(error) => {
                panic!("There was a problem during JWT ENCODE: {:?}", error);
            },
        };

        // Create CIVIC extension in base64 using hmac with the application secret on the JWT AC
        let mut mac = HmacSha256::new_varkey(self.config.app_secret.as_bytes()).unwrap();
        mac.input(body.to_string().as_bytes());

        return format!("Civic {}.{}",
                       jwt_token,
                       base64::encode(&mac.result().code().to_owned()));
    }

    fn process_payload(_response: &str) -> &'static str {
        panic!("Have to develop that!")
    }
}
