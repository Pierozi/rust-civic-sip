extern crate frank_jwt as jwt;
extern crate openssl;
extern crate chrono;
extern crate uuid;
extern crate reqwest;

mod error;

use uuid::Uuid;
use chrono::Utc;
use serde::{Serialize, Deserialize};
use serde_json::json;
use reqwest::header::{CONTENT_TYPE, CONTENT_LENGTH, ACCEPT, AUTHORIZATION};
use reqwest::StatusCode;
use error::CivicError;

use openssl::{
    pkey::Private,
    ec::EcPoint, ec::EcGroup, ec::EcKey,
    bn::BigNum, bn::BigNumContext,
};

use sha2::Sha256;
use hmac::{Hmac, Mac};

// Create alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

const CIVIC_SIP_API_URL: &'static str = "https://api.civic.com/sip";
const CIVIC_SIP_API_PUB: &'static str = "049a45998638cfb3c4b211d72030d9ae8329a242db63bfb0076a54e7647370a8ac5708b57af6065805d5a6be72332620932dbb35e8d318fce18e7c980a0eb26aa1";
const CIVIC_JWT_EXPIRATION: i64 = 180; // 3 min

#[derive(Serialize, Deserialize)]
struct Claims {
    sub: String,
    company: String,
}

#[derive(Deserialize)]
struct Payload {
    data: String,
}

/// CIVIC Application configuration
pub struct CivicSipConfig {
    pub app_id: &'static str,
    pub app_secret: &'static str,
    pub private_key: &'static str,
    pub env: &'static str,
    pub proxy: Option<&'static str>,
}

pub struct CivicSip {
    config: CivicSipConfig
}

impl CivicSip {
    pub fn new(config: CivicSipConfig) -> CivicSip {
        CivicSip { config }
    }

    /// Exchange the authorization code wrapped in a JWT token for the requested user data
    ///
    /// # Arguments
    /// * `jwt_token` - A string containing the authorization code (AC)
    ///
    pub fn exchange_code(&self, jwt_token: &str) -> Result<&'static str, CivicError> {
        let body: String = json!({
            "authToken": jwt_token,
            "processPayload": true,
        }).to_string();
        let auth_header: String = self.make_authorization_header(&body);

        let client = match self.config.proxy {
            Some(proxy) => reqwest::Client::builder()
                .proxy(reqwest::Proxy::all(proxy)?)
                .build()?,
            _ => reqwest::Client::new(),
        };

        let mut response = client.post(
            format!("{}/{}/scopeRequest/authCode", CIVIC_SIP_API_URL, &self.config.env).as_str()
            )
            .header(AUTHORIZATION, auth_header)
            .header(CONTENT_LENGTH, body.len())
            .header(CONTENT_TYPE, "application/json")
            .header(ACCEPT, "Accept")
            .body(body)
            .send()?;

        return match response.status() {
            StatusCode::OK => {
                return self.process_payload(response.json()?);
            },
            StatusCode::BAD_REQUEST => Err(CivicError {
                code: 100400,
                message: String::from("Exchange code failed!"),
            }),
            StatusCode::UNAUTHORIZED => Err(CivicError {
                code: 100401,
                message: String::from("Exchange code failed!"),
            }),
            StatusCode::FORBIDDEN => Err(CivicError {
                code: 100403,
                message: String::from("Exchange code failed!"),
            }),
            StatusCode::NOT_FOUND => Err(CivicError {
                code: 100404,
                message: String::from("Exchange code failed!"),
            }),
            StatusCode::INTERNAL_SERVER_ERROR => Err(CivicError {
                code: 100500,
                message: String::from("Exchange code failed!"),
            }),
            status => Err(CivicError {
                code: 1,
                message: format!("Backend status code not supported: {:?}", status),
            }),
        };
    }

    /// Convert ECDSA private key from HEX to PEM
    ///
    /// secp256r1 and NIST P-256 are the same @https://www.ietf.org/rfc/rfc5480.txt
    ///
    fn get_private_key_pem(&self) -> Vec<u8> {
        let private_number: BigNum = match BigNum::from_hex_str(&self.config.private_key) {
            Ok(bn) => bn,
            Err(error) => panic!("Error during parsing private key in hex, please check your configuration: {:?}", error),
        };

        let group: EcGroup = EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
        let mut context: BigNumContext = BigNumContext::new().unwrap();

        let mut public_point = EcPoint::new(&group).unwrap();
        match public_point.mul_generator(
            &group,
            &private_number,
            &mut context
        ) {
            Ok(_) => (),
            Err(error) => panic!("Error during public key generation from private key. key must be ECDSA nist256 format: {:?}", error),
        }

        let eckey: EcKey<Private> = match EcKey::from_private_components(
            &group,
            &private_number,
            &public_point
        ) {
            Ok(key) => key,
            Err(error) => panic!("Error pub/pvt key construction: {:?}", error),
        };

        return match eckey.private_key_to_pem() {
            Ok(pem) => pem,
            Err(error) => panic!("Error during PEM conversion: {:?}", error),
        };
    }

    /// Create the value of Authorization header for the call of CIVIC API
    /// The token format: Civic requestToken.extToken
    /// where requestToken certifies the service path, method
    /// and audience, and extToken certifies the request body.
    ///
    /// The token is signed by the application private_key and secret.
    ///
    fn make_authorization_header(&self, body: &String) -> String {
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

        let private_key: Vec<u8> = self.get_private_key_pem();
        let jwt_token = match frank_jwt::encode(
            header,
            &private_key,
            &payload,
            frank_jwt::Algorithm::ES256
        ) {
            Ok(token) => token,
            Err(error) => {
                panic!("There was a problem during JWT ENCODE: {:?}", error);
            },
        };

        // Create CIVIC extension in base64 using hmac with the application secret on the JWT AC
        let mut mac = HmacSha256::new_varkey(self.config.app_secret.as_bytes()).unwrap();
        mac.input(body.as_bytes());

        return format!("Civic {}.{}",
                       jwt_token,
                       base64::encode(&mac.result().code().to_owned()));
    }

    fn process_payload(&self, payload: Payload) -> Result<&'static str, CivicError> {
        return Err(CivicError {
            code: 1,
            message: format!("DEBUG: {:?}", payload.data),
        })
    }
}
