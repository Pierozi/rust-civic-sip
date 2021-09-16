extern crate chrono;
extern crate frank_jwt as jwt;
extern crate openssl;
extern crate reqwest;
extern crate uuid;

pub mod crypto;
pub mod error;

use chrono::Utc;
use error::CivicError;
use hmac::{Hmac, Mac};
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE};
use reqwest::StatusCode;
use serde::Deserialize;
use serde_json::{json, Value as JsonValue};
use sha2::Sha256;
use uuid::Uuid;

// Create alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

const CIVIC_SIP_API_URL: &str = "https://api.civic.com/sip";
const CIVIC_SIP_API_PUB: &str = "049a45998638cfb3c4b211d72030d9ae8329a242db63bfb0076a54e7647370a8ac5708b57af6065805d5a6be72332620932dbb35e8d318fce18e7c980a0eb26aa1";
const CIVIC_JWT_EXPIRATION: i64 = 180; // 3 min

#[derive(Deserialize)]
struct Payload {
    data: String,
}

/// CIVIC Application configuration
pub struct CivicSipConfig {
    pub app_id: &'static str,
    pub app_secret: &'static str,
    pub private_key: &'static str,
    pub proxy: Option<&'static str>,
}

pub enum CivicEnv {
    Prod,
    Dev,
}

pub struct CivicSip {
    config: CivicSipConfig,
    env: &'static str,
}

impl CivicSip {
    pub fn new(config: CivicSipConfig, civic_env: Option<CivicEnv>) -> CivicSip {
        let env = match civic_env {
            None => "prod",
            Some(civic_env_enum) => match civic_env_enum {
                CivicEnv::Prod => "prod",
                CivicEnv::Dev => "dev",
            },
        };
        CivicSip { config, env }
    }

    /// Exchange the authorization code wrapped in a JWT token for the requested user data
    ///
    /// # Arguments
    /// * `jwt_token` - A string containing the authorization code (AC)
    ///
    pub fn exchange_code(&self, jwt_token: &str) -> Result<JsonValue, CivicError> {
        let body: String = json!({
            "authToken": jwt_token,
            "processPayload": true,
        })
        .to_string();
        let auth_header: String = self.make_authorization_header(&body);

        let client = match self.config.proxy {
            Some(proxy) => reqwest::Client::builder()
                .proxy(reqwest::Proxy::all(proxy)?)
                .build()?,
            _ => reqwest::Client::new(),
        };

        let mut response = client
            .post(format!("{}/{}/scopeRequest/authCode", CIVIC_SIP_API_URL, &self.env).as_str())
            .header(AUTHORIZATION, auth_header)
            .header(CONTENT_LENGTH, body.len())
            .header(CONTENT_TYPE, "application/json")
            .header(ACCEPT, "Accept")
            .body(body)
            .send()?;

        match response.status() {
            StatusCode::OK => self.process_payload(response.json()?),

            StatusCode::BAD_REQUEST => Err(CivicError {
                code: 100_400,
                message: String::from("Exchange code failed!"),
            }),
            StatusCode::UNAUTHORIZED => Err(CivicError {
                code: 100_401,
                message: String::from("Exchange code failed!"),
            }),
            StatusCode::FORBIDDEN => Err(CivicError {
                code: 100_403,
                message: String::from("Exchange code failed!"),
            }),
            StatusCode::NOT_FOUND => Err(CivicError {
                code: 100_404,
                message: String::from("Exchange code failed!"),
            }),
            StatusCode::INTERNAL_SERVER_ERROR => Err(CivicError {
                code: 100_500,
                message: String::from("Exchange code failed!"),
            }),

            status => Err(CivicError {
                code: 1,
                message: format!("Backend status code not supported: {:?}", status),
            }),
        }
    }

    /// Create the value of Authorization header for the call of CIVIC API
    /// The token format: Civic requestToken.extToken
    /// where requestToken certifies the service path, method
    /// and audience, and extToken certifies the request body.
    ///
    /// The token is signed by the application private_key and secret.
    ///
    fn make_authorization_header(&self, body: &str) -> String {
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

        let private_key: Vec<u8> = crypto::get_private_key_pem(self.config.private_key);
        let jwt_token =
            match frank_jwt::encode(header, &private_key, &payload, frank_jwt::Algorithm::ES256) {
                Ok(token) => token,
                Err(error) => {
                    panic!("There was a problem during JWT ENCODE: {:?}", error);
                }
            };

        // Create CIVIC extension in base64 using hmac with the application secret on the JWT AC
        let mut mac = HmacSha256::new_varkey(self.config.app_secret.as_bytes()).unwrap();
        mac.input(body.as_bytes());

        return format!(
            "Civic {}.{}",
            jwt_token,
            base64::encode(&mac.result().code().to_owned())
        );
    }

    /// Process CIVIC response
    /// decrypt data using app secret and return result as JsonValue
    fn process_payload(&self, payload: Payload) -> Result<JsonValue, CivicError> {
        match crypto::decode(&payload.data, CIVIC_SIP_API_PUB) {
            Err(error) => Err(error),
            Ok((_, jwt_payload)) => crypto::decrypt(
                jwt_payload["data"].as_str().unwrap(),
                self.config.app_secret,
            ),
        }
    }
}
