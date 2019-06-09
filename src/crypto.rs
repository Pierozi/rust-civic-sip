extern crate frank_jwt as jwt;
use std::str;
use serde_json::Value as JsonValue;
use base64;
use openssl::symm::{decrypt as aes_decrypt, Cipher};
use openssl::{
    pkey::Private,
    ec::EcPoint, ec::EcGroup, ec::EcKey,
    bn::BigNum, bn::BigNumContext,
};
use super::error::CivicError;

/// Convert ECDSA private key from HEX to PEM
///
/// secp256r1 and NIST P-256 are the same @https://www.ietf.org/rfc/rfc5480.txt
///
pub fn get_private_key_pem(private_key: &str) -> Vec<u8> {
    let private_number: BigNum = match BigNum::from_hex_str(&private_key) {
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

pub fn decode(token: &str, pub_key: &str) -> Result<(JsonValue, JsonValue), CivicError> {
    let validate_result = jwt::validate_signature(
        &token,
        &pub_key,
        frank_jwt::Algorithm::ES256
    );

    if validate_result.is_err() {
        return Err(CivicError {
            code: 20100,
            message: String::from("JWT validation signature fail!"),
        });
    }

    if !validate_result.unwrap() {
        return Err(CivicError {
            code: 20101,
            message: String::from("JWT token bad signature"),
        });
    }

    let result = jwt::decode(&token, &pub_key, frank_jwt::Algorithm::ES256);

    if result.is_err() {
        return Err(CivicError {
            code: 20102,
            message: String::from("JWT decode fail!"),
        });
    }

    return Ok(result.unwrap());
}

/// Decrypt data payload of JWT with secret using AES CBC
///
/// ```
/// use civic_sip::crypto::decrypt;
/// use serde_json::json;
/// let data = "2e656bbd384b949db5bbe5b35f6778c5dHupD38ef0XXXrs+3jybUArQSWtWA1ixH/89A6CC5vBN/pbFO2cmCwf2HThkMMbzVWnOG4TSPvRZTYzN7SpIHAlDKTl9Rf/U+oZyxsCsgf5YuJPKcge2H/jB1JsR0O9k";
/// let secret = "d14e0dc05f7333700306881b6f1de3c0";
/// let result = decrypt(data, secret);
/// let expected = json!({
///     "label": "contact.personal.email",
///     "value": "my-private-email",
///     "isValid": true,
///     "isOwner": true,
/// });
/// assert_eq!(expected, result.unwrap());
/// ```
pub fn decrypt(data: &str, secret: &str) -> Result<JsonValue, CivicError> {
    let key = hex::decode(secret).unwrap();
    let cipher = Cipher::aes_128_cbc();
    let iv = hex::decode(&data[0..32]).unwrap();
    let encrypted = base64::decode(&data[32..]).unwrap();

    return match aes_decrypt(
        cipher,
        key.as_slice(),
        Some(iv.as_slice()),
        encrypted.as_slice(),
    ) {
        Ok(out) => Ok(serde_json::from_slice(out.as_slice()).unwrap()),
        Err(error) => Err(CivicError {
            code: 20200,
            message: format!("JWT decrypt error: {:?}", error),
        })
    };
}
