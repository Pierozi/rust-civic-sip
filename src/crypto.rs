extern crate frank_jwt as jwt;
use super::error::CivicError;
use base64;
use openssl::symm::{decrypt as aes_decrypt, Cipher};
use openssl::{
    bn::BigNum, bn::BigNumContext, ec::EcGroup, ec::EcKey, ec::EcPoint, pkey::PKey, pkey::Private,
    pkey::Public,
};
use serde_json::Value as JsonValue;
use std::str;

/// Convert ECDSA Public key from HEX to PEM
///
/// ```
/// use civic_sip::crypto::get_public_key_from_hex;
/// let public_hex = "043878449419fc8ed0327bb41195b7d68bcdc5c1a7cc9967baef2eaa4174ed02e26f482776810f444b2d2ede46b6539623563b1a87522f6d53ba252c3c1ebdf19f";
/// let expected = "2d2d2d2d2d424547494e205055424c4943204b45592d2d2d2d2d0a4d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a304441516344516741454f4868456c426e386a744179653751526c626657693833467761664d0a6d576536377936715158547441754a76534364326751394553793075336b61325535596a566a73616831497662564f364a537738487233786e773d3d0a2d2d2d2d2d454e44205055424c4943204b45592d2d2d2d2d0a";
/// let pub_pem = get_public_key_from_hex(public_hex);
///
/// assert_eq!(expected, hex::encode(pub_pem.as_slice()));
/// ```
pub fn get_public_key_from_hex(public_key: &str) -> Vec<u8> {
    let public_number: BigNum = match BigNum::from_hex_str(&public_key) {
        Ok(bn) => bn,
        Err(error) => panic!(
            "Error during parsing public key in hex, please check your configuration: {:?}",
            error
        ),
    };
    let group = EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
    let mut ctx = BigNumContext::new().unwrap();
    let point = EcPoint::from_bytes(&group, public_number.to_vec().as_slice(), &mut ctx).unwrap();
    let eckey: EcKey<Public> = EcKey::from_public_key(&group, &point).unwrap();
    let pkey = PKey::from_ec_key(eckey).unwrap();

    pkey.public_key_to_pem().unwrap()
}

/// Convert ECDSA private key from HEX to PEM
///
/// secp256r1 and NIST P-256 are the same @https://www.ietf.org/rfc/rfc5480.txt
///
/// ```bash
/// openssl ecparam -genkey -name secp256r1 -out k.pem
/// # private hex
/// # 31d707b57b7a0fd512855dd5b2f1f66d5bdfe0f8c03296853d7b3cf33c732a8a
/// ```
///
/// ```
/// use civic_sip::crypto::get_private_key_pem;
/// let private_hex = "009003de3067d418591d6b782a14595ab45b071a505b109c7d4189d864f62e5cec";
/// let expected = "2d2d2d2d2d424547494e2045432050524956415445204b45592d2d2d2d2d0a4d48634341514545494a4144336a426e3142685a485774344b68525a5772526242787051577843636655474a324754324c6c7a736f416f4743437147534d34390a417745486f555144516741454f4868456c426e386a744179653751526c626657693833467761664d6d576536377936715158547441754a7653436432675139450a53793075336b61325535596a566a73616831497662564f364a537738487233786e773d3d0a2d2d2d2d2d454e442045432050524956415445204b45592d2d2d2d2d0a";
/// let pem = get_private_key_pem(private_hex);
/// assert_eq!(expected, hex::encode(pem.as_slice()));
/// ```
pub fn get_private_key_pem(private_key: &str) -> Vec<u8> {
    let private_number: BigNum = match BigNum::from_hex_str(&private_key) {
        Ok(bn) => bn,
        Err(error) => panic!(
            "Error during parsing private key in hex, please check your configuration: {:?}",
            error
        ),
    };

    let group: EcGroup = EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
    let context: BigNumContext = BigNumContext::new().unwrap();

    let mut public_point = EcPoint::new(&group).unwrap();
    match public_point.mul_generator(
        &group,
        &private_number,
        &context
    ) {
        Ok(_) => (),
        Err(error) => panic!("Error during public key generation from private key. key must be ECDSA nist256 format: {:?}", error),
    }

    let eckey: EcKey<Private> =
        match EcKey::from_private_components(&group, &private_number, &public_point) {
            Ok(key) => key,
            Err(error) => panic!("Error pub/pvt key construction: {:?}", error),
        };

    match eckey.private_key_to_pem() {
        Ok(pem) => pem,
        Err(error) => panic!("Error during PEM conversion: {:?}", error),
    }
}

pub fn decode(token: &str, pub_key: &str) -> Result<(JsonValue, JsonValue), CivicError> {
    let public_key = get_public_key_from_hex(&pub_key);
    let validate_result = jwt::validate_signature(&token, &public_key, frank_jwt::Algorithm::ES256);

    if validate_result.is_err() {
        return Err(CivicError {
            code: 200_100,
            message: String::from("JWT validation signature fail!"),
        });
    }

    if !validate_result.unwrap() {
        return Err(CivicError {
            code: 200_101,
            message: String::from("JWT token bad signature"),
        });
    }

    let result = jwt::decode(
        &token,
        &public_key,
        frank_jwt::Algorithm::ES256,
        &frank_jwt::ValidationOptions::default(),
    );

    if result.is_err() {
        return Err(CivicError {
            code: 200_102,
            message: String::from("JWT decode fail!"),
        });
    }

    Ok(result.unwrap())
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

    match aes_decrypt(
        cipher,
        key.as_slice(),
        Some(iv.as_slice()),
        encrypted.as_slice(),
    ) {
        Ok(out) => Ok(serde_json::from_slice(out.as_slice()).unwrap()),
        Err(error) => Err(CivicError {
            code: 200_200,
            message: format!("JWT decrypt error: {:?}", error),
        }),
    }
}
