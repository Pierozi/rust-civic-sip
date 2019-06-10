extern crate frank_jwt as jwt;
use std::str;
use serde_json::Value as JsonValue;
use base64;
use openssl::symm::{decrypt as aes_decrypt, Cipher};
use openssl::{
    pkey::Private,
    pkey::Public,
    pkey::PKey,
    ec::EcPoint, ec::EcGroup, ec::EcKey,
    bn::BigNum, bn::BigNumContext,
};
use super::error::CivicError;

/// Convert ECDSA Public key from HEX to PEM
///
/// ```
/// use civic_sip::crypto::get_public_key_from_hex;
/// let public_hex = "04479088bdfbe1516142a8934c081e858521e897b6f96c58966a14cccd361bf07b45dd41b0433b403b55f34ca87c2611ddba3ac6c95459b385429e7a6c5043418e";
/// let expected = "2d2d2d2d2d424547494e205055424c4943204b45592d2d2d2d2d0a4d494942537a434341514d4742797147534d34394167457767666343415145774c4159484b6f5a497a6a30424151496841502f2f2f2f384141414142414141410a4141414141414141414141412f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f4d46734549502f2f2f2f384141414142414141414141414141414141414141412f2f2f2f0a2f2f2f2f2f2f2f2f2f2f2f3842434261786a5859716a715435375072765656326d4961385a523047734d7854735059377a6a772b4a394a6753774d56414d53640a4e67694735775354616d5a3434524f644a7265426e333651424545456178665238754573516b6634764f626c59365241386e634466594574367a4f67394b45350a5264695977705a5034304c692f68702f6d34376e36307038443534574b38347a563273785873374c746b426f4e3739523951496841502f2f2f2f3841414141410a2f2f2f2f2f2f2f2f2f2f2b38357671747078656568504f3579734c3859795652416745424130494142456551694c3337345646685171695454416765685955680a364a65322b5778596c6d6f557a4d3032472f42375264314273454d37514474563830796f6643595233626f3678736c5557624f4651703536624642445159343d0a2d2d2d2d2d454e44205055424c4943204b45592d2d2d2d2d0a";
/// let pub_pem = get_public_key_from_hex(public_hex);
///
/// assert_eq!(expected, hex::encode(pub_pem.as_slice()));
/// ```
pub fn get_public_key_from_hex(public_key: &str) -> Vec<u8> {
    let public_number: BigNum = match BigNum::from_hex_str(&public_key) {
        Ok(bn) => bn,
        Err(error) => panic!("Error during parsing public key in hex, please check your configuration: {:?}", error),
    };
    let group = EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
    let mut ctx = BigNumContext::new().unwrap();
    let point = EcPoint::from_bytes(&group, public_number.to_vec().as_slice(), &mut ctx).unwrap();
    let eckey: EcKey<Public> = EcKey::from_public_key(&group, &point).unwrap();

    let pkey = PKey::from_ec_key(eckey).unwrap();
    return pkey.public_key_to_pem().unwrap();
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
/// let private_hex = "31d707b57b7a0fd512855dd5b2f1f66d5bdfe0f8c03296853d7b3cf33c732a8a";
/// let expected = "2d2d2d2d2d424547494e2045432050524956415445204b45592d2d2d2d2d0a4d49494261414942415151674d646348745874364439555368563356737648326256766634506a414d70614650587338387a787a4b6f716767666f77676663430a415145774c4159484b6f5a497a6a30424151496841502f2f2f2f384141414142414141414141414141414141414141412f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f0a4d46734549502f2f2f2f384141414142414141414141414141414141414141412f2f2f2f2f2f2f2f2f2f2f2f2f2f2f3842434261786a5859716a7154353750720a765656326d4961385a523047734d7854735059377a6a772b4a394a6753774d56414d53644e67694735775354616d5a3434524f644a7265426e333651424545450a6178665238754573516b6634764f626c59365241386e634466594574367a4f67394b45355264695977705a5034304c692f68702f6d34376e36307038443534570a4b38347a563273785873374c746b426f4e3739523951496841502f2f2f2f3841414141412f2f2f2f2f2f2f2f2f2f2b38357671747078656568504f3579734c380a59795652416745426f55514451674145584837444e6778386c3841395568756b706e6c7243474e69425879794d30377274634778527a46483447515a7a516d2b0a796b4a323631425151773341516131347a616a34366567486f494b4547386d4f477a553259413d3d0a2d2d2d2d2d454e442045432050524956415445204b45592d2d2d2d2d0a";
/// let pem = get_private_key_pem(private_hex);
/// assert_eq!(expected, hex::encode(pem.as_slice()));
/// ```
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
    let public_key = get_public_key_from_hex(&pub_key);

    let validate_result = jwt::validate_signature(
        &token,
        &public_key,
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

    let result = jwt::decode(&token, &public_key, frank_jwt::Algorithm::ES256);

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
