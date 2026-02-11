use rsa::{
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding},
    Oaep, RsaPrivateKey, RsaPublicKey,
};
use sha2::Sha256;

const RSA_BITS: usize = 2048;

pub fn generate_keypair() -> Result<(RsaPrivateKey, RsaPublicKey), String> {
    let mut rng = rand::rngs::OsRng;
    let private_key =
        RsaPrivateKey::new(&mut rng, RSA_BITS).map_err(|e| format!("RSA keygen error: {}", e))?;
    let public_key = RsaPublicKey::from(&private_key);
    Ok((private_key, public_key))
}

pub fn public_key_to_pem(key: &RsaPublicKey) -> Result<String, String> {
    key.to_public_key_pem(LineEnding::LF)
        .map_err(|e| format!("PEM encode error: {}", e))
}

pub fn public_key_from_pem(pem: &str) -> Result<RsaPublicKey, String> {
    RsaPublicKey::from_public_key_pem(pem).map_err(|e| format!("PEM decode error: {}", e))
}

pub fn private_key_to_pem(key: &RsaPrivateKey) -> Result<String, String> {
    key.to_pkcs8_pem(LineEnding::LF)
        .map(|pem| pem.to_string())
        .map_err(|e| format!("PEM encode error: {}", e))
}

pub fn private_key_from_pem(pem: &str) -> Result<RsaPrivateKey, String> {
    RsaPrivateKey::from_pkcs8_pem(pem).map_err(|e| format!("PEM decode error: {}", e))
}

pub fn private_key_to_der(key: &RsaPrivateKey) -> Result<Vec<u8>, String> {
    key.to_pkcs8_der()
        .map(|doc| doc.as_bytes().to_vec())
        .map_err(|e| format!("DER encode error: {}", e))
}

pub fn private_key_from_der(der: &[u8]) -> Result<RsaPrivateKey, String> {
    RsaPrivateKey::from_pkcs8_der(der).map_err(|e| format!("DER decode error: {}", e))
}

pub fn rsa_encrypt(data: &[u8], public_key: &RsaPublicKey) -> Result<Vec<u8>, String> {
    let mut rng = rand::rngs::OsRng;
    let padding = Oaep::new::<Sha256>();
    public_key
        .encrypt(&mut rng, padding, data)
        .map_err(|e| format!("RSA encrypt error: {}", e))
}

pub fn rsa_decrypt(data: &[u8], private_key: &RsaPrivateKey) -> Result<Vec<u8>, String> {
    let padding = Oaep::new::<Sha256>();
    private_key
        .decrypt(padding, data)
        .map_err(|e| format!("RSA decrypt error: {}", e))
}
