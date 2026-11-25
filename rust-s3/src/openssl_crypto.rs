//! SHA-256 and HMAC-SHA256 through OpenSSL, for the `openssl` feature.

use openssl::error::ErrorStack;
use openssl::hash::{Hasher, MessageDigest};
use openssl::pkey::{PKey, Private};
use openssl::sign::Signer;

pub struct Sha256(Hasher);

impl Default for Sha256 {
    fn default() -> Self {
        Sha256(Hasher::new(MessageDigest::sha256()).expect("SHA-256"))
    }
}

impl Sha256 {
    pub fn update<T: AsRef<[u8]>>(&mut self, data: T) {
        self.0.update(data.as_ref()).expect("SHA-256 update");
    }

    pub fn finalize(mut self) -> Vec<u8> {
        self.0.finish().expect("SHA-256 finish").to_vec()
    }
}

pub struct HmacSha256 {
    key: PKey<Private>,
    data: Vec<u8>,
}

pub struct HmacOutput(Vec<u8>);

impl HmacOutput {
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl HmacSha256 {
    pub fn new_from_slice(key: &[u8]) -> Result<Self, ErrorStack> {
        Ok(HmacSha256 {
            key: PKey::hmac(key)?,
            data: Vec::new(),
        })
    }

    pub fn update<T: AsRef<[u8]>>(&mut self, data: T) {
        self.data.extend_from_slice(data.as_ref());
    }

    pub fn finalize(self) -> HmacOutput {
        let mut signer = Signer::new(MessageDigest::sha256(), &self.key).expect("HMAC-SHA256");
        signer.update(&self.data).expect("HMAC-SHA256 update");
        HmacOutput(signer.sign_to_vec().expect("HMAC-SHA256 sign"))
    }
}
