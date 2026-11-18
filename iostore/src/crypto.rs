use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};

/// AES-256 key, as used by Unreal (ECB, no IV).
#[derive(Clone)]
pub struct AesKey {
    bytes: [u8; 32],
    cipher: aes::Aes256,
}

impl AesKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self {
            bytes,
            cipher: aes::Aes256::new(GenericArray::from_slice(&bytes)),
        }
    }
    pub fn bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
    /// Decrypts whole 16-byte blocks in place; a trailing partial block is left alone.
    pub fn decrypt_ecb(&self, data: &mut [u8]) {
        for block in data.chunks_exact_mut(16) {
            self.cipher.decrypt_block(GenericArray::from_mut_slice(block));
        }
    }
    pub fn encrypt_ecb(&self, data: &mut [u8]) {
        for block in data.chunks_exact_mut(16) {
            self.cipher.encrypt_block(GenericArray::from_mut_slice(block));
        }
    }
}

impl std::fmt::Debug for AesKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AesKey(..)")
    }
}

impl PartialEq for AesKey {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}
