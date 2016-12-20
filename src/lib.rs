//! *lamport* implements one-time hash-based signatures using the Lamport signature scheme.

#![deny(
    missing_docs,
    missing_debug_implementations, missing_copy_implementations,
    trivial_casts, trivial_numeric_casts,
    unsafe_code, unstable_features,
    unused_import_braces, unused_qualifications
)]

extern crate ring;
extern crate rand;

use std::hash::{Hash, Hasher};
use rand::OsRng;
use rand::Rng;
use ring::digest::{Algorithm, Context};

/// A type alias defining a Lamport signature
pub type LamportSignatureData = Vec<Vec<u8>>;

/// A one-time signing public key
#[derive(Clone, Debug)]
pub struct PublicKey {
    zero_values: Vec<Vec<u8>>,
    one_values: Vec<Vec<u8>>,
    algorithm: &'static Algorithm,
}

impl PartialEq for PublicKey {
    #[allow(trivial_casts)]
    fn eq(&self, other: &Self) -> bool {
       self.zero_values == other.zero_values &&
       self.one_values == other.one_values &&
       self.algorithm as *const Algorithm as usize == other.algorithm as *const Algorithm as usize
   }
}

impl Hash for PublicKey {
    #[allow(trivial_casts)]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.zero_values.hash(state);
        self.one_values.hash(state);
        (self.algorithm as *const Algorithm as usize).hash(state);
    }
}

impl Eq for PublicKey {}

/// A one-time signing private key
#[derive(Clone, Debug)]
pub struct PrivateKey {
    // For a n bits hash function: (n * n/8 bytes) for zero_values and one_values
    zero_values: Vec<Vec<u8>>,
    one_values: Vec<Vec<u8>>,
    algorithm: &'static Algorithm,
    used: bool,
}

impl From<PublicKey> for Vec<u8> {
    fn from(original: PublicKey) -> Vec<u8> {
        original.to_bytes()
    }
}

impl PublicKey {
    /// Intializes a public key with a byte vector.
    /// Returns `None` if it couldn't parse the provided data
    pub fn from_vec(vec: Vec<u8>, algorithm: &'static Algorithm) -> Option<PublicKey> {
        let size = vec.len();
        let hash_output_size = algorithm.output_len;

        let mut zero_values_merged = vec;
        let one_values_merged = zero_values_merged.split_off(size / 2);

        let mut zero_values = Vec::new();
        for i in (0..zero_values_merged.len()).filter(|x| x % hash_output_size == 0) {
            // indexes for heads
            let mut sub_vec = Vec::new();
            for j in 0..hash_output_size {
                sub_vec.push(zero_values_merged[i + j]);
            }

            zero_values.push(sub_vec);
        }

        let mut one_values = Vec::new();
        for i in (0..one_values_merged.len()).filter(|x| x % hash_output_size == 0) {
            // indexes for heads
            let mut sub_vec = Vec::new();
            for j in 0..hash_output_size {
                sub_vec.push(one_values_merged[i + j]);
            }

            one_values.push(sub_vec);
        }

        Some(PublicKey {
            zero_values: zero_values,
            one_values: one_values,
            algorithm: algorithm,
        })
    }

    /// Serializes a public key into a byte vector
    pub fn to_bytes(&self) -> Vec<u8> {
        self.zero_values.iter().chain(self.one_values.iter()).fold(Vec::new(), |mut acc, i| {
            acc.append(&mut i.clone());
            acc
        })
    }

    /// Verifies that the signature of the data is correctly signed with the given key
    pub fn verify_signature(&self, signature: &LamportSignatureData, data: &[u8]) -> bool {
        let mut context = Context::new(self.algorithm);
        context.update(data);
        let result = context.finish();
        let data_hash = result.as_ref();

        for (i, byte) in data_hash.iter().enumerate() {
            for j in 0..8 {
                let offset = i * 8 + j;
                if (byte & (1 << j)) > 0 {
                    let mut context = Context::new(self.algorithm);
                    context.update(signature[offset].as_slice());
                    let hashed_value = Vec::from(context.finish().as_ref());

                    if hashed_value != self.one_values[offset] {
                        return false;
                    }
                } else {
                    let mut context = Context::new(self.algorithm);
                    context.update(signature[offset].as_slice());
                    let hashed_value = Vec::from(context.finish().as_ref());

                    if hashed_value != self.zero_values[offset] {
                        return false;
                    }
                }
            }
        }

        true
    }
}

impl PrivateKey {
    /// Generates a new random one-time signing key. This method can panic if OS RNG fails
    pub fn new(algorithm: &'static Algorithm) -> PrivateKey {
        let generate_bit_hash_values = || -> Vec<Vec<u8>> {
            let mut rng = match OsRng::new() {
                Ok(g) => g,
                Err(e) => panic!("Failed to obtain OS RNG: {}", e),
            };
            let buffer_byte = vec![0u8; algorithm.output_len];
            let mut buffer = vec![buffer_byte; algorithm.output_len * 8];

            for hash in &mut buffer {
                rng.fill_bytes(hash)
            }

            buffer
        };

        let zero_values = generate_bit_hash_values();
        let one_values  = generate_bit_hash_values();

        PrivateKey {
            zero_values: zero_values,
            one_values: one_values,
            algorithm: algorithm,
            used: false,
        }
    }

    /// Returns the public key associated with this private key
    pub fn public_key(&self) -> PublicKey {
        let hash_values = |x: &Vec<Vec<u8>>| -> Vec<Vec<u8>> {
            let buffer_byte = vec![0u8; self.algorithm.output_len];
            let mut buffer  = vec![buffer_byte; self.algorithm.output_len * 8];

            for i in 0 .. self.algorithm.output_len * 8 {
                let mut context = Context::new(self.algorithm);
                context.update(x[i].as_slice());
                buffer[i] = Vec::from(context.finish().as_ref());
            }

            buffer
        };

        let hashed_zero_values = hash_values(&self.zero_values);
        let hashed_one_values  = hash_values(&self.one_values);

        PublicKey {
            zero_values: hashed_zero_values,
            one_values: hashed_one_values,
            algorithm: self.algorithm,
        }
    }

    /// Signs the data with the private key and returns the result if successful.
    /// If unsuccesful, an explanation string is returned
    pub fn sign(&mut self, data: &[u8]) -> Result<LamportSignatureData, &'static str> {
        if self.used {
            return Err("Attempting to sign more than once.");
        }

        let mut context = Context::new(self.algorithm);
        context.update(data);
        let result    = context.finish();
        let data_hash = result.as_ref();

        let signature_len = data_hash.len() * 8;
        let mut signature = Vec::with_capacity(signature_len);

        for (i, byte) in data_hash.iter().enumerate() {
            for j in 0..8 {
                let offset = i * 8 + j;
                if (byte & (1 << j)) > 0 {
                    // Bit is 1
                    signature.push(self.one_values[offset].clone());
                } else {
                    // Bit is 0
                    signature.push(self.zero_values[offset].clone());
                }
            }
        }
        self.used = true;
        Ok(signature)
    }
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        let zeroize_vector = |vector: &mut Vec<Vec<u8>>| {
            for v2 in vector.iter_mut() {
                for byte in v2.iter_mut() {
                    *byte = 0;
                }
            }
        };

        zeroize_vector(&mut self.zero_values);
        zeroize_vector(&mut self.one_values);
    }
}

impl PartialEq for PrivateKey {
    // ⚠️ This is not a constant-time implementation
    fn eq(&self, other: &PrivateKey) -> bool {
        if self.one_values.len() != other.one_values.len() {
            return false;
        }
        if self.zero_values.len() != other.zero_values.len() {
            return false;
        }

        for i in 0..self.zero_values.len() {
            if self.zero_values[i] != other.zero_values[i] ||
               self.one_values[i] != other.one_values[i] {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
pub mod tests;
