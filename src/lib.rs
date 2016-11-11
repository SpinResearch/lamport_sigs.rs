//! *lamport* implements one-time hash-based signatures using the Lamport signature scheme.

extern crate crypto;
extern crate rand;

use rand::OsRng;
use rand::Rng;
use crypto::digest::Digest;

/// A one-time signing public key
pub struct PublicKey<T: Digest + Clone> {
    zero_values: Vec<Vec<u8>>,
    one_values:  Vec<Vec<u8>>,
    digest: T
}

/// A one-time signing private key
pub struct PrivateKey<T: Digest + Clone> {
    zero_values: Vec<Vec<u8>>, // For a n bits hash function: (n * n/8 bytes) for zero_values and one_values
    one_values:  Vec<Vec<u8>>,
    digest: T,
    used: bool
}

impl<T: Digest + Clone> PublicKey<T> {
    /// Verifies that the signature of the data is correctly signed with the given key
    pub fn verify_signature(    &self,
                                signature: &Vec<Vec<u8>>,
                                data:&[u8],
                                ) -> bool
    {
        let mut digest = self.digest.clone();
        digest.input(data);
        let mut data_hash = vec![0 as u8; digest.output_bytes()];
        digest.result(data_hash.as_mut_slice());
        digest.reset();

        for i in 0..data_hash.len() {
            let byte = data_hash[i];
            for j in 0..8 {
                let offset = i*8 + j;
                if (byte & (1<<j)) > 0 {
                    digest.input(signature[offset].as_slice());
                    let mut hashed_value = vec![0 as u8; digest.output_bytes()];
                    digest.result(hashed_value.as_mut_slice());
                    digest.reset();
                    if hashed_value != self.one_values[offset] {
                        return false;
                    }
                } else {
                    digest.input(signature[offset].as_slice());
                    let mut hashed_value = vec![0 as u8; digest.output_bytes()];
                    digest.result(hashed_value.as_mut_slice());
                    digest.reset();
                    if hashed_value != self.zero_values[offset] {
                        return false;
                    }
                }
            }
        }

        return true;
    }
}

impl <T: Digest + Clone> PrivateKey<T> {
    /// Generates a new random one-time signing key. This method can panic if OS RNG fails
    pub fn new(digest: T) -> PrivateKey<T> {
        let generate_bit_hash_values = |hasher: &T| -> Vec<Vec<u8>> {
            let mut rng = match OsRng::new() {
                Ok(g) => g,
                Err(e) => panic!("Failed to obtain OS RNG: {}", e)
            };
            let buffer_byte = vec![0 as u8; hasher.output_bytes()];
            let mut buffer  = vec![buffer_byte; hasher.output_bits()];

            for hash in buffer.iter_mut() {
                rng.fill_bytes(hash)
            }

            return buffer;
        };

        let zero_values = generate_bit_hash_values(&digest);
        let one_values  = generate_bit_hash_values(&digest);

        return PrivateKey { zero_values: zero_values,
                            one_values: one_values,
                            digest: digest,
                            used: false }
    }

    /// Returns the public key associated with this private key
    pub fn public_key(&self) -> PublicKey<T> {
        let mut digest = self.digest.clone();

        let hash_values = |x: &Vec<Vec<u8>>, hash_func: &mut Digest | -> Vec<Vec<u8>> {
            let buffer_byte = vec![0 as u8; hash_func.output_bytes()];
            let mut buffer  = vec![buffer_byte; hash_func.output_bits()];

            for i in 0..hash_func.output_bits(){
                hash_func.input(x[i].as_slice());
                hash_func.result(buffer[i].as_mut_slice());
                hash_func.reset();
            }

            return buffer;
        };

        let hashed_zero_values = hash_values(&self.zero_values, &mut digest);
        let hashed_one_values  = hash_values(&self.one_values, &mut digest);

        return PublicKey { zero_values: hashed_zero_values,
                            one_values: hashed_one_values,
                            digest: digest }
    }

    /// Signs the data with the private key and returns the result if successful.
    /// If unsuccesful, an explanation string is returned
    pub fn sign(&mut self, data: &[u8]) ->  Result<Vec<Vec<u8>>, &'static str> {
        if self.used {
            return Err("Attempting to sign more than once.");
        }
        self.digest.input(data);
        let mut data_hash = vec![0 as u8; self.digest.output_bytes()];
        self.digest.result(data_hash.as_mut_slice());
        self.digest.reset();

        let signature_len = data_hash.len() * 8;
        let mut signature = Vec::with_capacity(signature_len);

        for i in 0..data_hash.len() {
            let byte = data_hash[i];
            for j in 0..8 {
                let offset = i*8 + j;
                if (byte & (1<<j)) > 0 {
                    // Bit is 1
                    signature.push(self.one_values[offset].clone());
                } else {
                    // Bit is 0
                    signature.push(self.zero_values[offset].clone());
                }
            }
        }
        self.used = true;
        return Ok(signature);
    }
}

impl <T: Digest + Clone> Drop for PrivateKey<T> {
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

impl<T: Digest + Clone> PartialEq for PrivateKey<T> {
    // ⚠️ This is not a constant-time implementation
    fn eq(&self, other: &PrivateKey<T>) -> bool {
        if self.one_values.len() != other.one_values.len() {
            return false;
        }
        if self.zero_values.len() != other.zero_values.len() {
            return false;
        }

        for i in 0..self.zero_values.len() {
            if self.zero_values[i] != other.zero_values[i] || self.one_values[i] != other.one_values[i] {
                return false
            }
        }
        return true;
    }
}

#[cfg(test)]
use crypto::sha3::Sha3;
#[test]
fn test_public_key_length_256() {
    let pk = PrivateKey::new(Sha3::sha3_256());
    assert!(    pk.public_key().one_values.len() == 256 &&
                pk.public_key().zero_values.len() == 256);
}
#[test]
fn test_public_key_length_512() {
    let pk = PrivateKey::new(Sha3::sha3_512());
    assert!(    pk.public_key().one_values.len() == 512 &&
                pk.public_key().zero_values.len() == 512);
}


#[cfg(test)]
pub mod test;
