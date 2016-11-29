
use ring::digest::{Algorithm, SHA256, SHA512};

use PrivateKey;
use PublicKey;

#[allow(non_upper_case_globals)]
static digest_256: &'static Algorithm = &SHA256;

#[allow(non_upper_case_globals)]
static digest_512: &'static Algorithm = &SHA512;

#[cfg(test)]
#[test]
fn test_public_key_length_256() {
    let pk = PrivateKey::new(digest_256);
    assert!(pk.public_key().one_values.len() == 256 && pk.public_key().zero_values.len() == 256);
}

#[test]
fn test_public_key_length_512() {
    let pk = PrivateKey::new(digest_512);
    assert!(pk.public_key().one_values.len() == 512 && pk.public_key().zero_values.len() == 512);
}

#[test]
fn test_distinctive_successive_keygen() {
    let mut past_buff = PrivateKey::new(digest_512);
    for _ in 0..100 {
        let buffer = PrivateKey::new(digest_512);
        assert!(past_buff != buffer);
        past_buff = buffer;
    }
}

#[test]
fn test_sign_verif() {
    let mut priv_key = PrivateKey::new(digest_512);
    let data = "Hello World".as_bytes();
    let signature = priv_key.sign(data).unwrap();

    let pub_key = priv_key.public_key();

    assert!(pub_key.verify_signature(&signature, data));
}

#[test]
fn test_sign_verif_fail() {
    let mut priv_key = PrivateKey::new(digest_512);
    let data = "Hello Word".as_bytes();
    let signature = priv_key.sign(data).unwrap();

    let pub_key = priv_key.public_key();
    let data2 = "Hello".as_bytes();
    assert!(!pub_key.verify_signature(&signature, data2));
}

#[test]
fn test_serialization() {
    let pub_key = PrivateKey::new(digest_512).public_key();
    let bytes = pub_key.to_bytes();
    let recovered_pub_key = PublicKey::from_vec(bytes, digest_512).unwrap();

    assert_eq!(pub_key.one_values, recovered_pub_key.one_values);
    assert_eq!(pub_key.zero_values, recovered_pub_key.zero_values);
}

#[test]
#[should_panic]
fn test_serialization_panic() {
    let pub_key = PrivateKey::new(digest_512).public_key();
    let mut bytes = pub_key.to_bytes();
    bytes.pop();
    let recovered_pub_key = PublicKey::from_vec(bytes, digest_512).unwrap();

    assert_eq!(pub_key.one_values, recovered_pub_key.one_values);
    assert_eq!(pub_key.zero_values, recovered_pub_key.zero_values);
}
