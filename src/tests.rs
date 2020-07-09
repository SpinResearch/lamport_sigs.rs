use ring::digest::{Algorithm, SHA256, SHA512};

use crate::PrivateKey;
use crate::PublicKey;

static DIGEST_256: &Algorithm = &SHA256;
static DIGEST_512: &Algorithm = &SHA512;

#[cfg(test)]
#[test]
fn test_public_key_length_256() {
    let pk = PrivateKey::new(DIGEST_256);
    assert!(pk.public_key().one_values.len() == 256 && pk.public_key().zero_values.len() == 256);
}

#[test]
fn test_public_key_length_512() {
    let pk = PrivateKey::new(DIGEST_512);
    assert!(pk.public_key().one_values.len() == 512 && pk.public_key().zero_values.len() == 512);
}

#[test]
fn test_distinctive_successive_keygen() {
    let mut past_buff = PrivateKey::new(DIGEST_512);
    for _ in 0..100 {
        let buffer = PrivateKey::new(DIGEST_512);
        assert!(past_buff != buffer);
        past_buff = buffer;
    }
}

#[test]
fn test_sign_verif() {
    let mut priv_key = PrivateKey::new(DIGEST_512);
    let data = b"Hello World";
    let signature = priv_key.sign(data).unwrap();

    let pub_key = priv_key.public_key();

    assert!(pub_key.verify_signature(&signature, data));
}

#[test]
fn test_sign_verif_sig_wrong_size() {
    let mut priv_key = PrivateKey::new(DIGEST_512);
    let data = b"Hello World";
    let mut too_short = priv_key.sign(data).unwrap();
    let extra = too_short.pop();

    let pub_key = priv_key.public_key();

    assert!(!pub_key.verify_signature(&too_short, data));

    let mut priv_key = PrivateKey::new(DIGEST_512);
    let data = b"Hello World";
    let mut too_long = priv_key.sign(data).unwrap();
    too_long.extend(extra);

    assert!(!pub_key.verify_signature(&too_long, data));
}

#[test]
fn test_sign_verif_fail() {
    let mut priv_key = PrivateKey::new(DIGEST_512);
    let data = b"Hello Word";
    let signature = priv_key.sign(data).unwrap();

    let pub_key = priv_key.public_key();
    let data2 = b"Hello";
    assert!(!pub_key.verify_signature(&signature, data2));
}

#[test]
fn test_serialization() {
    let pub_key = PrivateKey::new(DIGEST_512).public_key();
    let bytes = pub_key.to_bytes();
    let recovered_pub_key = PublicKey::from_vec(bytes, DIGEST_512).unwrap();

    assert_eq!(pub_key.one_values, recovered_pub_key.one_values);
    assert_eq!(pub_key.zero_values, recovered_pub_key.zero_values);
}

#[test]
fn test_serialization_wrong_size_key() {
    let pub_key = PrivateKey::new(DIGEST_512).public_key();
    let mut too_short = pub_key.to_bytes();
    let extra = too_short.pop();
    assert!(PublicKey::from_vec(too_short, DIGEST_512).is_none());

    let pub_key = PrivateKey::new(DIGEST_512).public_key();
    let mut too_long = pub_key.to_bytes();
    too_long.extend(extra);
    assert!(PublicKey::from_vec(too_long, DIGEST_512).is_none());
}

#[test]
#[should_panic]
fn test_serialization_panic() {
    let pub_key = PrivateKey::new(DIGEST_512).public_key();
    let mut bytes = pub_key.to_bytes();
    bytes.pop();
    let recovered_pub_key = PublicKey::from_vec(bytes, DIGEST_512).unwrap();

    assert_eq!(pub_key.one_values, recovered_pub_key.one_values);
    assert_eq!(pub_key.zero_values, recovered_pub_key.zero_values);
}

#[test]
fn test_private_key_equality() {
    let mut pub_key = PrivateKey::new(DIGEST_512);
    let pub_key_2 = pub_key.clone();

    assert!(pub_key == pub_key_2);

    pub_key.one_values.push(vec![0]);

    assert!(pub_key != pub_key_2);

    let mut pub_key = PrivateKey::new(DIGEST_512);
    let pub_key_2 = pub_key.clone();
    pub_key.one_values.pop();

    assert!(pub_key != pub_key_2);

    let mut pub_key = PrivateKey::new(DIGEST_512);
    let pub_key_2 = pub_key.clone();
    pub_key.algorithm = DIGEST_256;

    assert!(pub_key != pub_key_2);
}
