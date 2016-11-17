use crypto::sha3::Sha3;
use PrivateKey;

#[cfg(test)]

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

#[test]
fn test_distinctive_successive_keygen() {
    let mut past_buff = PrivateKey::new(Sha3::sha3_256());
    for _ in 0..100 {
        let buffer = PrivateKey::new(Sha3::sha3_256());
        assert!(past_buff != buffer);
        past_buff = buffer;
    }
}

#[test]
fn test_sign_verif() {
    let mut priv_key = PrivateKey::new(Sha3::sha3_256());
    let data = "Hello World".as_bytes();
    let signature = priv_key.sign(data).unwrap();

    let pub_key = priv_key.public_key();

    assert!(pub_key.verify_signature(&signature, data));
}

#[test]
fn test_sign_verif_fail() {
    let mut priv_key = PrivateKey::new(Sha3::sha3_256());
    let data = "Hello Word".as_bytes();
    let signature = priv_key.sign(data).unwrap();

    let pub_key = priv_key.public_key();
    let data2 = "Hello".as_bytes();
    assert!(!pub_key.verify_signature(&signature, data2));
}
