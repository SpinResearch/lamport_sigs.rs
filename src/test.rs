use crypto::sha3::Sha3;
use PrivateKey;
use verify_signature;

#[cfg(test)]
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

    assert!(verify_signature(&signature, data, &pub_key));
}

#[test]
fn test_sign_verif_fail() {
    let mut priv_key = PrivateKey::new(Sha3::sha3_256());
    let data = "Hello Word".as_bytes();
    let signature = priv_key.sign(data).unwrap();

    let pub_key = priv_key.public_key();
    let data2 = "Hello".as_bytes();
    assert!(!verify_signature(&signature, data2, &pub_key));
}
