use ecvrf::{derive_public_key, proof_to_hash, prove, verify};
use serde::Deserialize;

#[derive(Deserialize)]
struct TestVectors {
    suite: String,
    spec: String,
    vectors: Vec<PositiveVector>,
    negative_vectors: Vec<NegativeVector>,
}

#[derive(Deserialize)]
struct PositiveVector {
    label: String,
    sk: String,
    pk: String,
    alpha: String,
    #[allow(dead_code)]
    alpha_string: Option<String>,
    #[allow(dead_code)]
    h: String,
    #[allow(dead_code)]
    h_ctr: u32,
    #[allow(dead_code)]
    k: String,
    #[allow(dead_code)]
    gamma: String,
    #[allow(dead_code)]
    u: String,
    #[allow(dead_code)]
    v: String,
    #[allow(dead_code)]
    c: String,
    #[allow(dead_code)]
    s: String,
    pi: String,
    beta: String,
}

#[derive(Deserialize)]
struct NegativeVector {
    description: String,
    pk: String,
    alpha: String,
    pi: String,
    #[allow(dead_code)]
    expected_verify: bool,
}

fn load_vectors() -> TestVectors {
    let content =
        std::fs::read_to_string("../vectors/vectors.json").expect("failed to read vectors.json");
    serde_json::from_str(&content).expect("failed to parse vectors.json")
}

#[test]
fn positive_vectors_pk_derivation() {
    let tv = load_vectors();
    assert_eq!(tv.suite, "ECVRF-SECP256K1-SHA256-TAI");
    assert_eq!(tv.spec, "RFC 9381");

    for (i, v) in tv.vectors.iter().enumerate() {
        let sk: [u8; 32] = hex::decode(&v.sk)
            .unwrap()
            .try_into()
            .expect("sk must be 32 bytes");
        let pk = derive_public_key(&sk)
            .unwrap_or_else(|e| panic!("vector {i} '{}': derive_public_key failed: {e}", v.label));

        assert_eq!(
            hex::encode(pk),
            v.pk,
            "vector {i} '{}': pk mismatch",
            v.label
        );
    }
}

#[test]
fn positive_vectors_prove() {
    let tv = load_vectors();

    for (i, v) in tv.vectors.iter().enumerate() {
        let sk: [u8; 32] = hex::decode(&v.sk)
            .unwrap()
            .try_into()
            .expect("sk must be 32 bytes");
        let alpha = hex::decode(&v.alpha).unwrap();

        let pi =
            prove(&sk, &alpha).unwrap_or_else(|e| panic!("vector {i} '{}': prove failed: {e}", v.label));

        assert_eq!(
            hex::encode(pi),
            v.pi,
            "vector {i} '{}': pi mismatch",
            v.label
        );
    }
}

#[test]
fn positive_vectors_verify() {
    let tv = load_vectors();

    for (i, v) in tv.vectors.iter().enumerate() {
        let pk = hex::decode(&v.pk).unwrap();
        let alpha = hex::decode(&v.alpha).unwrap();
        let pi = hex::decode(&v.pi).unwrap();

        let beta = verify(&pk, &pi, &alpha)
            .unwrap_or_else(|e| panic!("vector {i} '{}': verify failed: {e}", v.label));

        assert_eq!(
            hex::encode(beta),
            v.beta,
            "vector {i} '{}': beta mismatch on verify",
            v.label
        );
    }
}

#[test]
fn positive_vectors_proof_to_hash() {
    let tv = load_vectors();

    for (i, v) in tv.vectors.iter().enumerate() {
        let pi = hex::decode(&v.pi).unwrap();

        let beta = proof_to_hash(&pi)
            .unwrap_or_else(|e| panic!("vector {i} '{}': proof_to_hash failed: {e}", v.label));

        assert_eq!(
            hex::encode(beta),
            v.beta,
            "vector {i} '{}': beta mismatch on proof_to_hash",
            v.label
        );
    }
}

#[test]
fn negative_vectors() {
    let tv = load_vectors();

    for (i, v) in tv.negative_vectors.iter().enumerate() {
        let pk = hex::decode(&v.pk).unwrap();
        let alpha = hex::decode(&v.alpha).unwrap();
        let pi = hex::decode(&v.pi).unwrap();

        let result = verify(&pk, &pi, &alpha);
        assert!(
            result.is_err(),
            "negative vector {i} '{}': expected verify to fail but got beta={}",
            v.description,
            result.map(hex::encode).unwrap_or_default()
        );
    }
}

#[test]
fn prove_is_deterministic() {
    let tv = load_vectors();
    let v = &tv.vectors[0];

    let sk: [u8; 32] = hex::decode(&v.sk)
        .unwrap()
        .try_into()
        .expect("sk must be 32 bytes");
    let alpha = hex::decode(&v.alpha).unwrap();

    let pi1 = prove(&sk, &alpha).expect("prove should succeed");
    let pi2 = prove(&sk, &alpha).expect("prove should succeed");
    assert_eq!(pi1, pi2, "prove must be deterministic (RFC 6979)");
}

#[test]
fn prove_rejects_invalid_sk() {
    let group_order =
        hex::decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141").unwrap();

    let zero_sk: [u8; 32] = [0u8; 32];
    assert!(
        prove(&zero_sk, b"test").is_err(),
        "prove must reject zero secret key"
    );

    let n_sk: [u8; 32] = group_order.clone().try_into().unwrap();
    assert!(
        prove(&n_sk, b"test").is_err(),
        "prove must reject sk = group order n"
    );

    let mut n_plus_1 = group_order;
    // n+1: increment the last byte (n ends in 0x41, so 0x42 won't overflow)
    n_plus_1[31] = n_plus_1[31].wrapping_add(1);
    let n1_sk: [u8; 32] = n_plus_1.try_into().unwrap();
    assert!(
        prove(&n1_sk, b"test").is_err(),
        "prove must reject sk = n+1"
    );
}

#[test]
fn prove_then_verify_roundtrip() {
    let tv = load_vectors();

    for (i, v) in tv.vectors.iter().enumerate() {
        let sk: [u8; 32] = hex::decode(&v.sk)
            .unwrap()
            .try_into()
            .expect("sk must be 32 bytes");
        let pk = hex::decode(&v.pk).unwrap();
        let alpha = hex::decode(&v.alpha).unwrap();

        let pi = prove(&sk, &alpha)
            .unwrap_or_else(|e| panic!("vector {i} '{}': prove failed: {e}", v.label));
        let beta = verify(&pk, &pi, &alpha)
            .unwrap_or_else(|e| panic!("vector {i} '{}': verify own proof failed: {e}", v.label));

        let expected_beta = hex::decode(&v.beta).unwrap();
        assert_eq!(
            beta.as_slice(),
            expected_beta.as_slice(),
            "vector {i} '{}': roundtrip beta mismatch",
            v.label
        );
    }
}
