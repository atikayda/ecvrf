use serde::Deserialize;
use std::fs;

#[derive(Deserialize)]
struct VectorFile {
    suite: String,
    #[allow(dead_code)]
    spec: String,
    vectors: Vec<PositiveVector>,
    negative_vectors: Vec<NegativeVector>,
}

#[derive(Deserialize)]
struct PositiveVector {
    label: String,
    pk: String,
    pi: String,
    alpha: String,
    beta: String,
    #[allow(dead_code)]
    #[serde(flatten)]
    extra: serde_json::Value,
}

#[derive(Deserialize)]
struct NegativeVector {
    description: String,
    pk: String,
    pi: String,
    alpha: String,
    expected_verify: bool,
}

fn load_vectors() -> VectorFile {
    let data = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../vectors/vectors.json"))
        .expect("failed to read vectors.json");
    serde_json::from_str(&data).expect("failed to parse vectors.json")
}

#[test]
fn positive_vectors() {
    let file = load_vectors();
    assert_eq!(file.suite, "ECVRF-SECP256K1-SHA256-TAI");

    let mut passed = 0;
    let total = file.vectors.len();

    for (i, vec) in file.vectors.iter().enumerate() {
        let pk_vec = hex::decode(&vec.pk).unwrap();
        let pi_vec = hex::decode(&vec.pi).unwrap();
        let alpha = hex::decode(&vec.alpha).unwrap();
        let expected_beta = hex::decode(&vec.beta).unwrap();

        let pk: [u8; 33] = pk_vec
            .try_into()
            .unwrap_or_else(|v: Vec<u8>| panic!("vector {i}: pk length {}", v.len()));
        let pi: [u8; 81] = pi_vec
            .try_into()
            .unwrap_or_else(|v: Vec<u8>| panic!("vector {i}: pi length {}", v.len()));

        match ecvrf_solana::verify(&pk, &pi, &alpha) {
            Ok(beta) => {
                assert_eq!(
                    beta.to_vec(),
                    expected_beta,
                    "vector {i} '{}': beta mismatch",
                    vec.label
                );
                passed += 1;
            }
            Err(e) => {
                panic!("vector {i} '{}': verify failed: {:?}", vec.label, e);
            }
        }
    }

    eprintln!("{passed}/{total} positive vectors passed");
}

#[test]
fn negative_vectors() {
    let file = load_vectors();
    let mut passed = 0;
    let mut skipped = 0;
    let total = file.negative_vectors.len();

    for (i, vec) in file.negative_vectors.iter().enumerate() {
        assert!(!vec.expected_verify, "negative vector {i} has expected_verify=true");

        let pk_vec = hex::decode(&vec.pk).unwrap();
        let pi_vec = hex::decode(&vec.pi).unwrap();
        let alpha = hex::decode(&vec.alpha).unwrap();

        let pk: [u8; 33] = pk_vec
            .try_into()
            .unwrap_or_else(|v: Vec<u8>| panic!("negative vector {i}: pk length {}", v.len()));

        if pi_vec.len() != 81 {
            // Wrong-length proofs are rejected at the instruction data parsing layer.
            // The library API takes [u8; 81], so these can't reach verify().
            skipped += 1;
            continue;
        }

        let pi: [u8; 81] = pi_vec.try_into().unwrap();

        let result = ecvrf_solana::verify(&pk, &pi, &alpha);
        assert!(
            result.is_err(),
            "negative vector {i} '{}': expected failure but got Ok",
            vec.description
        );
        passed += 1;
    }

    eprintln!("{passed}/{total} negative vectors rejected ({skipped} skipped — wrong pi length)");
}

#[test]
fn proof_to_hash_matches() {
    let file = load_vectors();

    for (i, vec) in file.vectors.iter().enumerate() {
        let pi_vec = hex::decode(&vec.pi).unwrap();
        let expected_beta = hex::decode(&vec.beta).unwrap();
        let pi: [u8; 81] = pi_vec.try_into().unwrap();

        let beta =
            ecvrf_solana::proof_to_hash(&pi).unwrap_or_else(|e| {
                panic!("vector {i} '{}': proof_to_hash failed: {:?}", vec.label, e)
            });

        assert_eq!(
            beta.to_vec(),
            expected_beta,
            "vector {i} '{}': proof_to_hash beta mismatch",
            vec.label
        );
    }
}
