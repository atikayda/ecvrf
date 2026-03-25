//! CLI wrapper for ECVRF Rust implementation — cross-validation use only.
//!
//! Usage:
//!   cargo run --example cli -- prove <sk_hex> <alpha_hex>
//!   cargo run --example cli -- verify <pk_hex> <pi_hex> <alpha_hex>

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("invalid hex"))
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: cli prove|verify ...");
        std::process::exit(1);
    }

    match args[1].as_str() {
        "prove" => {
            let sk_bytes = hex_decode(&args[2]);
            let alpha = hex_decode(&args[3]);
            let sk: [u8; 32] = sk_bytes.try_into().expect("sk must be 32 bytes");
            let pi = ecvrf::prove(&sk, &alpha).expect("prove failed");
            let beta = ecvrf::proof_to_hash(&pi).expect("proof_to_hash failed");
            println!(
                r#"{{"pi":"{}","beta":"{}"}}"#,
                hex_encode(&pi),
                hex_encode(&beta)
            );
        }
        "verify" => {
            let pk = hex_decode(&args[2]);
            let pi = hex_decode(&args[3]);
            let alpha = hex_decode(&args[4]);
            match ecvrf::verify(&pk, &pi, &alpha) {
                Ok(beta) => println!(r#"{{"valid":true,"beta":"{}"}}"#, hex_encode(&beta)),
                Err(_) => println!(r#"{{"valid":false,"beta":null}}"#),
            }
        }
        cmd => {
            eprintln!("unknown command: {cmd}");
            std::process::exit(1);
        }
    }
}
