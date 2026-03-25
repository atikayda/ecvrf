//! CLI wrapper for ECVRF Solana implementation — cross-validation use only.
//! Verify-only (Solana is a verify-only implementation).
//!
//! Usage:
//!   cargo run --example cli --features no-entrypoint -- verify <pk_hex> <pi_hex> <alpha_hex|--alpha-file path>

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("invalid hex"))
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn read_alpha(args: &[String], idx: usize) -> String {
    if args[idx] == "--alpha-file" {
        std::fs::read_to_string(&args[idx + 1])
            .expect("failed to read alpha file")
            .trim()
            .to_string()
    } else {
        args[idx].clone()
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: cli verify <pk_hex> <pi_hex> <alpha_hex|--alpha-file path>");
        std::process::exit(1);
    }

    match args[1].as_str() {
        "verify" => {
            let pk_bytes = hex_decode(&args[2]);
            let pi_bytes = hex_decode(&args[3]);
            let alpha = hex_decode(&read_alpha(&args, 4));

            let pk: [u8; 33] = pk_bytes
                .try_into()
                .expect("pk must be 33 bytes");
            let pi: [u8; 81] = pi_bytes
                .try_into()
                .expect("pi must be 81 bytes");

            match ecvrf_solana::verify(&pk, &pi, &alpha) {
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
