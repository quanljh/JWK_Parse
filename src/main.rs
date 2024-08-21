use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rsa::{pkcs1::EncodeRsaPublicKey, BigUint};

fn main() {
    // Read command line arguments
    let args: Vec<String> = std::env::args().collect();
    // Check if there is only one argument
    if args.len() < 2 {
        eprintln!("Usage: {} <input_file>", args[0]);
        std::process::exit(1);
    }
    // Get first argument as input file name
    let input_file = &args[1];
    // Read input file
    let input = std::fs::read_to_string(input_file).expect("Failed to read input file");
    // Parse input as json
    let json_value = json::parse(&input).expect("Failed to parse input as json");
    // Get n property value from json
    let n_base64 = json_value["n"].to_string();
    let e_base64 = json_value["e"].to_string();

    let n_bytes = URL_SAFE_NO_PAD
        .decode(n_base64)
        .expect("Failed to decode base64 url");
    let e_bytes = URL_SAFE_NO_PAD
        .decode(e_base64)
        .expect("Failed to decode base64 url");

    let n = BigUint::from_bytes_be(&n_bytes);
    let e = BigUint::from_bytes_be(&e_bytes);

    let rsa_public_key = rsa::RsaPublicKey::new(n, e).expect("Failed to create RSA public key");

    let pem_string = rsa_public_key
        .to_pkcs1_pem(rsa::pkcs8::LineEnding::CRLF)
        .expect("Failed to encode RSA public key");

    // Check if there is a third argument, if so write to file
    if args.len() > 2 {
        let output_file = &args[2];
        std::fs::write(output_file, pem_string).expect("Failed to write to output file");
        return;
    } else {
        println!("{}", pem_string);
    }
}
