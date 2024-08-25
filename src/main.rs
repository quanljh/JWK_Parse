use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rsa::{
    pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey},
    traits::PublicKeyParts,
    BigUint,
};

const N_PROPERTY: &str = "n";
const E_PROPERTY: &str = "e";

fn main() {
    // Read command line arguments
    let args: Vec<String> = std::env::args().collect();
    // Check if there is only one argument
    check_missing_argument(&args, 2);

    match args[1].as_str() {
        "-jwk" => {
            check_missing_argument(&args, 3);
            jwk_to_rsa(&args);
        }
        "-rsa" => {
            check_missing_argument(&args, 3);
            rsa_to_jwk(&args);
        }
        "-h" | "--help" => {
            print_help();
        }
        "-v" | "--version" => {
            println!("rsa-jwk v0.1.0");
        }
        _ => {
            println!(
                r"Invalid argument.
For more information, try '--help'
        "
            );
        }
    }
}

fn jwk_to_rsa(args: &Vec<String>) {
    // Get first argument as input file name
    let input_file = args[2].as_str();
    // Read input file
    let input = std::fs::read_to_string(input_file).expect("Failed to read input file");
    // Parse input as json
    let json_value = json::parse(&input).expect("Failed to parse input as json");

    // Call has_n_property function to check if n and e properties exists
    // If not, exit the program
    check_json_property(&json_value, N_PROPERTY);
    check_json_property(&json_value, E_PROPERTY);

    // Get n property value from json
    let n_base64 = json_value[N_PROPERTY]
        .as_str()
        .expect("Failed to get n property");
    let e_base64 = json_value[E_PROPERTY]
        .as_str()
        .expect("Failed to get e property");

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
    if args.len() > 3 {
        let output_file = &args[3];
        std::fs::write(output_file, pem_string).expect("Failed to write to output file");
        return;
    } else {
        println!("{}", pem_string);
    }
}

fn rsa_to_jwk(args: &Vec<String>) {
    // Get first argument as input file name
    let input_file = args[2].as_str();
    // Read input file
    let input = std::fs::read_to_string(input_file).expect("Failed to read input file");

    let public_key =
        rsa::RsaPublicKey::from_pkcs1_pem(&input).expect("Failed to parse input as RSA public key");

    let n_bytes = public_key.n().to_bytes_be();
    let e_bytes = public_key.e().to_bytes_be();

    let n = URL_SAFE_NO_PAD.encode(n_bytes);

    let e = URL_SAFE_NO_PAD.encode(e_bytes);

    let jwk = json::object! {
        "e": e,
        "kid": "RSA_JWK_KEY",
        "kty": "RSA",
        "n": n,
        "use": "sig"
    };

    let jwk_string = jwk.pretty(4);

    // Check if there is a third argument, if so write to file
    if args.len() > 3 {
        let output_file = &args[3];
        std::fs::write(output_file, jwk_string).expect("Failed to write to output file");
        return;
    } else {
        println!("{}", jwk_string);
    }
}

fn check_missing_argument(args: &Vec<String>, length: usize) {
    if args.len() < length {
        println!(
            r"Required argument missing.
For more information, try '--help'
        "
        );
        std::process::exit(1);
    }
}

fn print_help() {
    println!(
        r"A simple program to convert between RSA public key and JSON Web Key (JWK) format for signing

Usage: rsa-jwk [OPTIONS] <input_file> [output_file](Optional)

Options:
    -jwk <input_file> [output_file] Convert JWK for signing to RSA public key
    -rsa <input_file> [output_file] Convert RSA public key to JWK for signing
    -h, --help                      Print this help message
    -v, --version                   Print version information
"
    );
    std::process::exit(1);
}

fn check_json_property(json_value: &json::JsonValue, key: &str) {
    if !json_value.has_key(key) {
        eprintln!("{} property not found in input json", key);
        std::process::exit(1);
    }
}
