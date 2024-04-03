use rsa::{sha2::Sha256, Oaep, RsaPrivateKey, RsaPublicKey, pkcs8::EncodePrivateKey, pkcs8::LineEnding, pkcs8::EncodePublicKey};
// use crate::utils::LineEnding;
use std::fs::File;
use std::io::{self, Read};
use std::path::PathBuf;

pub fn read_input(file: &Option<PathBuf>) -> Result<String, io::Error> {
    match file {
        Some(filepath) => {
            let mut file = File::open(filepath)?;
            let mut message = String::new();
            file.read_to_string(&mut message)?;

            Ok(message)
        }
        None => {
            let mut message = String::new();
            io::stdin().read_to_string(&mut message)?;

            Ok(message)
        }
    }
}

pub fn create_rsa_keys(output: &PathBuf, bits: usize) -> Result<(), io::Error> {
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let public_key = RsaPublicKey::from(&private_key);

    println!("{:#?}", private_key.write_pkcs8_pem_file(output, LineEnding::default()));
    println!("{:#?}", public_key.write_public_key_pem_file(String::from("hdii"), LineEnding::default()));
    Ok(())
}
