use rsa::{
    pkcs8::EncodePrivateKey, pkcs8::EncodePublicKey, pkcs8::LineEnding, sha2::Sha256, Oaep,
    RsaPrivateKey, RsaPublicKey,
};
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

/// Private and Public RSA keys generation
///
/// Currently, this function can only export to PKCS#8 format.
///
pub fn generate_rsa_keys(output: &PathBuf, bits: usize) -> Result<(), std::io::Error> {
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, bits)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err.to_string()))?; // returns an error when the key can't
                                                                                          // be generated
    private_key.write_pkcs8_pem_file(output, LineEnding::default());

    let public_key = RsaPublicKey::from(&private_key);
    let output_pub: PathBuf = output.with_file_name(format!(
        "{}.pub",
        output.file_stem().unwrap().to_string_lossy()
    ));
    public_key.write_public_key_pem_file(output_pub, LineEnding::default());
    Ok(())
}

pub fn generate_signature_keys()
