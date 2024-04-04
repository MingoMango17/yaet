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

pub fn create_rsa_keys(output: &PathBuf, bits: usize) -> Result<(), io::Error> {
    let mut rng = rand::thread_rng();
    match RsaPrivateKey::new(&mut rng, bits) {
        Ok(private_key) => {
            private_key.write_pkcs8_pem_file(output, LineEnding::default());
            let public_key = RsaPublicKey::from(&private_key);

            let output_pub:  PathBuf = output.with_file_name(format!("{}.pub",output.file_stem().unwrap().to_string_lossy()));

            public_key
                .write_public_key_pem_file(output_pub, LineEnding::default());
            Ok(())
        }

        Err(error) => Err(error),
    };
    Err(io::Error::new(io::ErrorKind::Other, format!("Unkown error!")))
}
