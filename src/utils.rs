use pkcs8::DecodePublicKey;
use rsa::sha2::{Digest, Sha256};
use rsa::signature::{Keypair, RandomizedSigner, SignatureEncoding, Verifier};
use rsa::{
    pkcs8::DecodePrivateKey,
    pkcs8::EncodePrivateKey,
    pkcs8::EncodePublicKey,
    pkcs8::LineEnding,
    pss::{BlindedSigningKey, VerifyingKey},
    Oaep, RsaPrivateKey, RsaPublicKey,
};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, prelude::*, Read, Write};
use std::path::PathBuf;

fn print_raw_data(data: &[u8]) -> io::Result<()> {
    io::stdout().lock().write_all(data)?;
    Ok(())
}

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

/// Appends a string `suffix` to a path `path` and returns the resulting `PathBuf`.
///
/// # Arguments
///
/// * `path` - A value that can be converted into an `OsString`, representing the base path.
/// * `suffix` - A reference to a value that can be converted into an `OsStr`, representing the string to append.
///
/// # Returns
///
/// A `PathBuf` containing the concatenated path.
///
/// # Example
///
/// ```
/// use std::path::PathBuf;
///
/// let base_path = "/path/to/base".to_owned();
/// let appended_path = utils::append_to_path(base_path, "file.txt");
/// assert_eq!(appended_path.to_string_lossy(), "/path/to/base/file.txt");
/// ```
///
pub fn append_to_path(path: impl Into<OsString>, suffix: impl AsRef<OsStr>) -> PathBuf {
    let mut path = path.into();
    path.push(suffix);
    path.into()
}

/// Generate a Private RSA key
///
/// This function generates a private RSA key and saves it to the specified output file.
///
/// # Arguments
///
/// * output - The path to the file where the private key will be saved.
/// * bits - The number of bits for the RSA key.
///
/// # Errors
///
/// Returns an Err variant if there is an error generating the private key or if there
/// is an error writing the key to the output file. The error may occur if the key cannot
/// be generated or if there is an issue with file I/O operations.
///
/// # Examples
///
/// ```
/// use std::path::PathBuf;
/// let output_path = PathBuf::from("/path/to/private_key.pem");
/// let bits = 2048; // Example key size
/// if let Err(err) = generate_private_key(&output_path, bits) {
///     eprintln!("Error generating private key: {}", err);
/// }
///  ```
///
pub fn generate_private_key(output: &PathBuf, bits: usize) -> Result<(), io::Error> {
    let mut rng = rand::rngs::OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, bits)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err.to_string()))?; // returns an error when the key can't
                                                                                          // be generated
    private_key
        .write_pkcs8_pem_file(output, LineEnding::default())
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err.to_string()))?; // returns an error when the key can't be written

    Ok(())
}

/// Generate a Public RSA key
///
/// This function generates a public RSA key based on the provided private key file path.
/// It reads the content of the private key file, extracts the private key, and then derives
/// the corresponding public key. The generated public key is saved to a file with the same name
/// as the private key file but with a .pub extension.
///
/// # Arguments
///
/// * private_key_path - The path to the private key file.
///
/// # Errors
///
/// Returns an Err variant if there is an error reading the private key file or if there
/// is an error generating the public key. The error may occur if the private key file cannot
/// be opened, if its content is invalid, or if the public key cannot be derived from the
/// private key.
///
/// # Examples
///
/// ```
/// use std::path::PathBuf;
/// let private_key_path = PathBuf::from("/path/to/private_key.pem");
/// if let Err(err) = generate_public_key(&private_key_path) {
///     eprintln!("Error generating public key: {}", err);
/// }
/// ```
///
pub fn generate_public_key(private_key_path: &PathBuf) -> Result<(), io::Error> {
    let private_key = RsaPrivateKey::read_pkcs8_pem_file(private_key_path)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err.to_string()))?; // returns an error when the key can't
                                                                                          // be generated
    let public_key = RsaPublicKey::from(&private_key);

    let output: PathBuf = append_to_path(private_key_path, ".pub");
    public_key
        .write_public_key_pem_file(output, LineEnding::default()) // Save public key to file
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err.to_string()))?; // returns an error when the key can't be written

    Ok(())
}

/// Encrypts then signs a plain text message.
///
/// Once the message is encrypted with signature, this should output a FILE or standard output.
///
pub fn generate_encrypted_message(
    message: &str,
    public_key_path: &PathBuf,
    signature_path: &PathBuf,
    output: &PathBuf,
) -> Result<(), io::Error> {
    let public_key = RsaPublicKey::read_public_key_pem_file(public_key_path)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err.to_string()))?;
    let signature = RsaPrivateKey::read_pkcs8_pem_file(signature_path)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err.to_string()))?;

    let encrypted_data: Vec<u8> = encrypt_message_rsa_oaep(public_key, message)?;

    // Write to standard output
    if output.to_string_lossy().len() == 0 {
        return print_raw_data(&encrypted_data);
    }

    // Otherwise, write to a FILE
    let mut file = File::create(output)?;
    file.write_all(&encrypted_data)?;
    file.flush()?;

    // println!("Encrypted message: {:#?}", enc_data);
    // Decrypt
    // let padding = Oaep::new::<Sha256>();
    // let dec_data = private_key
    //     .decrypt(padding, &enc_data)
    //     .expect("failed to decrypt");
    Ok(())
}

pub fn encrypt_message_rsa_oaep(
    public_key: RsaPublicKey,
    message: &str,
) -> Result<Vec<u8>, io::Error> {
    let mut rng = rand::rngs::OsRng;
    let data: &[u8] = message.as_bytes();
    let padding = Oaep::new::<Sha256>();
    let encrypted_data = public_key
        .encrypt(&mut rng, padding, &data[..])
        .expect("failed to encrypt message");

    Ok(encrypted_data) // return encrypted data (message)
}

pub fn decrypt_message_rsa_oaep(private_key: RsaPrivateKey, encrypted_message: &str) -> Result<(), io::Error> {
    Ok(())
}
