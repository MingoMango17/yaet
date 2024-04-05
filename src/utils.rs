use pkcs8::DecodePublicKey;
use rsa::sha2::Sha256;
use rsa::signature::{RandomizedSigner, SignatureEncoding, Verifier};
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
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

pub fn print_raw_data(data: &[u8]) {
    let _ = io::stdout().lock().write_all(data);
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

pub fn read_input_raw(file: &Option<PathBuf>) -> Result<Vec<u8>, io::Error> {
    match file {
        Some(filepath) => {
            let mut file = File::open(filepath)?;
            let mut message = Vec::new();
            file.read_to_end(&mut message)?;

            Ok(message)
        }
        None => {
            let mut message = Vec::new();
            io::stdin().read_to_end(&mut message)?;

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
/// This function takes a plain text message, encrypts it using RSA-OAEP with a provided public key,
/// and then signs the encrypted message with a private key.
/// The encrypted message is either written to a file specified by `output`, or printed to standard output.
///
/// # Arguments
///
/// * `message` - A slice containing the plain text message to be encrypted and signed.
/// * `public_key_path` - The path to the file containing the public key used for encryption.
/// * `signature_path` - The path to the file containing the private key used for signing.
/// * `output` - The path to the file where the encrypted message will be written. If empty, the message
///              will be printed to standard output.
///
/// # Returns
///
/// A `Result` indicating success or failure. If successful, `Ok(())` is returned.
///
pub fn generate_encrypted_message(
    message: &[u8],
    public_key_path: &Path,
    signature_path: &Path,
    output: &Path,
) -> Result<(), io::Error> {
    let public_key: RsaPublicKey = match RsaPublicKey::read_public_key_pem_file(public_key_path) {
        Ok(pkey) => pkey,
        Err(err) => return Err(io::Error::new(io::ErrorKind::Other, err.to_string())),
    };
    let signature = match RsaPrivateKey::read_pkcs8_pem_file(signature_path) {
        Ok(signature) => signature,
        Err(err) => return Err(io::Error::new(io::ErrorKind::Other, err.to_string())),
    };

    let encrypted_data: Vec<u8> = match encrypt_message_rsa_oaep(public_key, message) {
        Ok(data) => data,
        Err(err) => return Err(io::Error::new(io::ErrorKind::Other, err.to_string())),
    };
    let digital_signature: rsa::pss::Signature = sign_message_with_rsassa_pss(signature, message);

    // Concatenate the encrypted message and digital signature
    let mut signed_message: Vec<u8> = encrypted_data.clone();
    signed_message.extend_from_slice(digital_signature.to_vec().as_ref());

    // Write encrypted message to standard output
    if output.to_string_lossy().len() == 0 {
        print_raw_data(&signed_message);

        return Ok(());
    }

    // Otherwise, write to a FILE
    let mut file = File::create(output)?;
    file.write_all(&signed_message)?;
    file.flush()?;

    Ok(())
}

/// Decrypts a previously encrypted and signed message.
///
/// This function takes an encrypted message, decrypts it using RSA-OAEP with a provided private key,
/// and verifies the signature using a provided public key.
/// The decrypted message is either written to a file specified by `output`, or printed to standard output.
///
/// # Arguments
///
/// * `encrypted_message` - A slice containing the encrypted message to be decrypted.
/// * `private_key_path` - The path to the file containing the private key used for decryption.
/// * `signature_path` - The path to the file containing the public key used for signature verification.
/// * `output` - The path to the file where the decrypted message will be written. If empty, the message
///              will be printed to standard output.
///
/// # Returns
///
/// A `Result` indicating success or failure. If successful, `Ok(())` is returned.
///
pub fn generate_decrypted_message(
    encrypted_message: &[u8],
    private_key_path: &Path,
    signature_path: &Path,
    output: &Path,
) -> Result<(), io::Error> {
    let private_key = match RsaPrivateKey::read_pkcs8_pem_file(private_key_path) {
        Ok(pkey) => pkey,
        Err(err) => return Err(io::Error::new(io::ErrorKind::Other, err.to_string())),
    };
    let signature = match RsaPublicKey::read_public_key_pem_file(signature_path) {
        Ok(signature) => signature,
        Err(err) => return Err(io::Error::new(io::ErrorKind::Other, err.to_string())),
    };

    // Split the vector into two equal parts
    let (encrypted_data_slice, signed_message) =
        encrypted_message.split_at(encrypted_message.len() / 2);
    let decrypted_data: Vec<u8> = match decrypt_message_rsa_oaep(private_key, encrypted_data_slice)
    {
        Ok(data) => data,
        Err(err) => return Err(io::Error::new(io::ErrorKind::Other, err.to_string())),
    };

    let digital_signature = rsa::pss::Signature::try_from(signed_message)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err.to_string()))?;
    verify_message_with_rsassa_pss(signature, &decrypted_data, digital_signature)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err.to_string()))?;

    // Write to standard output
    if output.to_string_lossy().len() == 0 {
        print_raw_data(&decrypted_data);

        return Ok(());
    }

    // Otherwise, write to a FILE
    let mut file = File::create(output)?;
    file.write_all(&decrypted_data)?;
    file.flush()?;

    Ok(())
}

/// Encrypts a message using RSA-OAEP.
///
/// This function takes a public key and a message, encrypts the message using RSA-OAEP encryption,
/// and returns the encrypted data.
///
/// # Arguments
///
/// * `public_key` - The RSA public key used for encryption.
/// * `message` - A slice containing the message to be encrypted.
///
/// # Returns
///
/// A `Result` containing a vector of bytes representing the encrypted message if successful.
/// If an error occurs during encryption, an `io::Error` is returned.
///
pub fn encrypt_message_rsa_oaep(
    public_key: RsaPublicKey,
    message: &[u8],
) -> Result<Vec<u8>, rsa::Error> {
    let mut rng = rand::rngs::OsRng;
    let padding = Oaep::new::<Sha256>();

    public_key.encrypt(&mut rng, padding, message)
}

/// Decrypts a message encrypted using RSA-OAEP.
///
/// This function takes a private key and an encrypted message, decrypts the message using RSA-OAEP decryption,
/// and returns the decrypted data.
///
/// # Arguments
///
/// * `private_key` - The RSA private key used for decryption.
/// * `encrypted_message` - A slice containing the encrypted message to be decrypted.
///
/// # Returns
///
/// A `Result` containing a vector of bytes representing the decrypted message if successful.
/// If an error occurs during decryption, an `io::Error` is returned.
///
pub fn decrypt_message_rsa_oaep(
    private_key: RsaPrivateKey,
    encrypted_message: &[u8],
) -> Result<Vec<u8>, rsa::Error> {
    let padding = Oaep::new::<Sha256>();

    private_key.decrypt(padding, encrypted_message)
}

pub fn sign_message_with_rsassa_pss(key: RsaPrivateKey, message: &[u8]) -> rsa::pss::Signature {
    let mut rng = rand::rngs::OsRng;

    // Generate the signing key from the private key signature
    let signing_key = BlindedSigningKey::<Sha256>::new(key);

    // Sign and return the message
    signing_key.sign_with_rng(&mut rng, message)
}

pub fn verify_message_with_rsassa_pss(
    key: RsaPublicKey,
    decrypted_message: &[u8],
    signature: rsa::pss::Signature,
) -> Result<(), rsa::signature::Error> {
    let verifying_key = VerifyingKey::<Sha256>::new(key);
    verifying_key.verify(decrypted_message, &signature)
}
