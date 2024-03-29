use clap::{Args, Parser};
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use std::path::PathBuf;

mod utils;

/// Command-line interface for Yet Another Encryption Tool.
///
/// Yet Another Encryption Tool!
///
/// RSA-OAEP encrypt or decrypt FILE, or standard input, to standard output.
///
/// With no FILE, or when FILE is -, read standard input.
///
///
/// This prototype tool is intended solely for educational purposes within the CMSC 134 Intro to Cyber
/// security course. It is not suitable for production use.
///
#[derive(Parser, Debug)]
#[command(
    version,
    about = "Yet Another Encryption Tool!

RSA-OAEP encrypt or decrypt FILE, or standard input, to standard output.

With no FILE, or when FILE is -, read standard input.


This prototype tool is intended solely for educational purposes within the CMSC 134 Intro to Cybersecurity course. It is not suitable for production use.",
    long_about = None
    )]
struct Cli {
    #[command(subcommand)]
    param: Params,

    /// Enable debug prints
    ///
    #[arg(long)]
    debug: bool,
}

/// Commands for different operations (Encrypt/Decrypt/Setup).
///
/// Attach `--debug` before the subcommand to output debug prints.
///
#[derive(Parser, Debug)]
enum Params {
    Encrypt(EncryptArgs),
    Decrypt(DecryptArgs),
    Configure(ConfigureArgs),
}

/// Specifies the arguments necessary for encrypting a message.
///
/// When encrypting a file, the following elements are required:
///
/// - Private encryption key: Used to encrypt the message.
///
/// - Public encryption key of the receiver: Essential for encrypting the message securely for the intended recipient.
///
/// - Private signature key: Utilized for message authentication or verification.
///
///
/// When a message is encrypted, it includes the public key of the recipient for encryption and the public signature key of the sender for authentication.
///
#[derive(Parser, Debug)]
#[command(about = "Help message for encrypting a message")]
struct EncryptArgs {
    /// Specifies the input file containing plaintext.
    ///
    /// You can provide a file path as the input source. Alternatively, you can directly pipe the output of another command to this argument.
    ///
    ///
    /// # Example
    ///
    /// ```bash
    /// echo "Hello World" | yaet encrypt [...]
    /// ```
    ///
    /// or
    ///
    /// ```bash
    /// yaet encrypt ~/message.txt [...]
    /// ```
    ///
    // #[arg(required = true)]
    #[arg()]
    file: Option<PathBuf>,

    /// Your identification key.
    ///
    /// This is your Privacy Enhanced Mail format private key which will be used for encrypting the
    /// message.
    ///
    #[arg(required = true, long, short = 'p')]
    pem: PathBuf,

    /// The recipient's public identification key.
    ///
    /// This is the recipient's Privacy Enhanced Mail format public key.
    ///
    #[arg(required = true, long, short = 'r')]
    recipient: PathBuf,

    /// Skip signing of the encrypted message.
    ///
    /// **WARNING: Disabling signing removes the authenticity assurance from the encrypted
    /// message!**
    ///
    #[arg(long, short = 'v')]
    skip_verification: bool,
}

/// Specifies the arguments necessary for decrypting a message.
///
/// When decrypting a file, the following elements are required:
///
/// - Private encryption key: Used to decrypt the message.
///
/// - Public signature key: Utilized for message authentication or verification.
///
///
/// Upon receiving an encrypted message, the recipient is expected to decrypt it using their private key. Before decryption, the recipient verifies that the public signature key associated with the message belongs to the sender.
///
#[derive(Parser, Debug)]
#[command(about = "Help message for decrypting an encrypted message")]
struct DecryptArgs {
    /// Specifies the input file containing ciphertext message.
    ///
    /// You can provide a file path as the input source. Alternatively, you can directly pipe the output of another command to this argument.
    ///
    ///
    /// # Example
    ///
    /// ```bash
    /// echo "Hello World" | yaet decrypt [...]
    /// ```
    ///
    /// or
    ///
    /// ```bash
    /// yaet decrypt ~/message.txt [...]
    /// ```
    ///
    #[arg(required = true)]
    file: Option<PathBuf>,

    /// Your identification key.
    ///
    /// This is your Privacy Enhanced Mail format private key to decrypt the encrypted message.
    ///
    #[arg(required = true, long, short = 'p')]
    pem: PathBuf,

    /// The recipient's public signature key.
    ///
    /// This is the recipient's public signature key used for verification if the message
    /// truly originated from the sender.
    ///
    #[arg(required = true, long, short = 's')]
    signature: PathBuf,

    /// Skip verification of the encrypted message.
    ///
    /// **WARNING: Disabling verification removes the authenticity assurance from the encrypted
    /// message!**
    ///
    #[arg(long, short = 'v')]
    skip_verification: bool,
}

/// A subcommand for configuring private and public keys.
///
/// **Usage: yaet setup** \<COMMAND\>
///
#[derive(Parser, Debug)]
#[command(about = "Help message for configuring private and public keys")]
struct ConfigureArgs {
    #[command(flatten)]
    setup: Setup,
}

/// Setup arguments for generating or deleting private and public key pairs.
///
/// **Usage: yaet setup** \<COMMAND\>
///
/// The [commands](#fields) are shown below.
///
/// Key pairs generated by this tool are stored in the user's home directory within a directory named `.keys`
/// (typically located at `~/.keys/`). Each key pair consists of both a private key and a corresponding public key.
/// Private keys are saved with the suffix `.pem`, while public keys have a `.pub.pem` suffix appended to their filenames.
/// Additionally, signatures for the keys are stored separately, with private key signatures using a `.signature.pem`
/// suffix and public key signatures using a `.signature.pub.pem` suffix.
///
#[derive(Args, Debug)]
#[group(required = true, multiple = false)]
struct Setup {
    /// Adds a new public identification key.
    ///
    /// This will add a new host to your `~/.keys/.known_hosts` file.
    /// Use this argument multiple times to add multiple identification hosts.
    ///
    #[arg(long, short = 'a')]
    add_host: Vec<String>,

    /// Deletes all key pairs.
    ///
    /// This flag removes all private and public keys stored in the `~/.keys/` directory.
    ///
    #[arg(long, short = 'd')]
    delete_all: bool,

    /// Generate new keypairs for encryption and signing.
    ///
    /// This flag triggers the generation of two pairs of keys: one for encryption and one for verification.
    /// Each pair includes both a private and a public key.
    ///
    #[arg(long, short = 'g')]
    generate: bool,
}

fn main() {
    let args: Cli = Cli::parse();

    match args.param {
        Params::Configure(configure_args) => {
            let setup_args = configure_args.setup;
            let generate = setup_args.generate;
            let delete_all = setup_args.delete_all;
            let add_host = setup_args.add_host;

            if args.debug {
                println!("Hosts: {:#?}", add_host);
                println!("Delete All: {}", delete_all);
                println!("Generate: {}", generate);
            }
        }
        Params::Encrypt(encrypt_args) => {
            let message: String = utils::read_input(&encrypt_args.file).unwrap();
            let pem: PathBuf = encrypt_args.pem;
            let recipient: PathBuf = encrypt_args.recipient;
            let skip_verification: bool = encrypt_args.skip_verification;

            if args.debug {
                println!("Message: {:#?}", message);
                println!("PEM: {:#?}", pem);
                println!("RECIPIENT: {:#?}", recipient);
                println!("Skip Verification: {:#?}", skip_verification);
            }
        }
        Params::Decrypt(decrypt_args) => {
            let message = decrypt_args.file;
            let pem: PathBuf = decrypt_args.pem;
            let signature: PathBuf = decrypt_args.signature;
            let skip_verification: bool = decrypt_args.skip_verification;

            if args.debug {
                println!("Message: {:#?}", message.unwrap());
                println!("PEM: {:#?}", pem);
                println!("Signature: {:#?}", signature);
                println!("Skip Verification: {:#?}", skip_verification);
            }
        }
    }
}
