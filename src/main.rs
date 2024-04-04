use clap::{builder::PossibleValuesParser, Args, Parser};
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

/// Commands for different operations (Encrypt/Decrypt/Configure).
///
/// Attach `--debug` before the subcommand to output debug prints.
///
#[derive(Parser, Debug)]
enum Params {
    Configure(ConfigureArgs),
    Decrypt(DecryptArgs),
    Encrypt(EncryptArgs),
    Generate(GenerateArgs),
}

/// Specifies the arguments necessary for encrypting a message.
///
/// When encrypting a file, the following elements are required:
///
/// - Public encryption key of the receiver: Essential for encrypting the message securely for the intended recipient.
///
#[derive(Parser, Debug)]
#[command(about = "Encrypt a message", visible_alias = "enc")]
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
#[derive(Parser, Debug)]
#[command(about = "Decrypt an encrypted message", visible_alias = "dec")]
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
    #[arg()]
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

/// A subcommand for configuring settings
///
#[derive(Parser, Debug)]
#[group(required = true, multiple = false)]
#[command(about = "Configure settings")]
struct ConfigureArgs {
    /// Adds a new public key.
    ///
    /// This will add a new host to your `~/.keys/.known_hosts` file.
    /// Use this argument multiple times to add multiple identification hosts.
    ///
    #[arg(long, short = 'a', value_delimiter = ',')]
    add_host: Vec<String>,

    /// Deletes all key pairs.
    ///
    /// This flag removes all private and public keys stored in the `~/.keys/` directory.
    ///
    #[arg(long, short = 'd')]
    delete_all: bool,
}

/// Generate new keypairs for encryption and signing.
///
/// This flag triggers the generation of two pairs of keys: one for encryption and one for verification.
/// Each pair includes both a private and a public key.
///
#[derive(Parser, Debug)]
#[command(about = "Generate private and public keys", visible_alias = "gen")]
struct GenerateArgs {
    /// Output file
    #[arg(
        long,
        short = 'o',
        required = true,
        visible_alias = "out",
        value_name = "FILE"
    )]
    output: PathBuf,

    /// Bit size
    #[arg(long, short = 'b', default_value = "2048", value_parser = PossibleValuesParser::new(["1024", "2048", "4096"]))]
    bits: String,
}

fn main() {
    let cli: Cli = Cli::parse();

    match cli.param {
        Params::Configure(args) => {
            let delete_all = args.delete_all;
            let add_host = args.add_host;

            if cli.debug {
                println!("Hosts: {:#?}", add_host);
                println!("Delete All: {}", delete_all);
            }
        }
        Params::Encrypt(args) => {
            let message: String = utils::read_input(&args.file).unwrap();
            let pem: PathBuf = args.pem; // probably not needed
            let recipient: PathBuf = args.recipient;
            let skip_verification: bool = args.skip_verification;

            if cli.debug {
                println!("Message: {:#?}", message);
                println!("PEM: {:#?}", pem);
                println!("RECIPIENT: {:#?}", recipient);
                println!("Skip Verification: {:#?}", skip_verification);
            }
        }
        Params::Decrypt(args) => {
            let message: String = utils::read_input(&args.file).unwrap();
            let pem: PathBuf = args.pem; // probably not needed
            let signature: PathBuf = args.signature;
            let skip_verification: bool = args.skip_verification;

            if cli.debug {
                println!("Message: {:#?}", message);
                println!("PEM: {:#?}", pem);
                println!("Signature: {:#?}", signature);
                println!("Skip Verification: {:#?}", skip_verification);
            }
        }
        Params::Generate(args) => {
            let output: PathBuf = args.output;
            let bits: usize = args.bits.parse().unwrap();

            if cli.debug {
                println!("Output: {:#?}", output);
                println!("Bits: {:#?}", bits);
            }

            println!("Generating private and public RSA keys...");
            // let result = utils::generate_rsa_keys(&output, bits);
            utils::generate_private_key(&output, bits);
            utils::generate_public_key(&output);

            println!("Saved {:?}", output.as_path());
        }
    }
}
