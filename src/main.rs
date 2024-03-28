use clap::{Args, Parser};
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use std::fs::File;
use std::io::{self, Read};
use std::path::PathBuf;

#[derive(Parser)]
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
}

#[derive(Parser)]
enum Params {
    #[command(about = "Help message for encrypting a plaintext or decrypting a ciphertext")]
    Encrypt(EncryptArgs),
    #[command(about = "Help message for configuring private and public keys")]
    Setup(SetupArgs),
}

#[derive(Parser)]
struct EncryptArgs {
    #[arg(required = true, help = "Standard file input")]
    file: Option<PathBuf>,
}

#[derive(Parser)]
struct SetupArgs {
    #[command(flatten)]
    setup: Setup,
}

#[derive(Args)]
#[group(required = true, multiple = false)]
struct Setup {
    #[arg(
        long,
        short = 'g',
        help = "Generate new keypairs for encryption and signing"
    )]
    generate: bool,

    #[arg(long, help = "Delete all key pairs")]
    delete_all: bool,
}

fn main() {
    let args: Cli = Cli::parse();

}
