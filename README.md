# Yet Another Encryption Tool! (yaet)

Yet Another Encryption Tool! (yaet) is a command-line tool designed for encrypting and decrypting messages using RSA-OAEP implementation with verification/authenticity.
It provides a simple and secure way to protect sensitive data using asymmetric encryption.

> [!WARNING]
> 
> This tool is a prototype intended solely for educational purposes within the CMSC 134 Intro to Cybersecurity course.
> It is not suitable for production use.

## Features

- Generate new key pairs for encryption and signing.
- Encrypt plaintext messages using RSA-OAEP encryption algorithm.
- Decrypt ciphertext messages using RSA-OAEP decryption algorithm.
- Verify the authenticity of encrypted messages through digital signatures.

## Installation

1. Clone the repository:
```sh
git clone https://github.com/0x42697262/yaet.git
```

2. Navigate to the project directory:

```sh
cd yaet
```

3. Build the project:

```sh
cargo build --release
```

4. Run the executable:

```sh
./target/release/yaet --help
```

## Usage



## Contributing

Contributions are welcome! If you have any suggestions, bug reports, or feature requests, please open an issue or submit a pull request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
