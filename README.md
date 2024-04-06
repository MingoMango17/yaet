# Yet Another Encryption Tool! (yaet)

**Yet Another Encryption Tool!** (yaet) is a command-line tool designed for encrypting and decrypting messages using RSA-OAEP implementation with verification/authenticity.
It provides a simple and secure way to protect sensitive data using asymmetric encryption.

> [!WARNING]
> 
> This tool is a prototype intended solely for educational purposes within the CMSC 134 Intro to Cybersecurity course.
> It is not suitable for production use.

Main repository is hosted on [Github](https://github.com/0x42697262/yaet).
Please see the [latest](https://github.com/0x42697262/yaet/releases/latest) release for downloads.

## Features

- [x] Generate new key pairs for encryption and signing.
- [x] Encrypt plaintext messages using RSA-OAEP encryption algorithm.
- [x] Decrypt ciphertext messages using RSA-OAEP decryption algorithm.
- [x] Verify the authenticity of encrypted messages through digital signatures.
- [ ] Can identify your mom

## Building

You must have a working Rust environment installed on your computer.
See how to install Rust using [rustup](https://rustup.rs/).

1. Clone the repository:
```
$ git clone https://github.com/0x42697262/yaet.git
```

2. Navigate to the project directory:

```
$ cd yaet
```

3. Build the project:

```
$ cargo build --release
```

4. Run the executable:

```
$ ./target/release/yaet --help
```

Alternatively, you can directly run the tool without building.

```
$ cargo run -- help
```

## Documentation

Check the full documentation [here](https://0x42697262.github.io/yaet/yaet/).

## Usage

Sample keys and signatures are provided in the [examples](./examples/) directory.

### Help

To show the available commands, run

```
$ yaet help
```

This will output the help manual


```
Usage: yaet [OPTIONS] <COMMAND>

Commands:
  decrypt   Decrypt an encrypted message [aliases: dec]
  encrypt   Encrypt a message [aliases: enc]
  generate  Generate private and public keys [aliases: gen]
  help      Print this message or the help of the given subcommand(s)

Options:
      --debug    Enable debug prints
  -h, --help     Print help
  -V, --version  Print version
```

### Generating keys

To generate the two key pairs, run

```
$ yaet generate --output chicken
Generating private and public RSA keys...
Saved "chicken"
Generating private and public signature keys...
Saved "chicken.sig"

$ ls
chicken
chicken.pub
chicken.sig
chicken.sig.pub
```

It's possible to generate a key with shorthand method

```
$ yaet gen -o chicken
```

### Encrypting messages

To encrypt a message, you will need the public key of the receiver and your signing key.

See the help options for `encrypt`

```
$ yaet help encrypt
Usage: yaet encrypt [OPTIONS] --public-key <PUBLIC_KEY> --signing-key <SIGNING_KEY> [FILE]

Arguments:
  [FILE]
          Specifies the input file containing plaintext.
          
          You can provide a file path as the input source. Alternatively, you can directly pipe the output of another command to this argument.

Options:
  -p, --public-key <PUBLIC_KEY>
          The recipient's public RSA key.
          
          The public key is used to encrypt the message.
          
          [aliases: public, key, pkey, pk]

  -s, --signing-key <SIGNING_KEY>
          Your private key signature.
          
          The private key signature is used for authenticity and integrity of your message.
          
          [aliases: signature, sig]

  -o, --output <OUTPUT>
          Output to a FILE
          
          Specify the file path for the output of the encrypted message.
          
          [aliases: out]

  -h, --help
          Print help (see a summary with '-h')
```

This will automatically write the encrypted message along with the signature as one.

> [!NOTE]
> This tool will only write the encrypted data in raw format!



#### Encrypting a file

To encrypt a file, run the following command

```
$ yaet enc --public-key receiver.pub --signing-key chicken.sig message.txt
```

The encrypted message will be printed directly to your terminal in raw bytes.
To make the output readable in string format, you can pipe it to the `base64` command.

```
$ yaet enc --public-key receiver.pub --signing-key chicken.sig message.txt | base64
TzRu8Ky5p8exu5eFsRDUVDndkV1N7WozY8Q9H/9tsMYinQyj2qyVzgKz4Mr/wIZh69zKmThhvj5G
xK1nZbpVKzD16hKX8xYjglYcPJK0+AiqHmNj9FaBiJT+YNFULttMiiwUH4gdmi9EcNLP0txfZrbT
riDhSjzXzwbJby7aUDOTYMMZ3Ikgkt97ADvB4Q6VzI7p3a2Zc248dK4m4a3QlfUTaas4jjEn6sfK
Yt56OI6Sl3Lu+yXMPC/FhB1D6i/rdBkR4VqXE9VldiKdofUYCex7nvcP0mk/aMLdVeJQ01aofz+U
UhQlRq1F7IvDLb3eyOaOXjW9blid5SG2bFCgP6nXB1S+MS9I+aYzdmm0NgVF/LL2IWwacA+F94ME
/7acMd8tYWSfkgzvjvRbbqltp5Qf5BTruZr9DcuOhMMOCeI/tyB0DEhsTYUCHtey4l/Mz45mnMLq
w5YvWCn8wsGp+mZXnda2Lt9VNotzeIiLsPrBDz4nJP+pEnt69GeJCXh92kOjbCaY8IcGogN/uPdd
+MdP/EJn/DHO1mm/Ww==
```

#### Encrypting from standard input

If no file path is provided, YAET will automatically use standard input.
Hit `^D` to encrypt.

Certainly, one could also do piping

```
$ echo "Hello, There!" | yaet enc --public-key receiver.pub --signing-key chicken.sig | base64
WARIqhadDNZaqJCyh/jphe1QtrXuME+QtrNxIl81lVAu8TK3P1knLsofQWoqHLEcRi336wUqKdbP
pCEG6z52f7feDjVri8FOSPthCpTTc+DTYUYzCwhq+h9RRm4CkryCr7fb7GuMQC0OSyRjEGLiP/Ha
0tqUlW6b1BPgEcNIxFUShHMqTLY/ksj6dV+FN/ScApYkKBgIWEnq/BOZtu1P7kvcaY8kPYr4Uc37
CWw7g6IlB5BSZbdXv/QFPsxYlBi43hSWS9j7kDBp2sc2yOCYnUaFH4U5OSS0jdQKfpIPKbSkOEtN
EdGGXAKL+/bCEwuSSzzxG4cVYnqGjjCsFavRvRe6oc8hXxTWRPS0EOUAVV9EJLFuole72p//YPqI
toUJEQo3cx/soCoRzSlLNc7PNc4IqeMuM5XCkE2xQYQcfwXg2oNImBRDPmK5XyBWYZQspYBGH4dw
Za/jriEVJZvqA/jkM8zbhHpYIvw2CmFQ4WqK/J9rl9LY7qSIAT/qT/1DOKtfFTswHNO3nX1kK+cR
qgbkS0S1ROHfkGpZNg==
```

#### Saving to a file

To save the encrypted message, simply append the `--output secret_message` parameter.

If you want to save the file encoded in base64, try this.

```
$ yaet enc --public-key receiver.pub --signing-key chicken.sig message.txt | base64 > secretv2
```

### Decrypting secret messages

Print out the help usage for `decryption` for more details.

```
Usage: yaet decrypt [OPTIONS] --private-key <PRIVATE_KEY> --verifying-key <VERIFYING_KEY> [FILE]

Arguments:
  [FILE]
          Specifies the input file containing ciphertext message.
          
          You can provide a file path as the input source. Alternatively, you can directly pipe the output of another command to this argument.

Options:
  -p, --private-key <PRIVATE_KEY>
          Your RSA private key to decrypt the message.
          
          The private key is used to decrypt the message.
          
          [aliases: private, key, pkey, pk]

  -s, --verifying-key <VERIFYING_KEY>
          The recipient's public key signature.
          
          The public key signature is used for authenticity and integrity of the received encrypted message.
          
          [aliases: signature, sig]

  -o, --output <OUTPUT>
          Output to a FILE
          
          Specify the file path for the output of the encrypted message.
          
          [aliases: out]

  -x, --skip-verification
          Option to skip integrity check.
          
          When enabled, this option ignores the signature of the encrypted message and proceeds to return the decrypted message without performing signature verification.
          
          By default, this option is set to `false`.
          
          [aliases: skip]

  -h, --help
          Print help (see a summary with '-h')
```

This will decrypt the message using the specified private key and verify its authenticity with the provided verifying key.
If successful, the decrypted message will be printed to the terminal.
If not, an error message will be displayed.

To decrypt an encrypted message from a file, you can run the following command

```
$ yaet decrypt --private-key chicken --verifying-key receiver.sig.pub secret
Hello, There!
```

This is on the assumption that the input file is saved as raw bytes, not encoded in base64.
To decrypt from base64, just pipe it

```
$ cat secretv2 | base64 -d | yaet decrypt --private-key chicken --verifying-key receiver.sig.pub
Hello, There!
```


## Methodology

### Key pair generation

**YAET** facilitates the generation of RSA key pairs, comprising both private and public keys.
While having the flexibility to specify the size of the private keys: `1024 bits`, `1648 bits`, `2048 bits`, and `4096 bits`.
By default, the YAET sets the key size to *1648 bits*, equivalent to *206 bytes*, a suitable choice to ensure compatibility with a maximum input limit of **140 characters**.
The maximum bytes it can take is limited to 206 bytes because the default algorithm scheme (explained later on) for encryption is *66 bytes*.

Upon generating the key pairs, YAET provides the option to either display the output on standard output or save it as a file.
The private key file is named according to the provided filename, while the public key file appends `.pub` as its suffix for easy identification.

The process remains consistent for both the signing and verifying keys.
However, the filenames are differentiated to indicate their respective functions.
The signing key appends `.sig` as its suffix, while the verifying key includes `.sig.pub` to denote its purpose.


### Encryption

The generated keys can then be used to encrypt and decrypt messages securely using **RSA-OAEP (Optimal Asymmetric Encryption Padding)**, a trusted encryption scheme that combines the RSA algorithm with Optimal Asymmetric Encryption Padding for enhanced security.
By default, it utilizes **SHA256** for the OAEP padding, a robust hashing algorithm recognized for its reliability because it's a standard.

The encryption process requires the receiver's public key (for encryption) and the sender's signing key (for verification).

### Signature

YAET uses "blinded" RSASSA-PSS signatures by default outlined in [draft-irtf-cfrg-rsa-blind-signatures](https://datatracker.ietf.org/doc/draft-irtf-cfrg-rsa-blind-signatures/) for its integrity.
Similarly with encryption process, the signature is also hashed with *SHA256*.

The signature is appended to the encrypted message and concatenated together to form the complete message.
This ensures that both the encrypted content and its corresponding signature are treated as a single entity, for convenient transmission and verification processes.

### Decryption

During the decryption process, the encrypted content is divided into two distinct components: the encrypted message and the signature.
This would require the sender's verification key (for integrity, which the key is publicly available) and the receiver's private key (for decryption).


### Verification

During the decryption process, if the verification of the signature fails, the decrypted message contents will not be shown.
This ensures that only authenticated and verified messages are presented to the user, maintaining the integrity and security of the communication.

## Contributing

Contributions are welcome! If you have any suggestions, bug reports, or feature requests, please open an issue or submit a pull request.

## License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/0x42697262/yaet/blob/main/LICENSE) file for details.

## Similar Projects

- [https://github.com/gebmecod/RSA-encryption](https://github.com/gebmecod/RSA-encryption) - A quick and easy way to encrypt your data written in Python
- [https://github.com/sycasec/rsa_oaep](https://github.com/sycasec/rsa_oaep) - A more advanced set of features written in Python
- [https://github.com/kyle-gonzales/cmsc134mp2-diez_gonzales_pulvera](https://github.com/kyle-gonzales/cmsc134mp2-diez_gonzales_pulvera) - An attempt to build a chat app implemented in Python
- [https://github.com/GoodyCarlo/cmsc134-mp2](https://github.com/GoodyCarlo/cmsc134-mp2) - Implements secure message encryption, signing, and decryption with detailed examples and explanations regarding threat vectors
