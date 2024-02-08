# Rustic Secure Transfer

Rustic Secure Transfer is my open-source project, crafted with Rust for secure, high performance for direct file sharing. It is a command-line tool designed for secure, direct file transfers, emphasizing data integrity and security. Inspired by the simplicity and reliability of tools like SCP and SFTP, this application aims to enhance user experience by offering a more intuitive command-line interface and advanced security features.
___
**NOTE: This project is still in development and is not yet ready for use. If you do, use it at your own risk.**

## Key Features

- **Secure File Transfers:** The application allows for the secure transfer of files over a network. It uses the TCP protocol to establish a connection between the sender and receiver. 
- **Data Integrity Checks:** Implements comprehensive hashing mechanisms to verify the integrity of transferred files, ensuring that files are not altered during transmission.
- **File Hashing**: The application generates a SHA256 hash of the file content to ensure data integrity. The hash is sent along with the file to the receiver.
- **Command-Line Interface:** Offers a simple, user-friendly CLI for initiating and receiving file transfers, making it accessible for both novice and advanced users.
- **Direct Peer-to-Peer Transfers:** Designed for direct transfers between two endpoints without the need for intermediary servers, enhancing privacy and reducing potential points of failure.

## Usage

To use the application, you need to specify the mode (send or get), the destination (IP address and port for send
mode, or port for receive mode), and the file path (for send mode).

For example, to send a file, you would use the following command:

```bash
cargo run -- send 192.168.1.2:8000 /path/to/file.txt
```

To receive a file, you would use the following command:

```bash
cargo run -- get 8000
```

### Future Plans for Security Enhancements

1. **Implement Transport Layer Security (TLS):**
   - Integrate TLS to secure the data transmission channel, ensuring that all data in transit is encrypted and protected from eavesdropping.

2. **Adopt End-to-End Encryption (E2EE):**
   - **Symmetric Encryption:** Utilize AES in GCM mode for efficient and secure data encryption, ensuring that the content of the files is encrypted from end to end.
   - **Asymmetric Encryption:** Implement modern asymmetric encryption algorithms, such as X25519 for key exchange and Ed25519 for digital signatures, to securely exchange keys and authenticate the integrity of the transmitted data.

3. **Employ Hybrid Encryption Techniques:**
   - Combine the strengths of asymmetric and symmetric encryption to securely exchange encryption keys and then encrypt file data, offering both efficiency and high security.

4. **Enhance Data Integrity and Authentication:**
   - Integrate cryptographic hashing (e.g., SHA-256) to verify the integrity and authenticity of the files being transferred, ensuring that the files are not tampered with during transmission.

## Dependencies

The application uses the following dependencies:

- `anyhow` for flexible error handling.
- `clap` for command line argument parsing.
- `ring` for cryptographic operations, specifically SHA256 hashing.
- `serde` and `serde_json` for serializing and deserializing data, specifically file metadata.
- `tokio` for asynchronous runtime, including file and network operations.
- `hex` for encoding and decoding hexadecimal.


## Comparison with SCP and SFTP

While SCP and SFTP provide reliable methods for secure file transfer over SSH, Rustic Secure Transfer brings additional features and improvements:

- **Enhanced Security:** Beyond standard SSH encryption, this tool will implement additional layers of security, ensuring that your data remains confidential and integral from end to end.
- **User Experience:** With a focus on usability, the tool offers a clearer, more straightforward command-line interface for initiating and managing file transfers.
- **Data Integrity Verification:** Each transfer is accompanied by a rigorous integrity check, providing peace of mind that your files arrive exactly as they were sent.

## Contributing

We welcome contributions and suggestions! Feel free to fork the repository, make changes, and submit pull requests. For major changes, please open an issue first to discuss what you would like to change.
