# Rustic Secure Transfer

Rustic Secure Transfer is my personal open-source project, crafted with Rust for secure, direct file sharing. This CLI
tool embodies my commitment to combining ease of use with robust security, using encryption for safe, peer-to-peer file
transfers without intermediary servers. It's a testament to my passion for secure software development and the power of
community collaboration.
___
**NOTE: This project is still in development and is not yet ready for use. If you do, use it at your own risk.**

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

## Features

- **Secure File Transfer**: The application allows for the secure transfer of files over a network. It uses the TCP
  protocol to establish a connection between the sender and receiver.

- **File Hashing**: The application generates a SHA256 hash of the file content to ensure data integrity. The hash is
  sent along with the file to the receiver.

- **Asynchronous File Operations**: The application uses the Tokio library to perform asynchronous file read and write
  operations. This allows for efficient handling of large files and network operations.

- **Command Line Interface**: The application provides a command line interface for easy use. The user can specify the
  mode (send or receive), the destination (IP address and port for send mode, or port for receive mode), and the file
  path (for send mode).

#### Planned Features

- Encrypt and decrypt file content using a symmetric key such as AES.2

## Dependencies

The application uses the following dependencies:

- `anyhow` for flexible error handling.
- `clap` for command line argument parsing.
- `ring` for cryptographic operations, specifically SHA256 hashing.
- `serde` and `serde_json` for serializing and deserializing data, specifically file metadata.
- `tokio` for asynchronous runtime, including file and network operations.
- `hex` for encoding and decoding hexadecimal.
