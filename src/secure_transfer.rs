use std::str::from_utf8;

use anyhow::{Context, Result};
use ring::digest;
use ring::digest::SHA256;
use serde::{Deserialize, Serialize};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::Instant;
use uuid::Uuid;

use rustic_secure_transfer::Config;

use crate::file_encrypt_decrypt::EncryptDecrypt;

pub struct SecureTransfer {
    pub path: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct FileMetadata {
    transaction_id: String,
    pub file_name: String,
    pub file_size: u64,
}

#[derive(Serialize, Deserialize, Debug)]
struct HashMessage {
    transaction_id: String,
    hash: Vec<u8>,
}

impl FileMetadata {
    pub fn new(transaction_id: String, file_name: String, file_size: u64) -> Self {
        Self {
            transaction_id,
            file_name,
            file_size,
        }
    }
}

impl SecureTransfer {
    pub async fn stream_file_and_compute_hash(
        mut file: File,
        transaction_id: String,
        stream: &mut TcpStream,
    ) -> Result<()> {
        let start = Instant::now();

        let mut buffer = [0; 64000];
        let mut hash_context = digest::Context::new(&SHA256);

        let start_file = b"--START OF FILE--";
        let end_file = b"--END OF FILE--";
        let end_hash = b"--END OF HASH--";

        stream
            .write_all(start_file)
            .await
            .context("Failed to send start delimiter")?;
        stream.flush().await?;

        // let elapsed = start.elapsed();
        println!(
            "Time elapsed before loop: {:.8} seconds",
            start.elapsed().as_secs_f64()
        );

        loop {
            let bytes = file
                .read(&mut buffer)
                .await
                .context("Failed to read file content")?;
            if bytes == 0 {
                break;
            }
            stream
                .write_all(&buffer[..bytes])
                .await
                .context("Failed to send file chunk")?;
            stream.flush().await?;
            hash_context.update(&buffer[..bytes]);
        }

        println!(
            "Time elapsed after loop: {:.8} seconds",
            start.elapsed().as_secs_f64()
        );

        stream
            .write_all(end_file)
            .await
            .context("Failed to send EOF delimiter")?;
        stream.flush().await?;

        println!(
            "Time elapsed after EOF: {:.8} seconds",
            start.elapsed().as_secs_f64()
        );

        println!("File content sent with transaction ID: {}", transaction_id);

        let hash_message = HashMessage {
            transaction_id: transaction_id.to_string(),
            hash: hash_context.finish().as_ref().to_vec(),
        };

        let serialized = serde_json::to_string(&hash_message)?;
        stream
            .write_all(serialized.as_bytes())
            .await
            .context("Failed to send hash message")?;
        stream.flush().await?;

        stream
            .write_all(end_hash)
            .await
            .context("Failed to send hash EOF delimiter")?;
        stream.flush().await?;

        println!(
            "Time elapsed after hash sent: {:.8} seconds",
            start.elapsed().as_secs_f64()
        );

        println!("File sent!\nHash generated: {:?}", hex::encode(hash_message.hash));

        println!("Waiting for acknowledgment...");
        if let Err(err) = Self::wait_for_acknowledgment(stream).await {
            println!("Error waiting for acknowledgment: {}", err);
        }
        println!(
            "Time elapsed after ACK: {:.8} seconds",
            start.elapsed().as_secs_f64()
        );

        Ok(())
    }

    pub async fn write_file_async(file_name: String, data: Vec<u8>) -> Result<()> {
        println!("Writing file: {}", file_name);
        let mut file = File::create(file_name.clone())
            .await
            .context("Failed to create file")?;
        file.write_all(&data)
            .await
            .context("Failed to write file contents")?;
        file.sync_all().await.context("Failed to sync file")?;
        println!("File written: {}", file_name);
        Ok(())
    }

    pub async fn connect_to_client(address: &str, port: &str) -> Result<TcpStream> {
        let stream = TcpStream::connect(format!("{}{}", address, port)).await?;
        println!("Connecting to client at {}:{}", address, port);
        Ok(stream)
    }

    pub async fn start_receiving(port: u16) -> Result<()> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;

        let start = Instant::now();

        loop {
            let (mut socket, addr) = listener.accept().await?;
            println!("Connection accepted from: {}", addr);
            tokio::spawn(async move {
                let mut overall_buffer = Vec::new();

                println!("Receiving data...");
                println!(
                    "Time elapsed before getting overall buffer: {:.8} seconds",
                    start.elapsed().as_secs_f64()
                );

                loop {
                    let mut buffer = [0; 4096];
                    if let Ok(size) = socket.read(&mut buffer).await {
                        let delimiter = b"--END OF HASH--";
                        let delimiter_len = delimiter.len();

                        overall_buffer.extend_from_slice(&buffer[..size]);

                        let found_delimiter = buffer[..size]
                            .windows(delimiter_len)
                            .any(|window| window == delimiter);

                        if found_delimiter {
                            break;
                        }
                    } else {
                        println!("Error reading data.");
                        break;
                    }
                }
                println!(
                    "Time elapsed AFTER overall buffer: {:.8} seconds",
                    start.elapsed().as_secs_f64()
                );
                println!("Finished reading data...");

                println!("Received {} bytes.", overall_buffer.len());

                if let Ok(metadata) = SecureTransfer::extract_metadata(&overall_buffer) {
                    println!("Received metadata: {:?}", metadata);

                    println!(
                        "Time elapsed start & end index for delimiter: {:.8} seconds",
                        start.elapsed().as_secs_f64()
                    );
                    let start_delimiter = b"--START OF FILE--";
                    let end_delimiter = b"--END OF FILE--";
                    let end_hash = b"--END OF HASH--";
                    let start_delimiter_length = start_delimiter.len();
                    let end_delimiter_length = end_delimiter.len();
                    let end_hash_length = end_hash.len();

                    if let Some(start_index) = overall_buffer
                        .windows(start_delimiter_length)
                        .position(|window| window == start_delimiter)
                    {
                        if let Some(end_index) = overall_buffer
                            .windows(end_delimiter_length)
                            .position(|window| window == end_delimiter)
                        {
                            println!(
                                "Time elapsed INSIDE start & end index for delimiter: {:.8} seconds",
                                start.elapsed().as_secs_f64()
                            );

                            let file_start_index = start_index + start_delimiter_length;
                            let file_end_index = end_index + end_delimiter_length;

                            let file_content = &overall_buffer[file_start_index..end_index];
                            let (_, extension) = metadata
                                .file_name
                                .split_at(metadata.file_name.rfind(".").unwrap_or(0));

                            println!(
                                "Time elapsed to save file: {:.8} seconds",
                                start.elapsed().as_secs_f64()
                            );
                            if let Err(e) =
                                Self::write_file_async(format!("file{}", extension), file_content.to_vec())
                                    .await
                            {
                                println!("Failed to write file: {}", e);
                            }

                            println!(
                                "Time elapsed after saving file: {:.8} seconds",
                                start.elapsed().as_secs_f64()
                            );
                            let hash_message_content = &overall_buffer[file_end_index..];
                            let hash_length = hash_message_content.len() - end_hash_length;
                            let hash_message_content = &hash_message_content[..hash_length];

                            match serde_json::from_slice::<HashMessage>(&hash_message_content) {
                                Ok(hash_message) => {
                                    let original_hash = hash_message.hash;
                                    let received_hash = EncryptDecrypt::get_hash(&file_content);
                                    if original_hash == received_hash {
                                        println!("Original hash: {:?}", hex::encode(original_hash));
                                        println!("Received hash: {:?}", hex::encode(received_hash));
                                        println!("Hashes match!");
                                    } else {
                                        eprintln!("Hashes do not match");
                                    }
                                }
                                Err(e) => {
                                    println!("Failed to deserialize hash message: {}", e);
                                }
                            }

                            println!(
                                "Time elapsed before sending ack: {:.8} seconds",
                                start.elapsed().as_secs_f64()
                            );
                            if let Err(e) = Self::send_acknowledgment(&mut socket, "ACK_RECEIVED").await {
                                println!("Error sending acknowledgment: {}", e);
                            }
                            println!(
                                "Time elapsed after sending ack: {:.8} seconds",
                                start.elapsed().as_secs_f64()
                            );
                        }
                    }
                }
            });
        }
    }

    pub fn extract_metadata(buffer: &Vec<u8>) -> Result<FileMetadata> {
        if buffer.len() < 8 {
            return Err(anyhow::anyhow!("Buffer too short for metadata length"));
        }

        let metadata_length_bytes: [u8; 8] = buffer[0..8]
            .try_into()
            .context("Failed to extract metadata length")?;

        let metadata_length = u64::from_be_bytes(metadata_length_bytes) as usize;

        if buffer.len() < 8 + metadata_length {
            return Err(anyhow::anyhow!(
                "Buffer too short for the specified metadata length"
            ));
        }

        let metadata_str = from_utf8(&buffer[8..8 + metadata_length])
            .context("Failed to convert metadata to UTF-8 string")?;

        let metadata: FileMetadata =
            serde_json::from_str(metadata_str).context("Failed to deserialize metadata")?;

        Ok(metadata)
    }

    pub async fn send_metadata_and_hash(config: &Config, stream: &mut TcpStream) -> Result<()> {
        let transaction_id = Uuid::new_v4().to_string();

        let file = File::open(&config.file_path)
            .await
            .context("Failed to open file")?;

        let metadata = FileMetadata::new(
            transaction_id.clone(),
            config.file_name.to_string(),
            file.metadata().await?.len(),
        );

        let serialized_metadata = serde_json::to_string(&metadata)?;

        if let Err(err) = Self::send_metadata(stream, &serialized_metadata).await {
            println!("Error sending metadata: {}", err);
        }

        if let Err(err) = Self::stream_file_and_compute_hash(file, transaction_id.clone(), stream).await {
            println!("Error streaming file and computing hash: {}", err);
        }

        Ok(())
    }

    pub async fn send_metadata(stream: &mut TcpStream, metadata: &str) -> Result<()> {
        let metadata_length = metadata.len() as u64;
        stream
            .write_all(&metadata_length.to_be_bytes())
            .await
            .context("Failed to write metadata length")?;
        stream
            .write_all(&metadata.as_bytes())
            .await
            .context("Failed to write metadata")?;
        stream.flush().await?;
        println!("Metadata sent: {}", metadata);
        Ok(())
    }

    pub async fn send_acknowledgment(stream: &mut TcpStream, message: &str) -> Result<()> {
        stream
            .write_all(message.as_bytes())
            .await
            .context("Failed to send acknowledgment")?;
        stream.flush().await?;
        Ok(())
    }

    pub async fn wait_for_acknowledgment(stream: &mut TcpStream) -> Result<()> {
        let mut ack_buffer = [0; 1024];
        let ack_size = stream
            .read(&mut ack_buffer)
            .await
            .context("Failed to read acknowledgment from receiver")?;
        let ack_message =
            from_utf8(&ack_buffer[..ack_size]).context("Failed to decode acknowledgment message")?;

        if ack_message == "ACK_RECEIVED" {
            println!("Acknowledgment received from receiver: {}", ack_message);
        } else {
            println!("Unexpected message received as acknowledgment: {}", ack_message);
        }
        Ok(())
    }
}
