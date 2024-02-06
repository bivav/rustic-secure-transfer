use std::str::from_utf8;

use anyhow::{Context, Result};
use ring::digest;
use ring::digest::SHA256;
use serde::{Deserialize, Serialize};
// use serde_json::Value::String;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

use rustic_secure_transfer::Config;

use crate::file_encrypt_decrypt::EncryptDecrypt;

pub struct SecureTransfer {
    pub path: String,
}

pub struct FileReadResult {
    pub content: Vec<u8>,
    pub hash: Vec<u8>,
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
    pub async fn stream_file_and_compute_hash(mut file: File, transaction_id: String, stream: &mut TcpStream) -> Result<()> {
        let mut buffer = [0; 64000];
        let mut hash_context = digest::Context::new(&SHA256);

        let start_file = b"--START OF FILE--";
        let end_file = b"--END OF FILE--";

        stream.write_all(start_file).await.context("Failed to send start delimiter")?;

        loop {
            let bytes = file.read(&mut buffer).await.context("Failed to read file content")?;
            if bytes == 0 { break; }
            stream.write_all(&buffer[..bytes]).await.context("Failed to send file chunk")?;
            hash_context.update(&buffer[..bytes]);
        }

        stream.write_all(end_file).await.context("Failed to send EOF delimiter")?;

        println!("File content sent with transaction ID: {}", transaction_id);

        let hash_message = HashMessage {
            transaction_id: transaction_id.to_string(),
            hash: hash_context.finish().as_ref().to_vec(),
        };

        let serialized = serde_json::to_string(&hash_message)?;
        stream.write_all(serialized.as_bytes()).await.context("Failed to send hash message")?;

        println!("File hash: {:?}", hex::encode(hash_message.hash));

        Ok(())
    }

    pub async fn write_file_async(&self, data: Vec<u8>) -> Result<()> {
        let mut file = File::create(&self.path)
            .await
            .context("Failed to create file")?;
        file.write_all(&data)
            .await
            .context("Failed to write file contents")?;
        Ok(())
    }

    pub async fn connect_to_client(address: &str, port: &str) -> Result<TcpStream> {
        let stream = TcpStream::connect(format!("{}{}", address, port)).await?;
        println!("Connecting to client at {}:{}", address, port);
        Ok(stream)
    }

    pub async fn start_receiving(port: u16) -> Result<()> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;

        loop {
            let (mut socket, addr) = listener.accept().await?;
            println!("Connection accepted from: {}", addr);
            tokio::spawn(async move {
                let mut overall_buffer = Vec::new();

                loop {
                    let mut buffer = [0; 1024];
                    if let Ok(size) = socket.read(&mut buffer).await {
                        if size == 0 {
                            break; // All data received
                        }
                        overall_buffer.extend_from_slice(&buffer[..size]);
                    } else {
                        break;
                    }
                }

                println!("Received {} bytes.", overall_buffer.len());

                if let Ok(metadata) = SecureTransfer::extract_metadata(&overall_buffer) {
                    println!("Received metadata: {:?}", metadata);
                    if let Err(e) = Self::send_acknowledgment(&mut socket, "Metadata received.").await {
                        println!("Error sending acknowledgment: {}", e);
                    }

                    let start_delimiter = b"--START OF FILE--";
                    let end_delimiter = b"--END OF FILE--";
                    let start_delimiter_length = start_delimiter.len();
                    let end_delimiter_length = end_delimiter.len();

                    if let Some(start_index) = overall_buffer.windows(start_delimiter_length).position(|window| window == start_delimiter) {
                        if let Some(end_index) = overall_buffer.windows(end_delimiter_length).position(|window| window == end_delimiter) {
                            let file_start_index = start_index + start_delimiter_length;
                            let file_end_index = end_index + end_delimiter_length;

                            let file_content = &overall_buffer[file_start_index..end_index];
                            let (_, extension) = metadata.file_name.split_at(metadata.file_name.rfind(".").unwrap_or(0));

                            if let Ok(mut file) = File::create(format!("file{}", extension)).await {
                                file.write_all(&file_content).await.context("Failed to write file content")
                                    .expect("Failed to write file content.");
                            } else {
                                println!("Failed to create file");
                            }

                            let hash_message_content = &overall_buffer[file_end_index..];
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
            return Err(anyhow::anyhow!("Buffer too short for the specified metadata length"));
        }

        let metadata_str = from_utf8(&buffer[8..8 + metadata_length])
            .context("Failed to convert metadata to UTF-8 string")?;

        let metadata: FileMetadata = serde_json::from_str(metadata_str)
            .context("Failed to deserialize metadata")?;

        Ok(metadata)
    }

    pub async fn send_metadata_and_hash(config: &Config, stream: &mut TcpStream) -> Result<()> {
        let transaction_id = Uuid::new_v4().to_string();

        let file = File::open(&config.file_path).await.context("Failed to open file")?;

        let metadata = FileMetadata::new(transaction_id.clone(), config.file_name.to_string(),
                                         file.metadata().await?.len());

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
        stream.write_all(&metadata_length.to_be_bytes()).await.context("Failed to write metadata length")?;
        stream.write_all(&metadata.as_bytes()).await.context("Failed to write metadata")?;
        println!("Metadata sent: {}", metadata);
        // tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        // println!("Waited 2 seconds");
        // if let Err(err) = Self::wait_for_acknowledgment(stream).await {
        //     println!("Error waiting for acknowledgment: {}", err);
        // }
        Ok(())
    }

    pub async fn send_acknowledgment(stream: &mut TcpStream, message: &str) -> Result<()> {
        stream.write_all(message.as_bytes()).await.context("Failed to send acknowledgment")?;
        Ok(())
    }

    pub async fn wait_for_acknowledgment(stream: &mut TcpStream) -> Result<()> {
        let mut buffer = [0; 1024];
        let bytes = stream.read(&mut buffer).await?;
        let message = from_utf8(&buffer[..bytes])?;
        println!("Received ACK: {}", message);
        Ok(())
    }
}
