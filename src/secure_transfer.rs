use std::net::SocketAddr;
use std::str::from_utf8;
use std::time::Duration;

use anyhow::{Context, Result};
use ring::digest;
use serde::{Deserialize, Serialize};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

use rustic_secure_transfer::Config;

pub struct SecureTransfer {
    pub path: String,
}

pub struct FileReadResult {
    pub content: Vec<u8>,
    pub hash: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct FileMetadata {
    transaction_id: String,
    pub file_name: String,
    pub file_size: u64,
}

#[derive(Serialize, Deserialize)]
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
    pub fn new(path: &str) -> SecureTransfer {
        SecureTransfer {
            path: path.to_string(),
        }
    }

    pub async fn stream_file_and_compute_hash(mut file: File, transaction_id: String, stream: &mut TcpStream) -> Result<()> {
        // let mut file = File::open(&self.path)
        //     .await
        //     .context("Failed to open file")?;
        // let mut content = vec![];
        // file.read_to_end(&mut content)
        //     .await
        //     .context("Failed to read file contents")?;

        // let hash = EncryptDecrypt::get_hash(&content);

        let mut buffer = [0; 64000];
        let mut hash_context = digest::Context::new(&digest::SHA256);



        while let Ok(bytes) = file.read(&mut buffer).await {
            if bytes == 0 { break;}
            stream.write_all(&buffer[..bytes]).await?;
            hash_context.update(&buffer[..bytes]);
        }

        println!("Here");

        let hash_message = HashMessage {
            transaction_id: transaction_id.to_string(),
            hash: hash_context.finish().as_ref().to_vec(),
        };

        let serialized = serde_json::to_string(&hash_message)?;
        stream.write_all(serialized.as_bytes()).await?;


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
        println!("Connecting to client at {}:{}", address, port);
        let stream = TcpStream::connect(format!("{}{}", address, port)).await?;
        Ok(stream)
    }

    pub async fn start_receiving(port: u16) -> Result<()> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;

        loop {
            let (mut socket, addr) = listener.accept().await?;
            println!("Connection accepted from: {}", addr);
            tokio::spawn(async move {
                let mut buffer = [0; 1024];
                match socket.read(&mut buffer).await {
                    Ok(size) => {
                        println!("Received {} bytes: {:?}", size, &buffer[..10]);

                        // Check if there's more than just the length bytes
                        if size > 8 {
                            // Skip the first 8 bytes and deserialize
                            match serde_json::from_slice::<FileMetadata>(&buffer[8..size]) {
                                Ok(metadata) => {
                                    println!("Received metadata: File name: '{}', File size: {} bytes",
                                             metadata.file_name, metadata.file_size);
                                }
                                Err(e) => {
                                    println!("Failed to deserialize metadata: {}", e);
                                }
                            }
                        } else {
                            println!("Not enough data to deserialize metadata");
                        }

                        tokio::time::sleep(Duration::from_secs(2)).await;
                        Self::send_acknowledgment(&mut socket, addr).await.context("Couldn't send ack").expect("TODO: panic message");
                    }
                    Err(e) => {
                        println!("Failed to receive data: {}", e);
                    }
                }
            });
        }
    }

    pub async fn send_metadata_and_hash(config: &Config, stream: &mut TcpStream) -> Result<()> {
        let transaction_id = Uuid::new_v4().to_string();

        let file = File::open(&config.file_path).await.context("Failed to open file")?;

        let metadata = FileMetadata::new(transaction_id.clone(), config.file_name.to_string(), file.metadata().await?.len());

        let serialized_metadata = serde_json::to_string(&metadata)?;

        SecureTransfer::send_metadata(stream, &serialized_metadata).await?;
        SecureTransfer::wait_for_acknowledgment(stream).await?;

        Self::stream_file_and_compute_hash(file, transaction_id.clone(), stream).await?;

        Ok(())
    }

    pub async fn send_metadata(stream: &mut TcpStream, metadata: &str) -> Result<()> {
        let metadata_length = metadata.len() as u64;
        stream.write_all(&metadata_length.to_be_bytes()).await.context("Failed to write metadata length")?;
        stream.write_all(&metadata.as_bytes()).await.context("Failed to write metadata")?;
        Ok(())
    }

    pub async fn send_acknowledgment(stream: &mut TcpStream, address: SocketAddr) -> Result<()> {
        let message = "ACK";
        println!("Sending acknowledgement to: {} with message {}", address, message);
        stream.write_all(message.as_bytes()).await?;
        Ok(())
    }

    pub async fn wait_for_acknowledgment(stream: &mut TcpStream) -> Result<()> {
        let mut buffer = [0; 1024];

        let bytes = stream.read(&mut buffer).await?;

        // decoding received bytes
        let message = from_utf8(&buffer[..bytes])?;

        println!("Received ACK: {:?}", message);

        Ok(())
    }
}
