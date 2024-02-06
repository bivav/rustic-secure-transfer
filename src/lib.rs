use std::path::Path;

use anyhow::{Context, Result};
use clap::ArgMatches;
use serde::{Deserialize, Serialize};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub struct Config {
    pub mode: String,
    pub file_path: String,
    pub file_name: String,
    pub destination: String,  // Can be IP:Port for send mode or Port for get mode
}

impl Config {
    pub fn from_matches(matches: &ArgMatches) -> Config {
        let mode = matches.get_one::<String>("mode").unwrap().to_string();

        let file_path = matches.get_one::<String>("file")
            .map(|fp| Path::new(fp).to_path_buf())
            .unwrap_or_default();

        let full_path = file_path.canonicalize()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();

        let file_name = file_path.file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();

        // let (_, file_name) = file_path.split_at(file_path.rfind("/").unwrap() + 1);

        let destination = matches.get_one::<String>("destination").unwrap().to_string();

        Config {
            mode,
            file_path: full_path,
            file_name: file_name.to_string(),
            destination,
        }
    }
}

pub struct SecureTransfer {
    pub path: String,
}

impl SecureTransfer {
    pub fn new(path: &str) -> SecureTransfer {
        SecureTransfer {
            path: path.to_string(),
        }
    }

    pub async fn read_file_async(&self) -> Result<Vec<u8>> {
        let mut file = File::open(&self.path)
            .await
            .context("Failed to open file")?;
        let mut content = vec![];
        file.read_to_end(&mut content)
            .await
            .context("Failed to read file contents")?;
        Ok(content)
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

    pub async fn connect_to_client(address: &str) -> Result<TcpStream> {
        println!("Connecting to client at {}", address);
        let stream = TcpStream::connect(format!("{}:{}", address, "8080")).await?;
        Ok(stream)
    }

    pub async fn start_receiving(port: u16) -> Result<()> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;

        loop {
            let (mut socket, addr) = listener.accept().await?;
            println!("Accepted connection from: {}", addr);
            tokio::spawn(async move {
                let mut buffer = [0; 1024];
                match socket.read(&mut buffer).await {
                    Ok(size) => {
                        println!("Received {} bytes: {:?}", size, &buffer[..size]);

                        // Check if there's more than just the length bytes
                        if size > 8 {
                            // Skip the first 8 bytes and deserialize
                            match serde_json::from_slice::<FileMetadata>(&buffer[8..size]) {
                                Ok(metadata) => {
                                    println!("Received metadata: File name: '{}', File size: {} bytes", metadata.file_name, metadata.file_size);
                                }
                                Err(e) => {
                                    println!("Failed to deserialize metadata: {}", e);
                                }
                            }
                        } else {
                            println!("Not enough data to deserialize metadata");
                        }
                    }
                    Err(e) => {
                        println!("Failed to receive data: {}", e);
                    }
                }
            });
        }
    }

    pub async fn send_metadata(stream: &mut TcpStream, metadata: &str) -> Result<()> {
        let metadata_length = metadata.len() as u64;
        stream.write_all(&metadata_length.to_be_bytes()).await.context("Failed to write metadata length")?;
        stream.write_all(&metadata.as_bytes()).await.context("Failed to write metadata")?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
pub struct FileMetadata {
    pub file_name: String,
    pub file_size: u64,
}

impl FileMetadata {
    pub fn new(file_name: &str, file_size: u64) -> FileMetadata {
        FileMetadata {
            file_name: file_name.to_string(),
            file_size,
        }
    }
}
