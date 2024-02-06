use std::error::Error;
use std::process::exit;

use anyhow::Result;
use clap::{Arg, Command};

use rustic_secure_transfer::Config;

use crate::secure_transfer::SecureTransfer;

mod secure_transfer;
mod file_encrypt_decrypt;

const VERSION: &str = "0.1.0";
const APP_NAME: &str = "Rustic Secure Transfer";
const APP_ABOUT: &str = "Transfers files securely";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("File Transfer App Started...");

    let args = Command::new(APP_NAME)
        .version(VERSION)
        .about(APP_ABOUT)
        .arg(
            Arg::new("mode")
                .help("Mode: 'get' for receiving or 'send' for sending a file")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::new("destination")
                .help("The IP address with port to send to or port to listen on")
                .required(true)
                .index(2),
        )
        .arg(
            Arg::new("file")
                .help("The file path to send")
                .required_if_eq("mode", "send")
                .index(3),
        )
        .get_matches();

    let config = Config::from_matches(&args);

    match config.mode.as_str() {
        "get" => {
            println!("Getting file through port: {}", &config.destination);

            let port = config.destination.clone();
            let port = port.parse::<u16>()?;

            SecureTransfer::start_receiving(port).await?;
        }
        "send" => {
            println!("File to send: {}", &config.file_path);
            println!("File name: {}", &config.file_name);

            // let transfer = SecureTransfer::new(&config.file_path);
            // let file_content = transfer.read_file_in_chunk_async().await?;

            // let metadata = FileMetadata::new(config.file_name,
            //                                  file_content.content.len() as u64);

            // let serialized_metadata = serde_json::to_string(&metadata)?;


            let (address, port) = match config.destination.find(":") {
                None => {
                    println!(
                        "Invalid IP address and port format. It should be in the form IP:Port"
                    );
                    exit(1)
                }
                Some(index) => config.destination.split_at(index),
            };

            let mut stream = SecureTransfer::connect_to_client(&address, &port).await?;
            SecureTransfer::send_metadata_and_hash(&config, &mut stream).await?;

            // println!("File content length: {}", file_content.content.len());
            println!("Sending file to: {}{}", address, port);
            // println!("Hash: {:?}", hex::encode(metadata.hash));


        }
        _ => println!("Invalid mode selected"),
    }

    Ok(())
}
