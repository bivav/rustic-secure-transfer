use std::error::Error;

use anyhow::Result;
use clap::{Arg, Command};

use rustic_secure_transfer::{Config, FileMetadata, SecureTransfer};

const VERSION: &str = "0.1.0";
const APP_NAME: &str = "Rustic Secure Transfer";
const APP_ABOUT: &str = "Transfers files securely";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {


    // let args = std::env::args().collect::<Vec<String>>();

    let args = Command::new(APP_NAME)
        .version(VERSION)
        .about(APP_ABOUT)
        .arg(Arg::new("mode")
            .help("Mode: 'get' for receiving or 'send' for sending a file")
            .required(true)
            .index(1))
        .arg(Arg::new("destination")
            .help("The IP address with port to send to or port to listen on")
            .required(true)
            .index(2))
        .arg(Arg::new("file")
            .help("The file path to send")
            .required_if_eq("mode", "send")
            .index(3))
        .get_matches();

    println!("File Transfer App Started");
    let config = Config::from_matches(&args);

    match config.mode.as_str() {
        "get" => {
            println!("Get file: {}", &config.file_path);
            let port = 8080;
            SecureTransfer::start_receiving(port).await?;
        }
        "send" => {
            println!("File to send: {}", &config.file_path);
            println!("File name: {}", &config.file_name);

            let transfer = SecureTransfer::new(&config.file_path);
            let file_content = transfer.read_file_async().await?;

            let metadata = FileMetadata {
                file_name: config.file_name.clone(),
                file_size: file_content.len() as u64,
            };

            let serialized_metadata = serde_json::to_string(&metadata)?;

            let mut stream = SecureTransfer::connect_to_client(&config.destination).await?;
            SecureTransfer::send_metadata(&mut stream, &serialized_metadata).await?;

            println!("File content length: {}", file_content.len());
        }
        _ => println!("Invalid mode selected"),
    }

    // println!("Query: {}\nFilename: {}\nIP address: {} ", &config.query, &config.file_path, &config.ip_address);

    Ok(())
}
