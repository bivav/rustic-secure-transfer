use std::error::Error;
use rustic_secure_transfer::Config;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("File Transfer App Started");

    let args = std::env::args().collect::<Vec<String>>();
    let config = Config::new(&args)?;

    println!("Query: {}\nFilename: {}\nIP address: {} ", config.query, config.filename, config.ip_address);

    Ok(())
}
