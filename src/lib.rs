
pub struct Config {
    pub query: String,
    pub filename: String,
    pub ip_address: String,
}

impl Config {
    pub fn new(args: &[String]) -> Result<Config, &str> {
        if args.len() < 4 {
            return Err("not enough arguments");
        }
        let query = args[1].clone();
        let filename = args[2].clone();
        let ip_address = args[3].clone();
        Ok(Config { query, filename, ip_address })
    }
}