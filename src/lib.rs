use std::path::Path;

use clap::ArgMatches;

pub struct Config {
    pub mode: String,
    pub file_path: String,
    pub file_name: String,
    pub destination: String,
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