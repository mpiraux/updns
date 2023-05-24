use crate::{exit, CONFIG_FILE};
use clap::{crate_name, crate_version, Arg, Command};
use logs::Logs;
use regex::Regex;
use std::{net::IpAddr, path::PathBuf};

pub struct Args {
    pub path: PathBuf,
    pub run: RunType,
}

#[derive(Clone, Copy)]
pub enum RunMode {
    V4,
    V6,
    V4inV6,
    V6inV4,
    EXP3,
}

impl RunMode {
    fn values_str<'a>() -> &'a [&'a str] {
        &["v4", "v6", "v4inv6", "v6inv4", "exp3"]
    }

    fn from_str(s: &str) -> Result<Self, &str> {
        match s.to_lowercase().as_str() {
            "v4" => Ok(RunMode::V4),
            "v6" => Ok(RunMode::V6),
            "v4inv6" => Ok(RunMode::V4inV6),
            "v6inv4" => Ok(RunMode::V6inV4),
            "exp3" => Ok(RunMode::EXP3),
            _ => Err("Unknown run mode"),
        }
    }
}

impl From<RunMode> for &str {
    fn from(value: RunMode) -> Self {
        match value {
            RunMode::V4 => "v4",
            RunMode::V6 => "v6",
            RunMode::V4inV6 => "v4inv6",
            RunMode::V6inV4 => "v6inv4",
            RunMode::EXP3 => "exp3",
        }
    }
}

pub enum RunType {
    Start(RunMode),
    AddRecord { ip: String, host: String },
    PrintRecord,
    EditConfig,
    PrintPath,
}

pub fn parse_args() -> Args {
    let matches = Command::new(crate_name!())
        .version(crate_version!())
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .takes_value(true)
                .help("Specify a config file"),
        )
        .arg(
            Arg::with_name("log")
                .short('l')
                .long("log")
                .value_name("LEVEL")
                .takes_value(true)
                .possible_values(["trace", "debug", "info", "warn", "error", "off"])
                .default_value("info")
                .help("Set log level"),
        )
        .subcommand(
            Command::new("add")
                .about("Add a DNS record")
                .arg(
                    Arg::with_name("host")
                        .value_name("HOST")
                        .required(true)
                        .help("Domain of the DNS record"),
                )
                .arg(
                    Arg::with_name("ip")
                        .value_name("IP")
                        .required(true)
                        .help("IP of the DNS record"),
                ),
        )
        .subcommand(Command::new("ls").about("Print all configured DNS records"))
        .subcommand(Command::new("edit").about("Call 'vim' to edit the configuration file"))
        .subcommand(Command::new("path").about("Print related directories"))
        .subcommand(
            Command::new("run").about("Run UDPNS").arg(
                Arg::with_name("mode")
                    .possible_values(RunMode::values_str())
                    .default_value(RunMode::V4inV6.into()),
            ),
        )
        .get_matches();

    let level = matches.value_of("log").unwrap();

    Logs::new()
        .target(crate_name!())
        .level_from_str(level)
        .unwrap()
        .init();

    let path = match matches.value_of("config") {
        Some(s) => PathBuf::from(s),
        None => match dirs::home_dir() {
            Some(p) => p.join(CONFIG_FILE[0]).join(CONFIG_FILE[1]),
            None => exit!("Can't get home directory"),
        },
    };

    match matches.subcommand() {
        None => Args {
            path,
            run: RunType::Start(RunMode::V4inV6),
        },
        Some(("run", matches)) => {
            let mode = matches.value_of("mode").unwrap_or("");
            Args {
                path,
                run: RunType::Start(RunMode::from_str(mode).unwrap()),
            }
        }
        Some(("add", matches)) => {
            let host = matches.value_of("host").unwrap();
            let ip = matches.value_of("ip").unwrap();
            // check
            if let Err(err) = Regex::new(host) {
                exit!(
                    "Cannot resolve host '{}' to regular expression\n{:?}",
                    host,
                    err
                );
            }
            if ip.parse::<IpAddr>().is_err() {
                exit!("Cannot resolve '{}' to ip address", ip);
            }
            Args {
                path,
                run: RunType::AddRecord {
                    ip: ip.to_string(),
                    host: host.to_string(),
                },
            }
        }
        Some(("ls", _)) => Args {
            path,
            run: RunType::PrintRecord,
        },
        Some(("edit", _)) => Args {
            path,
            run: RunType::EditConfig,
        },
        Some(("path", _)) => Args {
            path,
            run: RunType::PrintPath,
        },
        _ => unreachable!(),
    }
}
