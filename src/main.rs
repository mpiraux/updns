mod cli;
mod config;
mod matcher;
mod watch;

use cli::{parse_args, Args, RunMode, RunType};
use config::{Config, Hosts, MultipleInvalid, Parser};
use futures_util::StreamExt;
use lazy_static::lazy_static;
use logs::{error, info, warn};
use std::{
    env,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};
use tokio::{
    io::{self, Error, ErrorKind, Result},
    net::UdpSocket,
    sync::RwLock,
    time::timeout,
};
use updns::*;
use watch::Watch;

const CONFIG_FILE: [&str; 2] = [".updns", "config"];
const WATCH_INTERVAL: Duration = Duration::from_millis(5000);
const DEFAULT_BIND: &str = "0.0.0.0:53";
const DEFAULT_PROXY: [&str; 2] = ["8.8.8.8:53", "1.1.1.1:53"];
const DEFAULT_TIMEOUT: Duration = Duration::from_millis(2000);
const DEFAULT_FEEDBACK_BIND: &str = "0.0.0.0:50000";

lazy_static! {
    static ref PROXY: RwLock<Vec<SocketAddr>> = RwLock::new(Vec::new());
    static ref HOSTS: RwLock<Hosts> = RwLock::new(Hosts::new());
    static ref TIMEOUT: RwLock<Duration> = RwLock::new(DEFAULT_TIMEOUT);
    static ref FEEDBACK: RwLock<Option<SocketAddr>> = RwLock::new(None);
}

#[macro_export]
macro_rules! exit {
    ($($arg:tt)*) => {
        {
            logs::error!($($arg)*);
            std::process::exit(1)
        }
    };
}

#[tokio::main]
async fn main() {
    let Args { path, run } = parse_args();
    match run {
        RunType::AddRecord { ip, host } => {
            let mut parser = Parser::new(&path)
                .await
                .unwrap_or_else(|err| exit!("Failed to read config file {:?}\n{:?}", &path, err));

            if let Err(err) = parser.add(&host, &ip).await {
                exit!("Add record failed\n{:?}", err);
            }
        }
        RunType::PrintRecord => {
            let mut config = force_get_config(&path).await;
            let n = config
                .hosts
                .iter()
                .map(|(m, _)| m.to_string().len())
                .fold(0, |a, b| a.max(b));

            for (host, ip) in config.hosts.iter() {
                println!("{:domain$}    {}", host.to_string(), ip, domain = n);
            }
        }
        RunType::EditConfig => {
            let status = Command::new("vim")
                .arg(&path)
                .status()
                .unwrap_or_else(|err| exit!("Call 'vim' command failed\n{:?}", err));

            if status.success() {
                force_get_config(&path).await;
            } else {
                exit!("'vim' exits with a non-zero status code: {:?}", status);
            }
        }
        RunType::PrintPath => {
            let binary = env::current_exe()
                .unwrap_or_else(|err| exit!("Failed to get directory\n{:?}", err));

            println!("Binary: {}\nConfig: {}", binary.display(), path.display());
        }
        RunType::Start(mode) => {
            let mut config = force_get_config(&path).await;
            if config.bind.is_empty() {
                warn!("Will bind the default address '{}'", DEFAULT_BIND);
                config.bind.push(DEFAULT_BIND.parse().unwrap());
            }
            info!("Run mode {:?}", <&str>::from(mode));
            if config.proxy.is_empty() {
                warn!(
                    "Will use the default proxy address '{}'",
                    DEFAULT_PROXY.join(", ")
                );
            }
            if config.feedback.is_none() {
                warn!(
                    "Will bind the default feedback address '{}'",
                    DEFAULT_FEEDBACK_BIND
                );
                config.feedback = Some(DEFAULT_FEEDBACK_BIND.parse().unwrap());
            }

            update_config(config.proxy, config.hosts, config.timeout, config.feedback).await;

            // Run server
            for addr in config.bind {
                tokio::spawn(run_server(addr, config.feedback.unwrap(), mode)); // TODO(mp): I've likely broken the threading model
            }
            // watch config
            watch_config(path, WATCH_INTERVAL).await;
        }
    }
}

async fn update_config(
    mut proxy: Vec<SocketAddr>,
    hosts: Hosts,
    timeout: Option<Duration>,
    feedback: Option<SocketAddr>,
) {
    if proxy.is_empty() {
        proxy = DEFAULT_PROXY
            .iter()
            .map(|p| p.parse().unwrap())
            .collect::<Vec<SocketAddr>>();
    }

    {
        let mut w = PROXY.write().await;
        *w = proxy;
    }
    {
        let mut w = HOSTS.write().await;
        *w = hosts;
    }
    {
        let mut w = TIMEOUT.write().await;
        *w = timeout.unwrap_or(DEFAULT_TIMEOUT);
    }
    {
        let mut w = FEEDBACK.write().await;
        *w = Some(feedback.unwrap_or(DEFAULT_FEEDBACK_BIND.parse().unwrap()));
    }
}

async fn force_get_config(file: &Path) -> Config {
    let parser = Parser::new(file)
        .await
        .unwrap_or_else(|err| exit!("Failed to read config file {:?}\n{:?}", file, err));

    let config: Config = parser
        .parse()
        .await
        .unwrap_or_else(|err| exit!("Parsing config file failed\n{:?}", err));

    config.invalid.print();
    config
}

async fn watch_config(p: PathBuf, d: Duration) {
    let mut watch = Watch::new(&p, d).await;
    while watch.next().await.is_some() {
        info!("Reload the configuration file: {:?}", &p);
        if let Ok(parser) = Parser::new(&p).await {
            if let Ok(config) = parser.parse().await {
                update_config(config.proxy, config.hosts, config.timeout, config.feedback).await;
                config.invalid.print();
            }
        }
    }
}

async fn run_server(addr: SocketAddr, feedback_addr: SocketAddr, mode: RunMode) {
    let socket = match UdpSocket::bind(&addr).await {
        Ok(socket) => {
            info!("Start listening to '{}'", addr);
            socket
        }
        Err(err) => {
            exit!("Binding '{}' failed\n{:?}", addr, err)
        }
    };

    let feedback_socket = match UdpSocket::bind(&feedback_addr).await {
        Ok(socket) => {
            info!("Start listening for feedback on '{}'", feedback_addr);
            socket
        }
        Err(err) => {
            exit!("Binding '{}' failed\n{:?}", feedback_addr, err)
        }
    };
    let mut exp3_state = EXP3State::new("test");

    loop {
        let mut req = BytePacketBuffer::new();

        tokio::select! {
            _ = socket.readable() => {
                let (len, src) = match socket.try_recv_from(&mut req.buf) {
                    Ok(r) => r,
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        continue;
                    }
                    Err(err) => {
                        error!("Failed to receive message {:?}", err);
                        continue;
                    }
                };

                let res = match handle_request(req, len, mode, &mut exp3_state).await {
                    Ok(data) => data,
                    Err(err) => {
                        error!("Processing request failed {:?}", err);
                        continue;
                    }
                };

                if let Err(err) = socket.send_to(&res, &src).await {
                    error!("Replying to '{}' failed {:?}", &src, err);
                }
            }
            _ = feedback_socket.readable() => {
                let len = match feedback_socket.try_recv(&mut req.buf) {
                    Ok(r) => r,
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        continue;
                    }
                    Err(err) => {
                        error!("Failed to receive message {:?}", err);
                        continue;
                    }
                };
                if let Err(err) = handle_feedback(req, len, &mut exp3_state).await {
                    error!("Unable to parse feedback {:?}", err);
                }
            }
        }
    }
}

async fn proxy(buf: &[u8]) -> Result<Vec<u8>> {
    let proxy = PROXY.read().await;
    let duration = *TIMEOUT.read().await;

    for addr in proxy.iter() {
        let socket = UdpSocket::bind(("0.0.0.0", 0)).await?;

        let data: Result<Vec<u8>> = timeout(duration, async {
            socket.send_to(buf, addr).await?;
            let mut res = [0; 512];
            let len = socket.recv(&mut res).await?;
            Ok(res[..len].to_vec())
        })
        .await?;

        match data {
            Ok(data) => {
                return Ok(data);
            }
            Err(err) => {
                error!("Agent request to {} {:?}", addr, err);
            }
        }
    }

    Err(Error::new(
        ErrorKind::Other,
        "Proxy server failed to proxy request",
    ))
}

async fn get_answer(domain: &str, query: QueryType) -> Option<DnsRecord> {
    if let Some(ip) = HOSTS.read().await.get(domain) {
        match query {
            QueryType::A => {
                if let IpAddr::V4(addr) = ip {
                    return Some(DnsRecord::A {
                        domain: domain.to_string(),
                        addr: *addr,
                        ttl: 3600,
                    });
                }
            }
            QueryType::AAAA => {
                if let IpAddr::V6(addr) = ip {
                    return Some(DnsRecord::AAAA {
                        domain: domain.to_string(),
                        addr: *addr,
                        ttl: 3600,
                    });
                }
            }
            _ => {}
        }
    }
    None
}

async fn handle_request(
    mut req: BytePacketBuffer,
    len: usize,
    mode: RunMode,
    exp3_state: &mut EXP3State,
) -> Result<Vec<u8>> {
    let mut request = DnsPacket::from_buffer(&mut req)?;
    assert!(request.questions.len() < 2);

    let query = match request.questions.get(0) {
        Some(q) => q,
        None => return proxy(&req.buf[..len]).await,
    };

    info!("{} {:?}", query.name, query.qtype);

    match (mode, query.qtype) {
        (_, QueryType::UNKNOWN(65)) => {},
        (RunMode::V4, _) => {
            if query.qtype != QueryType::AAAA {
                return proxy(&req.buf[..len]).await;
            }
        }
        (RunMode::V6, _) => {
            if query.qtype != QueryType::A {
                return proxy(&req.buf[..len]).await;
            }
        }
        (RunMode::V4inV6, _) => {
            if query.qtype != QueryType::A {
                // Whether to proxy
                let answers = match get_answer(&query.name, query.qtype).await {
                    Some(record) => Vec::from([record]),
                    None => {
                        let ref mut v4_request = request.clone();
                        v4_request.questions.get_mut(0).unwrap().qtype = QueryType::A;
                        let ref mut buffer = BytePacketBuffer::new();
                        v4_request.write(buffer)?;

                        let response = proxy(&buffer.buf[..buffer.pos]).await?;
                        let ref mut response_buffer = BytePacketBuffer::new();
                        response_buffer.buf[..response.len()].copy_from_slice(&response);
                        let response_packet = DnsPacket::from_buffer(response_buffer)?;
                        response_packet.answers
                    }
                };
                for answer in answers {
                    request.answers.push(match answer {
                        DnsRecord::A { domain, addr, ttl } => DnsRecord::AAAA {
                            domain: domain,
                            addr: addr.to_ipv6_mapped(),
                            ttl: ttl,
                        },
                        _ => answer,
                    });
                }
            }
        }
        (RunMode::V6inV4, _) => {
            if query.qtype == QueryType::A {
                let ref mut v6_request = request.clone();
                v6_request.questions.get_mut(0).unwrap().qtype = QueryType::AAAA;
                let ref mut buffer = BytePacketBuffer::new();
                v6_request.write(buffer)?;

                let response = proxy(&buffer.buf[..buffer.pos]).await?;
                let ref mut response_buffer = BytePacketBuffer::new();
                response_buffer.buf[..response.len()].copy_from_slice(&response);
                let ref mut response_packet = DnsPacket::from_buffer(response_buffer)?;
                request.resources.append(&mut response_packet.answers)
            }
        }
        (RunMode::EXP3, _) => {
            let domain = request.questions.get(0).unwrap().name.to_owned();
            if query.qtype == QueryType::A || query.qtype == QueryType::AAAA {
                if exp3_state.retrieve_cache(&domain, query.qtype).is_empty() {
                    let response = proxy(&req.buf[0..len]).await?;
                    let ref mut response_buffer = BytePacketBuffer::new();
                    response_buffer.buf[..response.len()].copy_from_slice(&response);
                    for a in DnsPacket::from_buffer(response_buffer)?.answers {
                        exp3_state.insert_in_cache(a);
                    }
                }
            }
            if (query.qtype == QueryType::A
                && exp3_state
                    .retrieve_cache(&domain, QueryType::AAAA)
                    .is_empty())
                || (query.qtype == QueryType::AAAA
                    && exp3_state.retrieve_cache(&domain, QueryType::A).is_empty())
            {
                for r in exp3_state.retrieve_cache(&domain, query.qtype) {
                    request.answers.push(r);
                }
            }
            if request.answers.len() == 0 && query.qtype == QueryType::AAAA {
                let query_type = exp3_state.choose_query_type(&domain)?;
                let answers = exp3_state.retrieve_cache(&domain, query_type);
                for answer in answers {
                    request.answers.push(match answer {
                        DnsRecord::A { domain, addr, ttl } => DnsRecord::AAAA {
                            domain: domain,
                            addr: addr.to_ipv6_mapped(),
                            ttl: ttl,
                        },
                        _ => answer,
                    });
                }
            }
        }
    }

    request.header.recursion_desired = true;
    request.header.recursion_available = true;
    request.header.response = true;
    let mut res_buffer = BytePacketBuffer::new();
    request.write(&mut res_buffer)?;
    let data = res_buffer.get_range(0, res_buffer.pos())?;
    Ok(data.to_vec())
}

async fn handle_feedback(
    mut req: BytePacketBuffer,
    len: usize,
    exp3_state: &mut EXP3State,
) -> Result<()> {
    let feedback = ConnectionTime::read(&mut req)?;
    if req.pos() == len {
        exp3_state.update_with(feedback)
    } else {
        Err(Error::new(
            ErrorKind::InvalidData,
            "Bytes left after reading",
        ))
    }
}
