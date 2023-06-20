mod cli;
mod config;
mod matcher;
mod watch;

use cli::{parse_args, Args, RunMode, RunType};
use config::{Config, Hosts, MultipleInvalid, Parser};
use futures_util::{future::join_all, StreamExt};
use lazy_static::lazy_static;
use logs::{error, info, warn};
use std::{
    cmp::Reverse,
    collections::{BinaryHeap, HashMap},
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
    task::JoinError,
    time::{sleep_until, timeout, Instant},
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
    let mut exp3_state = EXP3State::new("test", PROXY.read().await.iter().map(|e| *e).collect(), match mode {
        RunMode::EXP3 => 2,
        _ => 1,
    });
    let mut pending_responses: HashMap<Instant, (SocketAddr, Vec<u8>)> = HashMap::new();
    let mut pending_timers: BinaryHeap<Reverse<Instant>> = BinaryHeap::new();

    loop {
        let mut req = BytePacketBuffer::new();

        let max_timer = Instant::now() + Duration::from_secs(86400 * 365);
        let next_timer = pending_timers.peek().unwrap_or(&Reverse(max_timer)).0;

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

                let (it, res) = match handle_request(req, len, mode, &mut exp3_state).await {
                    Ok(data) => data,
                    Err(err) => {
                        error!("Processing request failed {:?}", err);
                        continue;
                    }
                };

                pending_timers.push(Reverse(it.clone()));
                pending_responses.insert(it, (src, res));
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
            _ = sleep_until(next_timer.clone()) => {
                if next_timer != max_timer {
                    let (src, res) = pending_responses.remove(&next_timer).unwrap();
                    if let Err(err) = socket.send_to(&res, &src).await {
                        error!("Replying to '{}' failed {:?}", &src, err);
                    }
                    pending_timers.pop();
                }
            }
        }
    }
}

async fn proxy_on(addr: &SocketAddr, buf: &[u8]) -> Result<Vec<u8>> {
    let duration = *TIMEOUT.read().await;
    let socket = UdpSocket::bind(("0.0.0.0", 0)).await?;

    timeout(duration, async {
        socket.send_to(buf, addr).await?;
        let mut res = [0; 512];
        let len = socket.recv(&mut res).await?;
        Ok(res[..len].to_vec())
    })
    .await?
}

async fn proxy(buf: &[u8]) -> Result<(Instant, Vec<u8>)> {
    let now = Instant::now();
    let proxy = PROXY.read().await;

    for addr in proxy.iter() {
        match proxy_on(addr, buf).await {
            Ok(d) => return Ok((now, d)),
            Err(err) => error!("Agent request to {} {:?}", addr, err),
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
) -> Result<(Instant, Vec<u8>)> {
    let mut it = Instant::now();
    let mut request = DnsPacket::from_buffer(&mut req)?;
    assert!(request.questions.len() < 2);
    let default_res = SocketAddr::from(([0, 0, 0, 0], 0));

    let query = match request.questions.get(0) {
        Some(q) => q,
        None => return proxy(&req.buf[..len]).await,
    };

    info!("{} {:?}", query.name, query.qtype);

    match (mode, query.qtype) {
        (_, QueryType::UNKNOWN(65)) => {}
        (RunMode::Normal, _) => return proxy(&req.buf[..len]).await,
        (RunMode::V4, QueryType::AAAA) => {}
        (RunMode::V4, _) => return proxy(&req.buf[..len]).await,
        (RunMode::DelayV4, QueryType::A) => {
            return Ok((
                it.checked_add(Duration::from_millis(20)).unwrap(),
                (proxy(&req.buf[..len]).await)?.1,
            ))
        }
        (RunMode::DelayV4, _) => return proxy(&req.buf[..len]).await,
        (RunMode::V6, _) => {
            if query.qtype != QueryType::A {
                return proxy(&req.buf[..len]).await;
            }
        }
        (RunMode::DelayV6, QueryType::AAAA) => {
            return Ok((
                it.checked_add(Duration::from_millis(20)).unwrap(),
                (proxy(&req.buf[..len]).await)?.1,
            ))
        }
        (RunMode::DelayV6, _) => return proxy(&req.buf[..len]).await,
        (RunMode::V6AddV4, _) => {
            let domain = request.questions.get(0).unwrap().name.to_owned();
            if (query.qtype == QueryType::A || query.qtype == QueryType::AAAA)
                && exp3_state
                    .retrieve_cache(default_res, &domain, query.qtype)
                    .is_empty()
            {
                let (_, response) = proxy(&req.buf[0..len]).await?;
                let ref mut response_buffer = BytePacketBuffer::new();
                response_buffer.buf[..response.len()].copy_from_slice(&response);
                for a in DnsPacket::from_buffer(response_buffer)?.answers {
                    exp3_state.insert_in_cache(default_res, a);
                }
            }
            if query.qtype == QueryType::AAAA {
                for r in exp3_state.retrieve_cache(default_res, &domain, query.qtype) {
                    request.answers.push(r);
                }
                for r in exp3_state.retrieve_cache(default_res, &domain, QueryType::A) {
                    request.resources.push(match r {
                        DnsRecord::A { domain, addr, ttl } => DnsRecord::AAAA {
                            domain,
                            addr: addr.to_ipv6_mapped(),
                            ttl,
                        },
                        _ => r,
                    });
                }
            }
        }
        (RunMode::V4inV6, _) | (RunMode::V4inV6AddV6, _) => {
            if query.qtype != QueryType::A {
                // Whether to proxy
                let answers = match get_answer(&query.name, query.qtype).await {
                    Some(record) => Vec::from([record]),
                    None => {
                        let ref mut v4_request = request.clone();
                        v4_request.questions.get_mut(0).unwrap().qtype = QueryType::A;
                        let ref mut buffer = BytePacketBuffer::new();
                        v4_request.write(buffer)?;

                        let (_, response) = proxy(&buffer.buf[..buffer.pos]).await?;
                        let ref mut response_buffer = BytePacketBuffer::new();
                        response_buffer.buf[..response.len()].copy_from_slice(&response);
                        let response_packet = DnsPacket::from_buffer(response_buffer)?;
                        response_packet.answers
                    }
                };
                for answer in answers {
                    request.answers.push(match answer {
                        DnsRecord::A { domain, addr, ttl } => DnsRecord::AAAA {
                            domain,
                            addr: addr.to_ipv6_mapped(),
                            ttl,
                        },
                        _ => answer,
                    });
                }
            } else if mode == RunMode::V4inV6AddV6 {
                let answers = match get_answer(&query.name, QueryType::AAAA).await {
                    Some(record) => Vec::from([record]),
                    None => {
                        let ref mut v6_request = request.clone();
                        v6_request.questions.get_mut(0).unwrap().qtype = QueryType::AAAA;
                        let ref mut buffer = BytePacketBuffer::new();
                        v6_request.write(buffer)?;

                        let (_, response) = proxy(&buffer.buf[..buffer.pos]).await?;
                        let ref mut response_buffer = BytePacketBuffer::new();
                        response_buffer.buf[..response.len()].copy_from_slice(&response);
                        let response_packet = DnsPacket::from_buffer(response_buffer)?;
                        response_packet.answers
                    }
                };
                for answer in answers {
                    request.answers.push(answer);
                }
                it = Instant::now()
                    .checked_add(Duration::from_millis(40))
                    .unwrap();
            }
        }
        (RunMode::V6inV4, _) => {
            if query.qtype == QueryType::A {
                let ref mut v6_request = request.clone();
                v6_request.questions.get_mut(0).unwrap().qtype = QueryType::AAAA;
                let ref mut buffer = BytePacketBuffer::new();
                v6_request.write(buffer)?;

                let (_, response) = proxy(&buffer.buf[..buffer.pos]).await?;
                let ref mut response_buffer = BytePacketBuffer::new();
                response_buffer.buf[..response.len()].copy_from_slice(&response);
                let ref mut response_packet = DnsPacket::from_buffer(response_buffer)?;
                request.resources.append(&mut response_packet.answers)
            }
        }
        (RunMode::EXP3, _) |
        (RunMode::EXP3V4, _) => {
            let domain = request.questions.get(0).unwrap().name.to_owned();
            if query.qtype == QueryType::A || query.qtype == QueryType::AAAA {
                let responses: Vec<std::result::Result<(SocketAddr, Result<Vec<u8>>), JoinError>> = {
                    let resolvers = exp3_state.resolvers.clone();
                    let queries: Vec<(SocketAddr, QueryType)> = resolvers
                        .iter()
                        .map(|r| [(r.clone(), QueryType::A), (r.clone(), QueryType::AAAA)])
                        .flatten()
                        .filter(|&(r, qt)| mode != RunMode::EXP3V4 || qt != QueryType::AAAA)
                        .filter(|&(r, qt)| exp3_state.retrieve_cache(r, &domain, qt).is_empty())
                        .collect();

                    async fn wrap_request(
                        r: SocketAddr,
                        buffer: BytePacketBuffer,
                        len: usize,
                    ) -> (SocketAddr, Result<Vec<u8>>) {
                        (r, proxy_on(&r, &buffer.buf[0..len]).await)
                    }

                    join_all(queries.iter().map(|(r, qt)| {
                        let mut request = request.clone();
                        request.questions.get_mut(0).unwrap().qtype = *qt;
                        let mut buffer = BytePacketBuffer::new();
                        request.write(&mut buffer).unwrap();
                        tokio::spawn(wrap_request(*r, buffer, len))
                    }))
                    .await
                };

                for r in responses {
                    match r {
                        Ok((resolver, Ok(response))) => {
                            let mut response_buffer = BytePacketBuffer::new();
                            response_buffer.buf[..response.len()].copy_from_slice(&response);
                            for a in DnsPacket::from_buffer(&mut response_buffer)
                                .unwrap()
                                .answers
                            {
                                exp3_state.insert_in_cache(resolver, a);
                            }
                        }
                        Ok((_, Err(e))) => {
                            println!("{:?}", e);
                        }
                        Err(_) => todo!(),
                    }
                }
            }

            if mode != RunMode::EXP3 && (query.qtype == QueryType::A
                && exp3_state
                    .retrieve_cache(default_res, &domain, QueryType::AAAA)
                    .is_empty())
                || (query.qtype == QueryType::AAAA
                    && exp3_state
                        .retrieve_cache(default_res, &domain, QueryType::A)
                        .is_empty())
            {
                for r in exp3_state.retrieve_cache(default_res, &domain, query.qtype) {
                    request.answers.push(r);
                }
            }
            if request.answers.len() == 0 && (query.qtype == QueryType::AAAA || mode == RunMode::EXP3V4) {
                let (resolver, query_type) = exp3_state.choose_action(&domain)?;
                let answers = exp3_state.retrieve_cache(resolver, &domain, query_type);
                for answer in answers {
                    request.answers.push(match (answer, mode) {
                        (DnsRecord::A { domain, addr, ttl }, RunMode::EXP3) => DnsRecord::AAAA {
                            domain,
                            addr: addr.to_ipv6_mapped(),
                            ttl,
                        },
                        (a, _) => a,
                    });
                }
                exp3_state.decisions.insert(
                    domain.clone(),
                    EXP3Decision {
                        domain: domain.clone(),
                        resolver: resolver.to_owned(),
                        version: match query_type {
                            QueryType::A => 4,
                            QueryType::AAAA => 6,
                            _ => return Err(Error::new(ErrorKind::InvalidData, "Unknown action")),
                        },
                        addresses: vec![],
                        instant: std::time::Instant::now(),
                    },
                );
            }
        }
        (RunMode::Test, _) => {
            let answers = match get_answer(&query.name, query.qtype).await {
                Some(record) => Vec::from([record]),
                None => {
                    let ref mut other_request = request.clone();
                    other_request.questions.get_mut(0).unwrap().qtype =
                        if query.qtype == QueryType::A {
                            QueryType::AAAA
                        } else {
                            QueryType::A
                        };
                    let ref mut buffer = BytePacketBuffer::new();
                    other_request.write(buffer)?;

                    let (_, response) = proxy(&buffer.buf[..buffer.pos]).await?;
                    let ref mut response_buffer = BytePacketBuffer::new();
                    response_buffer.buf[..response.len()].copy_from_slice(&response);
                    let response_packet = DnsPacket::from_buffer(response_buffer)?;
                    response_packet.answers
                }
            };
            for answer in answers {
                request.answers.push(match answer {
                    DnsRecord::A { domain, addr, ttl } => DnsRecord::AAAA {
                        domain,
                        addr: addr.to_ipv6_mapped(),
                        ttl,
                    },
                    _ => answer,
                });
            }
            if query.qtype == QueryType::A {
                it = Instant::now()
                    .checked_add(Duration::from_millis(20))
                    .unwrap();
            }
        }
    }

    request.header.recursion_desired = true;
    request.header.recursion_available = true;
    request.header.response = true;
    let mut res_buffer = BytePacketBuffer::new();
    request.write(&mut res_buffer)?;
    let data = res_buffer.get_range(0, res_buffer.pos())?;
    Ok((it, data.to_vec()))
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
