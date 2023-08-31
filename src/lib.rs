// From   : EmilHernvall/dnsguide
// GitHub : https://github.com/EmilHernvall/dnsguide

#![allow(clippy::all)]
#![allow(dead_code)]

pub mod exp3;

use std::collections::HashMap;
use std::hash::Hash;
use std::io::{Error, ErrorKind, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};
use std::vec;

use exp3::EXP3;
use logs::info;
use rand::rngs::StdRng;
use rand::SeedableRng;

const MAX_BUFFER_SIZE: usize = 4096;

#[derive(Debug)]
pub struct BytePacketBuffer {
    pub buf: [u8; MAX_BUFFER_SIZE],
    pub pos: usize,
}

impl BytePacketBuffer {
    pub fn new() -> BytePacketBuffer {
        BytePacketBuffer {
            buf: [0; MAX_BUFFER_SIZE],
            pos: 0,
        }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    fn step(&mut self, steps: usize) -> Result<()> {
        self.pos += steps;

        Ok(())
    }

    fn seek(&mut self, pos: usize) -> Result<()> {
        self.pos = pos;

        Ok(())
    }

    fn read(&mut self) -> Result<u8> {
        if self.pos >= MAX_BUFFER_SIZE {
            return Err(Error::new(ErrorKind::InvalidInput, "End of buffer"));
        }
        let res = self.buf[self.pos];
        self.pos += 1;

        Ok(res)
    }

    pub fn read_range(&mut self, len: usize) -> Result<&[u8]> {
        self.step(len)?;
        self.get_range(self.pos() - len, len)
    }

    fn get(&mut self, pos: usize) -> Result<u8> {
        if pos >= MAX_BUFFER_SIZE {
            return Err(Error::new(ErrorKind::InvalidInput, "End of buffer"));
        }
        Ok(self.buf[pos])
    }

    pub fn get_range(&self, start: usize, len: usize) -> Result<&[u8]> {
        if start + len >= MAX_BUFFER_SIZE {
            return Err(Error::new(ErrorKind::InvalidInput, "End of buffer"));
        }
        Ok(&self.buf[start..start + len as usize])
    }

    fn read_u16(&mut self) -> Result<u16> {
        let res = ((self.read()? as u16) << 8) | (self.read()? as u16);

        Ok(res)
    }

    fn read_u32(&mut self) -> Result<u32> {
        let res = ((self.read()? as u32) << 24)
            | ((self.read()? as u32) << 16)
            | ((self.read()? as u32) << 8)
            | ((self.read()? as u32) << 0);

        Ok(res)
    }

    fn read_qname(&mut self, outstr: &mut String) -> Result<()> {
        let mut pos = self.pos();
        let mut jumped = false;

        let mut delim = "";
        loop {
            let len = self.get(pos)?;

            // A two byte sequence, where the two highest bits of the first byte is
            // set, represents a offset relative to the start of the buffer. We
            // handle this by jumping to the offset, setting a flag to indicate
            // that we shouldn't update the shared buffer position once done.
            if (len & 0xC0) == 0xC0 {
                // When a jump is performed, we only modify the shared buffer
                // position once, and avoid making the change later on.
                if !jumped {
                    self.seek(pos + 2)?;
                }

                let b2 = self.get(pos + 1)? as u16;
                let offset = (((len as u16) ^ 0xC0) << 8) | b2;
                pos = offset as usize;
                jumped = true;
                continue;
            }

            pos += 1;

            // Names are terminated by an empty label of length 0
            if len == 0 {
                break;
            }

            outstr.push_str(delim);

            let str_buffer = self.get_range(pos, len as usize)?;
            outstr.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase());

            delim = ".";

            pos += len as usize;
        }

        if !jumped {
            self.seek(pos)?;
        }

        Ok(())
    }

    fn write(&mut self, val: u8) -> Result<()> {
        if self.pos >= MAX_BUFFER_SIZE {
            return Err(Error::new(ErrorKind::InvalidInput, "End of buffer"));
        }
        self.buf[self.pos] = val;
        self.pos += 1;
        Ok(())
    }

    fn write_u8(&mut self, val: u8) -> Result<()> {
        self.write(val)?;

        Ok(())
    }

    fn write_u16(&mut self, val: u16) -> Result<()> {
        self.write((val >> 8) as u8)?;
        self.write((val & 0xFF) as u8)?;

        Ok(())
    }

    fn write_u32(&mut self, val: u32) -> Result<()> {
        self.write(((val >> 24) & 0xFF) as u8)?;
        self.write(((val >> 16) & 0xFF) as u8)?;
        self.write(((val >> 8) & 0xFF) as u8)?;
        self.write(((val >> 0) & 0xFF) as u8)?;

        Ok(())
    }

    fn write_qname(&mut self, qname: &str) -> Result<()> {
        let split_str = qname.split('.').collect::<Vec<&str>>();

        for label in split_str {
            let len = label.len();
            if len > 0x3F {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "Single label exceeds 63 characters of length",
                ));
            }

            self.write_u8(len as u8)?;
            for b in label.as_bytes() {
                self.write_u8(*b)?;
            }
        }

        if qname != "" {
            self.write_u8(0)?;
        }

        Ok(())
    }

    fn write_buf(&mut self, buf: &[u8]) -> Result<()> {
        for b in buf {
            self.write_u8(*b)?;
        }
        Ok(())
    }

    fn set(&mut self, pos: usize, val: u8) -> Result<()> {
        self.buf[pos] = val;

        Ok(())
    }

    fn set_u16(&mut self, pos: usize, val: u16) -> Result<()> {
        self.set(pos, (val >> 8) as u8)?;
        self.set(pos + 1, (val & 0xFF) as u8)?;

        Ok(())
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResultCode {
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5,
}

impl ResultCode {
    pub fn from_num(num: u8) -> ResultCode {
        match num {
            1 => ResultCode::FORMERR,
            2 => ResultCode::SERVFAIL,
            3 => ResultCode::NXDOMAIN,
            4 => ResultCode::NOTIMP,
            5 => ResultCode::REFUSED,
            0 | _ => ResultCode::NOERROR,
        }
    }
}

#[derive(Clone, Debug)]
pub struct DnsHeader {
    pub id: u16, // 16 bits

    pub recursion_desired: bool,    // 1 bit
    pub truncated_message: bool,    // 1 bit
    pub authoritative_answer: bool, // 1 bit
    pub opcode: u8,                 // 4 bits
    pub response: bool,             // 1 bit

    pub rescode: ResultCode,       // 4 bits
    pub checking_disabled: bool,   // 1 bit
    pub authed_data: bool,         // 1 bit
    pub z: bool,                   // 1 bit
    pub recursion_available: bool, // 1 bit

    pub questions: u16,             // 16 bits
    pub answers: u16,               // 16 bits
    pub authoritative_entries: u16, // 16 bits
    pub resource_entries: u16,      // 16 bits
}

impl DnsHeader {
    pub fn new() -> DnsHeader {
        DnsHeader {
            id: 0,

            recursion_desired: false,
            truncated_message: false,
            authoritative_answer: false,
            opcode: 0,
            response: false,

            rescode: ResultCode::NOERROR,
            checking_disabled: false,
            authed_data: false,
            z: false,
            recursion_available: false,

            questions: 0,
            answers: 0,
            authoritative_entries: 0,
            resource_entries: 0,
        }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        self.id = buffer.read_u16()?;

        let flags = buffer.read_u16()?;
        let a = (flags >> 8) as u8;
        let b = (flags & 0xFF) as u8;
        self.recursion_desired = (a & (1 << 0)) > 0;
        self.truncated_message = (a & (1 << 1)) > 0;
        self.authoritative_answer = (a & (1 << 2)) > 0;
        self.opcode = (a >> 3) & 0x0F;
        self.response = (a & (1 << 7)) > 0;

        self.rescode = ResultCode::from_num(b & 0x0F);
        self.checking_disabled = (b & (1 << 4)) > 0;
        self.authed_data = (b & (1 << 5)) > 0;
        self.z = (b & (1 << 6)) > 0;
        self.recursion_available = (b & (1 << 7)) > 0;

        self.questions = buffer.read_u16()?;
        self.answers = buffer.read_u16()?;
        self.authoritative_entries = buffer.read_u16()?;
        self.resource_entries = buffer.read_u16()?;

        // Return the constant header size
        Ok(())
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.write_u16(self.id)?;

        (buffer.write_u8(
            (self.recursion_desired as u8)
                | ((self.truncated_message as u8) << 1)
                | ((self.authoritative_answer as u8) << 2)
                | (self.opcode << 3)
                | ((self.response as u8) << 7) as u8,
        ))?;

        (buffer.write_u8(
            (self.rescode.clone() as u8)
                | ((self.checking_disabled as u8) << 4)
                | ((self.authed_data as u8) << 5)
                | ((self.z as u8) << 6)
                | ((self.recursion_available as u8) << 7),
        ))?;

        buffer.write_u16(self.questions)?;
        buffer.write_u16(self.answers)?;
        buffer.write_u16(self.authoritative_entries)?;
        buffer.write_u16(self.resource_entries)?;

        Ok(())
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Hash, Copy)]
pub enum QueryType {
    UNKNOWN(u16),
    A,     // 1
    NS,    // 2
    CNAME, // 5
    SOA,   // 6
    MX,    // 15
    AAAA,  // 28
    OPT,   // 41
}

impl QueryType {
    pub fn to_num(&self) -> u16 {
        match *self {
            QueryType::UNKNOWN(x) => x,
            QueryType::A => 1,
            QueryType::NS => 2,
            QueryType::CNAME => 5,
            QueryType::SOA => 6,
            QueryType::MX => 15,
            QueryType::AAAA => 28,
            QueryType::OPT => 41,
        }
    }

    pub fn from_num(num: u16) -> QueryType {
        match num {
            1 => QueryType::A,
            2 => QueryType::NS,
            5 => QueryType::CNAME,
            6 => QueryType::SOA,
            15 => QueryType::MX,
            28 => QueryType::AAAA,
            41 => QueryType::OPT,
            _ => QueryType::UNKNOWN(num),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: QueryType,
}

impl DnsQuestion {
    pub fn new(name: String, qtype: QueryType) -> DnsQuestion {
        DnsQuestion {
            name: name,
            qtype: qtype,
        }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.read_qname(&mut self.name)?;
        self.qtype = QueryType::from_num(buffer.read_u16()?); // qtype
        let _ = buffer.read_u16()?; // class

        Ok(())
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.write_qname(&self.name)?;

        let typenum = self.qtype.to_num();
        buffer.write_u16(typenum)?;
        buffer.write_u16(1)?;

        Ok(())
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Hash, Copy)]
pub enum OptionType {
    UNKNOWN(u16),
    CSUBNET, // 8
}

impl OptionType {
    pub fn to_num(&self) -> u16 {
        match *self {
            OptionType::UNKNOWN(x) => x,
            OptionType::CSUBNET => 8,
        }
    }

    pub fn from_num(num: u16) -> OptionType {
        match num {
            8 => OptionType::CSUBNET,
            _ => OptionType::UNKNOWN(num),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DnsOption {
    UNKNOWN {
        option_code: u16,
        option_data: Vec<u8>,
    },
    CSUBNET {
        family: u16,
        source_netmask: u8,
        scope_netmask: u8,
        client_subnet: Vec<u8>,
    },
}

impl DnsOption {
    pub fn read(buffer: &mut BytePacketBuffer) -> Result<DnsOption> {
        let option_code: OptionType = OptionType::from_num(buffer.read_u16()?);
        let option_len: usize = buffer.read_u16()?.into();
        let o = match option_code {
            OptionType::UNKNOWN(oc) => DnsOption::UNKNOWN {
                option_code: oc,
                option_data: buffer.read_range(option_len)?.to_vec(),
            },
            OptionType::CSUBNET => DnsOption::CSUBNET {
                family: buffer.read_u16()?,
                source_netmask: buffer.read()?,
                scope_netmask: buffer.read()?,
                client_subnet: buffer.read_range(option_len - (2 + 1 + 1))?.into(),
            },
        };
        Ok(o)
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<usize> {
        match self {
            DnsOption::UNKNOWN {
                option_code: option_type,
                option_data,
            } => {
                buffer.write_u16(*option_type)?;
                buffer.write_u16(option_data.len() as u16)?;
                buffer.write_buf(option_data)?;

                Ok(2 + 2 + option_data.len())
            }
            DnsOption::CSUBNET {
                family,
                source_netmask,
                scope_netmask,
                client_subnet,
            } => {
                buffer.write_u16(OptionType::CSUBNET.to_num())?;
                buffer.write_u16(2 + 1 + 1 + client_subnet.len() as u16)?;
                buffer.write_u16(*family)?;
                buffer.write(*source_netmask)?;
                buffer.write(*scope_netmask)?;
                buffer.write_buf(client_subnet)?;

                Ok(2 + 2 + 1 + 1 + client_subnet.len() as usize)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[allow(dead_code)]
pub enum DnsRecord {
    UNKNOWN {
        domain: String,
        qtype: u16,
        class: u16,
        ttl: u32,
        data_len: u16,
        data_bytes: Vec<u8>,
    }, // 0
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32,
    }, // 1
    NS {
        domain: String,
        host: String,
        ttl: u32,
    }, // 2
    CNAME {
        domain: String,
        host: String,
        ttl: u32,
    }, // 5
    SOA {
        domain: String,
        ttl: u32,
        name: String,
        mailbox: String,
        serial: u32,
        refresh_it: u32,
        retry_it: u32,
        expire_lim: u32,
        min_ttl: u32,
    }, // 6
    MX {
        domain: String,
        priority: u16,
        host: String,
        ttl: u32,
    }, // 15
    AAAA {
        domain: String,
        addr: Ipv6Addr,
        ttl: u32,
    }, // 28
    OPT {
        udp_payload_usize: u16,
        hb_rcode: u8,
        edns_version: u8,
        z: u16,
        options: Vec<DnsOption>,
    },
}

impl DnsRecord {
    pub fn read(buffer: &mut BytePacketBuffer) -> Result<DnsRecord> {
        let mut domain = String::new();
        buffer.read_qname(&mut domain)?;

        let qtype_num = buffer.read_u16()?;
        let qtype = QueryType::from_num(qtype_num);
        let class = buffer.read_u16()?;
        let ttl = buffer.read_u32()?;
        let data_len = buffer.read_u16()?;

        match qtype {
            QueryType::A => {
                let raw_addr = buffer.read_u32()?;
                let addr = Ipv4Addr::new(
                    ((raw_addr >> 24) & 0xFF) as u8,
                    ((raw_addr >> 16) & 0xFF) as u8,
                    ((raw_addr >> 8) & 0xFF) as u8,
                    ((raw_addr >> 0) & 0xFF) as u8,
                );

                Ok(DnsRecord::A {
                    domain: domain,
                    addr: addr,
                    ttl: ttl,
                })
            }
            QueryType::AAAA => {
                let raw_addr1 = buffer.read_u32()?;
                let raw_addr2 = buffer.read_u32()?;
                let raw_addr3 = buffer.read_u32()?;
                let raw_addr4 = buffer.read_u32()?;
                let addr = Ipv6Addr::new(
                    ((raw_addr1 >> 16) & 0xFFFF) as u16,
                    ((raw_addr1 >> 0) & 0xFFFF) as u16,
                    ((raw_addr2 >> 16) & 0xFFFF) as u16,
                    ((raw_addr2 >> 0) & 0xFFFF) as u16,
                    ((raw_addr3 >> 16) & 0xFFFF) as u16,
                    ((raw_addr3 >> 0) & 0xFFFF) as u16,
                    ((raw_addr4 >> 16) & 0xFFFF) as u16,
                    ((raw_addr4 >> 0) & 0xFFFF) as u16,
                );

                Ok(DnsRecord::AAAA {
                    domain: domain,
                    addr: addr,
                    ttl: ttl,
                })
            }
            QueryType::NS => {
                let mut ns = String::new();
                buffer.read_qname(&mut ns)?;

                Ok(DnsRecord::NS {
                    domain: domain,
                    host: ns,
                    ttl: ttl,
                })
            }
            QueryType::CNAME => {
                let mut cname = String::new();
                buffer.read_qname(&mut cname)?;

                Ok(DnsRecord::CNAME {
                    domain: domain,
                    host: cname,
                    ttl: ttl,
                })
            }
            QueryType::SOA => {
                let mut name = String::new();
                buffer.read_qname(&mut name)?;
                let mut mailbox = String::new();
                buffer.read_qname(&mut mailbox)?;
                let serial = buffer.read_u32()?;
                let refresh_it = buffer.read_u32()?;
                let retry_it = buffer.read_u32()?;
                let expire_lim = buffer.read_u32()?;
                let min_ttl = buffer.read_u32()?;

                Ok(DnsRecord::SOA {
                    domain,
                    ttl,
                    name,
                    mailbox,
                    serial,
                    refresh_it,
                    retry_it,
                    expire_lim,
                    min_ttl,
                })
            }
            QueryType::MX => {
                let priority = buffer.read_u16()?;
                let mut mx = String::new();
                buffer.read_qname(&mut mx)?;

                Ok(DnsRecord::MX {
                    domain: domain,
                    priority: priority,
                    host: mx,
                    ttl: ttl,
                })
            }
            QueryType::OPT => {
                let mut l = data_len as usize;
                let mut options = vec![];
                while l > 0 {
                    let pos = buffer.pos();
                    options.push(DnsOption::read(buffer)?);
                    l = l - (buffer.pos() - pos);
                }
                Ok(DnsRecord::OPT {
                    udp_payload_usize: class,
                    hb_rcode: (ttl >> 24) as u8,
                    edns_version: ((0x00FF0000 & ttl) >> 16) as u8,
                    z: (0xFFFF & ttl) as u16,
                    options,
                })
            }
            QueryType::UNKNOWN(_) => {
                let data_bytes = buffer.get_range(buffer.pos, data_len as usize)?.to_vec();
                buffer.step(data_bytes.len())?;
                let record = DnsRecord::UNKNOWN {
                    domain: domain,
                    qtype: qtype_num,
                    class: class,
                    data_len: data_len,
                    ttl: ttl,
                    data_bytes: data_bytes,
                };

                Ok(record)
            }
        }
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<usize> {
        let start_pos = buffer.pos();

        match self {
            &DnsRecord::A {
                ref domain,
                ref addr,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::A.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;
                buffer.write_u16(4)?;

                let octets = addr.octets();
                buffer.write_u8(octets[0])?;
                buffer.write_u8(octets[1])?;
                buffer.write_u8(octets[2])?;
                buffer.write_u8(octets[3])?;
            }
            &DnsRecord::NS {
                ref domain,
                ref host,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::NS.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
            }
            &DnsRecord::CNAME {
                ref domain,
                ref host,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::CNAME.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
            }
            &DnsRecord::SOA {
                ref domain,
                ttl,
                ref name,
                ref mailbox,
                serial,
                refresh_it,
                retry_it,
                expire_lim,
                min_ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::SOA.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_qname(name)?;
                buffer.write_qname(mailbox)?;
                buffer.write_u32(serial)?;
                buffer.write_u32(refresh_it)?;
                buffer.write_u32(retry_it)?;
                buffer.write_u32(expire_lim)?;
                buffer.write_u32(min_ttl)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
            }
            &DnsRecord::MX {
                ref domain,
                priority,
                ref host,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::MX.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_u16(priority)?;
                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
            }
            &DnsRecord::AAAA {
                ref domain,
                ref addr,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::AAAA.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;
                buffer.write_u16(16)?;

                for octet in &addr.segments() {
                    buffer.write_u16(*octet)?;
                }
            }
            DnsRecord::OPT {
                udp_payload_usize,
                hb_rcode,
                edns_version,
                z,
                options,
            } => {
                buffer.write_qname("")?;
                buffer.write_u16(QueryType::OPT.to_num())?;
                buffer.write_u16(*udp_payload_usize)?;
                buffer.write(*hb_rcode)?;
                buffer.write(*edns_version)?;
                buffer.write_u16(*z)?;
                for o in options {
                    o.write(buffer)?;
                }
            }
            &DnsRecord::UNKNOWN {
                ref domain,
                qtype,
                class,
                data_len,
                ttl,
                ref data_bytes,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(qtype)?;
                buffer.write_u16(class)?;
                buffer.write_u32(ttl)?;
                buffer.write_u16(data_len)?;
                buffer.write_buf(data_bytes)?;
            }
        }

        Ok(buffer.pos() - start_pos)
    }

    pub fn get_ttl(&self) -> u32 {
        match self {
            &DnsRecord::UNKNOWN { ttl, .. } => ttl,
            &DnsRecord::A { ttl, .. } => ttl,
            &DnsRecord::NS { ttl, .. } => ttl,
            &DnsRecord::CNAME { ttl, .. } => ttl,
            &DnsRecord::SOA { ttl, .. } => ttl,
            &DnsRecord::MX { ttl, .. } => ttl,
            &DnsRecord::AAAA { ttl, .. } => ttl,
            &DnsRecord::OPT { .. } => 0,
        }
    }

    pub fn set_ttl(&mut self, new_ttl: u32) {
        (*match self {
            DnsRecord::UNKNOWN { ttl, .. } => ttl,
            DnsRecord::A { ttl, .. } => ttl,
            DnsRecord::NS { ttl, .. } => ttl,
            DnsRecord::CNAME { ttl, .. } => ttl,
            DnsRecord::SOA { ttl, .. } => ttl,
            DnsRecord::MX { ttl, .. } => ttl,
            DnsRecord::AAAA { ttl, .. } => ttl,
            DnsRecord::OPT { .. } => return,
        }) = new_ttl;
    }

    pub fn get_domain(&self) -> String {
        (*match self {
            DnsRecord::UNKNOWN { domain, .. } => domain,
            DnsRecord::A { domain, .. } => domain,
            DnsRecord::NS { domain, .. } => domain,
            DnsRecord::CNAME { domain, .. } => domain,
            DnsRecord::SOA { domain, .. } => domain,
            DnsRecord::MX { domain, .. } => domain,
            DnsRecord::AAAA { domain, .. } => domain,
            DnsRecord::OPT { .. } => return "".to_string(),
        })
        .clone()
    }
}

#[derive(Clone, Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>,
}

impl DnsPacket {
    pub fn new() -> DnsPacket {
        DnsPacket {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new(),
        }
    }

    pub fn from_buffer(buffer: &mut BytePacketBuffer) -> Result<DnsPacket> {
        let mut result = DnsPacket::new();
        result.header.read(buffer)?;

        for _ in 0..result.header.questions {
            let mut question = DnsQuestion::new("".to_string(), QueryType::UNKNOWN(0));
            question.read(buffer)?;
            result.questions.push(question);
        }

        for _ in 0..result.header.answers {
            let rec = DnsRecord::read(buffer)?;
            result.answers.push(rec);
        }
        for _ in 0..result.header.authoritative_entries {
            let rec = DnsRecord::read(buffer)?;
            result.authorities.push(rec);
        }
        for _ in 0..result.header.resource_entries {
            let rec = DnsRecord::read(buffer)?;
            result.resources.push(rec);
        }

        Ok(result)
    }

    pub fn write(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        self.header.questions = self.questions.len() as u16;
        self.header.answers = self.answers.len() as u16;
        self.header.authoritative_entries = self.authorities.len() as u16;
        self.header.resource_entries = self.resources.len() as u16;

        self.header.write(buffer)?;

        for question in &self.questions {
            question.write(buffer)?;
        }
        for rec in &self.answers {
            rec.write(buffer)?;
        }
        for rec in &self.authorities {
            rec.write(buffer)?;
        }
        for rec in &self.resources {
            rec.write(buffer)?;
        }

        Ok(())
    }

    pub fn get_random_a(&self) -> Option<String> {
        if !self.answers.is_empty() {
            let a_record = &self.answers[0];
            if let DnsRecord::A { ref addr, .. } = *a_record {
                return Some(addr.to_string());
            }
        }

        None
    }

    pub fn get_resolved_ns(&self, qname: &str) -> Option<String> {
        let mut new_authorities = Vec::new();
        for auth in &self.authorities {
            if let DnsRecord::NS {
                ref domain,
                ref host,
                ..
            } = *auth
            {
                if !qname.ends_with(domain) {
                    continue;
                }

                for rsrc in &self.resources {
                    if let DnsRecord::A {
                        ref domain,
                        ref addr,
                        ttl,
                    } = *rsrc
                    {
                        if domain != host {
                            continue;
                        }

                        let rec = DnsRecord::A {
                            domain: host.clone(),
                            addr: *addr,
                            ttl: ttl,
                        };

                        new_authorities.push(rec);
                    }
                }
            }
        }

        if !new_authorities.is_empty() {
            if let DnsRecord::A { addr, .. } = new_authorities[0] {
                return Some(addr.to_string());
            }
        }

        None
    }

    pub fn get_unresolved_ns(&self, qname: &str) -> Option<String> {
        let mut new_authorities = Vec::new();
        for auth in &self.authorities {
            if let DnsRecord::NS {
                ref domain,
                ref host,
                ..
            } = *auth
            {
                if !qname.ends_with(domain) {
                    continue;
                }

                new_authorities.push(host);
            }
        }

        if !new_authorities.is_empty() {
            return Some(new_authorities[0].clone());
        }

        None
    }
}

#[derive(Debug)]
pub struct ConnectionTime {
    domain: String,
    ip_version: u8,
    connection_time: u16,
}

impl ConnectionTime {
    pub fn read(buffer: &mut BytePacketBuffer) -> Result<Vec<ConnectionTime>> {
        let ntimes = buffer.read()? as usize;
        let mut feedback_times: Vec<ConnectionTime> = Vec::with_capacity(ntimes);
        for _ in 0..ntimes {
            let str_size = buffer.read()? as usize;
            let domain =
                String::from_utf8_lossy(&buffer.buf[buffer.pos()..buffer.pos() + str_size])
                    .to_string();
            buffer.step(str_size)?;
            feedback_times.push(ConnectionTime {
                domain,
                ip_version: buffer.read()?,
                connection_time: buffer.read_u16()?,
            })
        }
        return Ok(feedback_times);
    }
}

#[derive(Debug)]
pub struct CachedRecord {
    pub record: DnsRecord,
    pub expiration: Instant,
}

#[derive(Debug)]
pub struct EXP3Decision {
    pub domain: String,
    pub resolver: SocketAddr,
    pub version: u8,
    pub addresses: Vec<IpAddr>,
    pub instant: Instant,
}

pub struct EXP3State {
    rng: StdRng,
    pub resolvers: Vec<SocketAddr>,
    pub no_queries_type: usize,
    instances: HashMap<String, EXP3>,
    history: HashMap<String, HashMap<(SocketAddr, u8), u16>>,
    cache: HashMap<(SocketAddr, String), Vec<CachedRecord>>,
    pub decisions: HashMap<String, EXP3Decision>,
}

impl EXP3State {
    pub fn new(seed: &str, resolvers: Vec<SocketAddr>, no_queries_type: usize) -> EXP3State {
        let mut bytes = [0u8; 32];
        bytes[0..seed.len()].copy_from_slice(seed.as_bytes());
        let rng = StdRng::from_seed(bytes);
        EXP3State {
            rng,
            resolvers,
            no_queries_type,
            instances: HashMap::new(),
            history: HashMap::new(),
            cache: HashMap::new(),
            decisions: HashMap::new(),
        }
    }

    fn get_root_domain(domain: &String) -> String {
        if domain.matches(".").count() < 2 {
            domain.to_string()
        } else {
            let s: Vec<&str> = domain.split(".").collect();
            s[s.len() - 2..s.len()].join(".")
        }
    }

    pub fn update_with(&mut self, feedback: Vec<ConnectionTime>) -> Result<()> {
        for c in feedback {
            let root_domain = EXP3State::get_root_domain(&c.domain);
            info!(
                "Connection to {}({})@v{} took {}ms",
                c.domain, root_domain, c.ip_version, c.connection_time
            );

            let last_decision = self.decisions.get(&c.domain);
            if last_decision.is_none() {
                continue;
            }
            let last_decision = last_decision.unwrap();
            if c.ip_version != last_decision.version {
                continue;
            }

            let action = self
                .resolvers
                .iter()
                .position(|s| s == &last_decision.resolver)
                .unwrap()
                * self.no_queries_type
                + match last_decision.version {
                    4 => 0,
                    6 => 1,
                    _ => return Err(Error::new(ErrorKind::InvalidData, "Unknown IP version")),
                };

            let last_ctimes = self.history.get_mut(&root_domain);
            let mut better = false;
            if let Some(v) = last_ctimes {
                if ((v.len() == (self.resolvers.len() * self.no_queries_type) - 1)
                    && !v.contains_key(&(last_decision.resolver.clone(), c.ip_version)))
                    || v.len() == self.resolvers.len() * self.no_queries_type
                {
                    better = true;
                    for ((resolver, version), ct) in v.iter() {
                        if resolver != &last_decision.resolver || version != &last_decision.version
                        {
                            if c.connection_time > *ct {
                                better = false;
                                break;
                            }
                        }
                    }
                }
                v.insert(
                    (last_decision.resolver.clone(), c.ip_version),
                    c.connection_time,
                );
            } else {
                let mut v: HashMap<(SocketAddr, u8), u16> = HashMap::new();
                v.insert(
                    (last_decision.resolver.clone(), c.ip_version),
                    c.connection_time,
                );
                self.history.insert(root_domain.to_owned(), v);
            }

            let reward = match better {
                true => 1.0,
                false => 0.0,
            };

            info!("Awarded {} to action {}", reward, action);

            match self.instances.get_mut(&root_domain) {
                Some(instance) => {
                    instance.give_reward(action, reward);
                    info!("EXP3 state {:?}", instance.history.last());
                }
                None => {} //assert!(reward == 0.0),
            }
        }
        Ok(())
    }

    pub fn choose_action(&mut self, domain: &String) -> Result<(SocketAddr, QueryType)> {
        let root_domain = EXP3State::get_root_domain(domain);
        if !self.instances.contains_key(&root_domain) {
            let instance = EXP3::new(
                self.resolvers.len() * self.no_queries_type,
                0.1,
                true,
                false,
            );
            self.instances.insert(root_domain.to_owned(), instance);
        }
        let instance = self.instances.get_mut(&root_domain).unwrap();
        let action = instance.take_action(&mut self.rng);
        info!(
            "EXP3 took action {} for root domain {}",
            action, root_domain
        );
        info!("EXP3 state {:?}", instance.history.last());
        let query_type = match (action * 2 / self.no_queries_type) % 2 {
            0 => QueryType::A,
            1 => QueryType::AAAA,
            _ => return Err(Error::new(ErrorKind::InvalidData, "Unknown action")),
        };
        let resolver = self.resolvers.get(action / self.no_queries_type).unwrap();
        Ok((*resolver, query_type))
    }

    pub fn insert_in_cache(&mut self, resolver: SocketAddr, record: DnsRecord) {
        if let DnsRecord::UNKNOWN { .. } = record {
            return;
        }
        let domain = record.get_domain();
        let v = match self.cache.get_mut(&(resolver.clone(), domain.clone())) {
            Some(v) => v,
            None => {
                let v = Vec::new();
                self.cache.insert((resolver.clone(), domain.clone()), v);
                self.cache.get_mut(&(resolver, domain)).unwrap()
            }
        };

        let expiration = Instant::now() + Duration::new(record.get_ttl().into(), 0);
        v.push(CachedRecord { record, expiration });
    }

    pub fn retrieve_cache(
        &mut self,
        resolver: SocketAddr,
        domain: &String,
        query_type: QueryType,
    ) -> Vec<DnsRecord> {
        // TODO: Extend it to return all records matching the query
        let now = Instant::now();
        let cr = match self.cache.get_mut(&(resolver, domain.to_string())) {
            Some(v) => {
                v.retain(|c| c.expiration > now);
                let cr = v.iter().find(|c| match (query_type, c.record.clone()) {
                    (QueryType::A, DnsRecord::A { .. })
                    | (QueryType::AAAA, DnsRecord::AAAA { .. })
                    | (QueryType::CNAME, DnsRecord::CNAME { .. })
                    | (QueryType::MX, DnsRecord::MX { .. })
                    | (QueryType::NS, DnsRecord::NS { .. })
                    | (QueryType::SOA, DnsRecord::SOA { .. }) => true,
                    _ => false,
                });
                if cr.is_none() {
                    v.iter().find(|c| match (query_type, c.record.clone()) {
                        (QueryType::A, DnsRecord::CNAME { .. })
                        | (QueryType::AAAA, DnsRecord::CNAME { .. }) => true,
                        _ => false,
                    })
                } else {
                    cr
                }
            }
            None => None,
        };
        if let Some(cr) = cr {
            match cr.record.clone() {
                mut r => {
                    r.set_ttl((cr.expiration - now).as_secs() as u32);
                    return match &r {
                        DnsRecord::CNAME { host, .. } => {
                            let alias = &mut self.retrieve_cache(resolver, host, query_type);
                            if !alias.is_empty() {
                                let mut v = vec![r.to_owned()];
                                v.append(alias);
                                v
                            } else {
                                vec![]
                            }
                        }
                        r => vec![r.to_owned()],
                    };
                }
            };
        }
        vec![]
    }
}
