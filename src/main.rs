use std::{net::Ipv4Addr, io::{self, Read}, fs::File};

struct BytePacketBuffer {
    buf: [u8; 512],
    pos: usize,
}

const MAX_DNS_MSG_SIZE: usize = 512;

impl BytePacketBuffer {
    fn new() -> BytePacketBuffer {
        BytePacketBuffer {
            buf: [0; 512],
            pos: 0,
        }
    }

    /// Current position within buffer
    fn pos(&self) -> usize {
        self.pos
    }

    /// Step the buffer position forward a specific number of steps
    fn step(&mut self, steps: usize) -> Result<(), String> {
        if self.pos + steps > MAX_DNS_MSG_SIZE {
            return Err("End of buffer".into());
        }
        self.pos += steps;
        Ok(())
    }

    /// Change the buffer position
    fn seek(&mut self, pos: usize) -> Result<(), String> {
        if pos >= MAX_DNS_MSG_SIZE {
            return Err("End of buffer".into());
        }
        self.pos = pos;

        Ok(())
    }

    /// Read a single byte and move the position on step forward
    fn read(&mut self) -> Result<u8, String> {
        if self.pos >= MAX_DNS_MSG_SIZE {
            return Err("End of buffer".into());
        }
        let res = self.buf[self.pos];
        self.pos += 1;

        Ok(res)
    }

    /// Get a single byte, without changing the buffer position
    fn get(&mut self, pos: usize) -> Result<u8, String> {
        if pos >= MAX_DNS_MSG_SIZE {
            return Err("End of buffer".into());
        }

        Ok(self.buf[pos])
    }

    /// Get a range of bytes
    fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8], String> {
        if start + len >= MAX_DNS_MSG_SIZE {
            return Err("End of buffer".into());
        }
        Ok(&self.buf[start..start + len as usize])
    }

    /// Read two bytes, stepping two steps forward
    fn read_u16(&mut self) -> Result<u16, String> {
        let res = ((self.read()? as u16) << 8) | (self.read()? as u16);

        Ok(res)
    }

    /// Read four bytes, stepping four steps forward
    fn read_u32(&mut self) -> Result<u32, String> {
        let res = ((self.read()? as u32) << 24)
            | ((self.read()? as u32) << 16)
            | ((self.read()? as u32) << 8)
            | ((self.read()? as u32) << 0);

        Ok(res)
    }

    /// Read a qname
    ///
    /// The tricky part: Reading domain names, taking labels into consideration.
    /// Will take something like [3]www[6]google[3]com[0] and append
    /// www.google.com to outstr.
    fn read_qname(&mut self, outstr: &mut String) -> Result<(), String> {
        // Since we might encounter jumps, we'll keep track of our position
        // locally as opposed to using the position within hte struct. This
        // allows us to move the shred position to a point past our current
        // qname, while keeping track of our progress on the current qname
        // using this variable.
        let mut pos = self.pos();

        // track whether or not we've jumped
        let mut jumped = false;
        let max_jumps = 5;
        let mut jumps_performed = 0;

        // Our delimiter which we append for each label. Since we don't want a
        // dot at the beginning of the domain name we'll leave it empty for now
        // and set it to "." at the end of the first iteration.
        let mut delim = "";
        loop {
            // DNS packets are untrusted data, so we need to be paranoid. Someone
            // can craft a packet with a cycle in the jump instructions. This guards
            // against such packets.
            if jumps_performed > max_jumps {
                return Err(format!("Limit of {max_jumps} jumps exceeded"));
            }

            // At this pin, we're always at the beginning of a label. Recall
            // that labels start with a length byte.
            let len = self.get(pos)?;

            // If len has the the two most significant bit are set, it represents a
            // jump to some other offset in the packet
            if (len & 0xC0) == 0xC0 {
                // Update the buffer position to a point past the current
                // label. We don't need to touch it any further.
                if !jumped {
                    self.seek(pos + 2)?;
                }

                // Read another byte, calculate offset and perform the jump by
                // updating our local position variable
                let b2 = self.get(pos + 1)? as u16;
                let offset = (((len as u16) ^ 0xC0) << 8) | b2;
                pos = offset as usize;

                // Indicate that a jump was performed.
                jumped = true;
                jumps_performed += 1;

                continue;
            }
            // the base scenario, where we're reading a single label and
            // appending it to the output:
            else {
                // Move a single byte forward to move pas the length byte.
                pos += 1;

                // Domain names are terminated by an empty label of length 0,
                // so if the length is zero we're done.
                if len == 0 {
                    break;
                }

                // Append the delimiter to our output buffer first.
                outstr.push_str(delim);

                // Extract the actual ASCII bytes for this label and append them
                // to the output buffer.
                let str_buffer = self.get_range(pos, len as usize)?;
                outstr.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase());

                delim = ".";

                // Move forward the full length of the label.
                pos += len as usize;
            }
        }

        if !jumped {
            self.seek(pos)?;
        }

        Ok(())
    }
}

#[derive(Debug)]
enum ResultCode {
    NoError = 0,
    FormErr = 1,
    ServFail = 2,
    NxDomain = 3,
    NoTimp = 4,
    Refused = 5,
}

impl ResultCode {
    pub fn from_num(num: u8) -> ResultCode {
        match num {
            1 => ResultCode::FormErr,
            2 => ResultCode::ServFail,
            3 => ResultCode::NxDomain,
            4 => ResultCode::NoTimp,
            5 => ResultCode::Refused,
            0 | _ => ResultCode::NoError,
        }
    }
}

#[derive(Debug)]
struct DnsHeader {
    id: u16, // 16 bits

    recursion_desired: bool,    // 1 bit
    truncated_message: bool,    // 1 bit
    authoritative_answer: bool, // 1 bit
    opcode: u8,                 // 4 bits
    response: bool,             // 1 bit

    rescode: ResultCode,       // 4 bits
    checking_disabled: bool,   // 1 bit
    authed_data: bool,         // 1 bit
    z: bool,                   // 1 bit
    recursion_available: bool, // 1 bit

    questions: u16,             // 16 bits
    answers: u16,               // 16 bits
    authoritative_entries: u16, // 16 bits
    resource_entries: u16,      // 16 bits
}

impl DnsHeader {
    fn new() -> DnsHeader {
        DnsHeader {
            id: 0,

            recursion_desired: false,
            truncated_message: false,
            authoritative_answer: false,
            opcode: 0,
            response: false,

            rescode: ResultCode::NoError,
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

    fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<(), String> {
        self.id = buffer.read_u16()?;

        let flags = buffer.read_u16()?;
        let a = (flags >> 8) as u8;
        let b = (flags & 0xff) as u8;
        self.recursion_desired = (a & (1 << 0)) > 0;
        self.truncated_message = (a & (1 << 1)) > 0;
        self.authoritative_answer = (a & (1 << 2)) > 0;
        self.opcode = (a >> 3) & 0x0f;
        self.response = (a & (1 << 7)) > 0;

        self.rescode = ResultCode::from_num(b & 0x0f);
        self.checking_disabled = (b & (1 << 4)) > 0;
        self.authed_data = (b & (1 << 5)) > 0;
        self.z = (b & (1 << 6)) > 0;
        self.recursion_available = (b & (1 << 7)) > 0;

        self.questions = buffer.read_u16()?;
        self.answers = buffer.read_u16()?;
        self.authoritative_entries = buffer.read_u16()?;
        self.resource_entries = buffer.read_u16()?;

        Ok(())
    }
}

#[derive(Debug)]
enum QueryType {
    Unknown(u16),
    A, // 1
}

impl QueryType {
    fn to_num(&self) -> u16 {
        match *self {
            QueryType::Unknown(x) => x,
            QueryType::A => 1,
        }
    }

    fn from_num(num: u16) -> QueryType {
        match num {
            1 => QueryType::A,
            _ => QueryType::Unknown(num),
        }
    }
}

#[derive(Debug)]
struct DnsQuestion {
    name: String,
    qtype: QueryType,
}

impl DnsQuestion {
    fn new(name: String, qtype: QueryType) -> DnsQuestion {
        DnsQuestion { name, qtype }
    }

    fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<(), String> {
        buffer.read_qname(&mut self.name)?;
        self.qtype = QueryType::from_num(buffer.read_u16()?);
        let _ = buffer.read_u16()?;  // class

        Ok(())
    }
}

#[derive(Debug)]
enum DnsRecord {
    Unknown {
        domain: String,
        qtype: u16,
        data_len: u16,
        ttl: u32,
    },  // 0
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32,
    },  // 1
}

impl DnsRecord {
    fn read(buffer: &mut BytePacketBuffer) -> Result<DnsRecord, String> {
        let mut domain = String::new();
        buffer.read_qname(&mut domain)?;

        let qtype_num = buffer.read_u16()?;
        let qtype = QueryType::from_num(qtype_num);
        let _ = buffer.read_u16()?;
        let ttl = buffer.read_u32()?;
        let data_len = buffer.read_u16()?;

        match qtype {
            QueryType::A => {
                let raw_addr = buffer.read_u32()?;
                let addr = Ipv4Addr::new(
                    ((raw_addr >> 24) & 0xff) as u8,
                    ((raw_addr >> 16) & 0xff) as u8,
                    ((raw_addr >> 8) & 0xff) as u8,
                    ((raw_addr >> 0) & 0xff) as u8,
                );

                Ok(DnsRecord::A { domain, addr, ttl })
            }
            QueryType::Unknown(_) => {
                buffer.step(data_len as usize)?;

                Ok(DnsRecord::Unknown { domain, qtype: qtype_num, data_len, ttl })
            }
        }
    }
}

#[derive(Debug)]
struct DnsPacket {
    header: DnsHeader,
    questions: Vec<DnsQuestion>,
    answers: Vec<DnsRecord>,
    authorities: Vec<DnsRecord>,
    resources: Vec<DnsRecord>,
}

impl DnsPacket {
    fn new() -> Self {
        Self {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new(),
        }
    }

    fn from_buffer(buffer: &mut BytePacketBuffer) -> Result<Self, String> {
        let mut result = DnsPacket::new();
        result.header.read(buffer)?;

        for _ in 0..result.header.questions {
            let mut question = DnsQuestion::new("".to_string(), QueryType::Unknown(0));
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
}

fn main() -> io::Result<()> {
    let mut f = File::open("response_packet.bin")?;
    let mut buffer = BytePacketBuffer::new();
    f.read(&mut buffer.buf)?;

    let packet = DnsPacket::from_buffer(&mut buffer).unwrap();
    println!("{:#?}", packet.header);

    for q in packet.questions {
        println!("{:#?}", q);
    }

    for rec in packet.answers {
        println!("{:#?}", rec);
    }

    for rec in packet.authorities {
        println!("{:#?}", rec);
    }

    for rec in packet.resources {
        println!("{:#?}", rec);
    }

    Ok(())
}
