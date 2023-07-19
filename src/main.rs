use std::io;
use std::net::{Ipv4Addr, UdpSocket};

use cookie_factory::gen_simple;

mod packet;

use packet::byte_buffer::{ByteBuffer, MAX_DNS_MSG_SIZE};
use packet::message::DnsMessage;
use packet::qname::Qname;
use packet::query_type::QueryType;
use packet::question::DnsQuestion;
use packet::ResultCode;

fn lookup(qname: &Qname, qtype: QueryType, server: (Ipv4Addr, u16)) -> io::Result<DnsMessage> {
    let socket = UdpSocket::bind(("0.0.0.0", 0))?;

    let mut packet = DnsMessage::new();
    packet.header.id = 6666;
    packet.header.questions = 1;
    packet.header.flags.recursion_desired = true;
    packet.questions.push(DnsQuestion {
        name: qname.clone(),
        qtype,
    });

    let req_buffer = gen_simple(packet.serialize(), Vec::new()).unwrap();

    socket.send_to(&req_buffer, server)?;

    let mut res_buffer = [0u8; MAX_DNS_MSG_SIZE];
    let (len, _) = socket.recv_from(&mut res_buffer)?;
    let res_buffer = &res_buffer[..len];

    let (_, packet) = DnsMessage::parse(res_buffer, &ByteBuffer::new(res_buffer)).unwrap();
    Ok(packet)
}

const ROOT_SERVERS: [&str; 13] = [
        "198.41.0.4",
        "199.9.14.201",
        "192.33.4.12",
        "199.7.91.13",
        "192.203.230.10",
        "192.5.5.241",
        "192.112.36.4",
        "198.97.190.53",
        "192.36.148.17",
        "192.58.128.30",
        "193.0.14.129",
        "199.7.83.42",
        "202.12.27.33",
    ];

fn recursive_lookup(qname: &Qname, qtype: QueryType) -> io::Result<DnsMessage> {
    use rand::seq::SliceRandom;
    let mut ns = ROOT_SERVERS.choose(&mut rand::thread_rng()).unwrap().parse::<Ipv4Addr>().unwrap();

    loop {
        println!("attempting to lookup {qtype:?} entry for {qname} on ns {ns}");

        let ns_copy = ns;
        let server = (ns_copy, 53);
        let response = lookup(qname, qtype, server)?;

        if !response.answers.is_empty() && response.header.flags.rescode == ResultCode::NoError {
            return Ok(response);
        }

        if response.header.flags.rescode == ResultCode::NxDomain {
            return Ok(response);
        }

        if let Some(new_ns) = response.get_resolved_ns(qname) {
            ns = new_ns;
            continue;
        }

        let new_ns_name = match response.get_unresolved_ns(qname) {
            Some(x) => x,
            None => return Ok(response),
        };

        let recursive_response = recursive_lookup(new_ns_name, QueryType::A)?;

        if let Some(new_ns) = recursive_response.get_random_a() {
            ns = new_ns;
        } else {
            return Ok(response);
        }
    }
}

fn handle_query(socket: &UdpSocket) -> io::Result<()> {
    let mut msg_buf = [0u8; MAX_DNS_MSG_SIZE];

    let (len, src) = socket.recv_from(&mut msg_buf)?;
    let msg_buf = &msg_buf[..len];

    let byte_buffer = ByteBuffer::new(msg_buf);

    let (_, mut request) = DnsMessage::parse(msg_buf, &byte_buffer).unwrap();

    let mut packet = DnsMessage::new();
    packet.header.id = request.header.id;
    packet.header.flags.recursion_desired = true;
    packet.header.flags.recursion_available = true;
    packet.header.flags.response = true;

    if let Some(question) = request.questions.pop() {
        println!("Received query: {:?}", question);

        if let Ok(result) = recursive_lookup(&question.name, question.qtype) {
            packet.questions.push(question);
            packet.header.flags.rescode = result.header.flags.rescode;

            for rec in result.answers {
                println!("Answer: {:?}", rec);
                packet.answers.push(rec);
            }
            for rec in result.authorities {
                println!("Authority: {:?}", rec);
                packet.authorities.push(rec);
            }
            for rec in result.resources {
                println!("Resource: {:?}", rec);
                packet.resources.push(rec);
            }
        } else {
            packet.header.flags.rescode = ResultCode::ServFail;
        }
    } else {
        packet.header.flags.rescode = ResultCode::FormErr;
    }

    packet.update_header();
    let res_buffer = gen_simple(packet.serialize(), Vec::new()).unwrap();

    socket.send_to(&res_buffer, src)?;

    Ok(())
}

fn main() -> io::Result<()> {
    let socket = UdpSocket::bind(("0.0.0.0", 2053))?;

    println!("Running DNS server on {}", socket.local_addr()?);

    loop {
        if let Err(e) = handle_query(&socket) {
            eprintln!("An error occurred: {}", e)
        }
    }
}
