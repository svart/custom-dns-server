use std::io;
use std::net::{Ipv4Addr, UdpSocket};

mod parse;

use cookie_factory::gen_simple;
use parse::byte_message_buffer::{MAX_DNS_MSG_SIZE, ByteMessageBuffer};
use parse::dns_packet::DnsPacket;
use parse::dns_question::DnsQuestion;
use parse::dns_query_type::QueryType;
use parse::dns_qname::Qname;
use parse::ResultCode;

fn lookup(qname: &Qname, qtype: QueryType, server: (Ipv4Addr, u16)) -> io::Result<DnsPacket> {
    let socket = UdpSocket::bind(("0.0.0.0", 0))?;

    let mut packet = DnsPacket::new();
    packet.header.id = 6666;
    packet.header.questions = 1;
    packet.header.flags.recursion_desired = true;
    packet.questions.push(DnsQuestion {
        name: qname.clone(),
        qtype,
    });

    let req_buffer = gen_simple(packet.serialize(), Vec::new()).unwrap();

    socket.send_to(&req_buffer, server)?;

    let mut res_buffer = Vec::new();
    socket.recv_from(&mut res_buffer)?;

    let (_, packet) = DnsPacket::parse(&res_buffer, &ByteMessageBuffer::new(&res_buffer)).unwrap();
    Ok(packet)
}

fn recursive_lookup(qname: &Qname, qtype: QueryType) -> io::Result<DnsPacket> {
    // For now we are always starting with `a.root-server.net`.
    let mut ns = "198.41.0.4".parse::<Ipv4Addr>().unwrap();

    loop {
        println!("attempting lookup of {qtype:?} {qname:?} with ns {ns}");

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

        let recursive_response = recursive_lookup(&new_ns_name, QueryType::A)?;

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

    let byte_buffer = ByteMessageBuffer::new(&msg_buf[..len]);

    let (_, mut request) = DnsPacket::parse(&msg_buf, &byte_buffer).unwrap();

    let mut packet = DnsPacket::new();
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
        match handle_query(&socket) {
            Err(e) => eprintln!("An error occurred: {}", e),
            Ok(_) => {}
        }
    }
}
