use std::net::{Ipv4Addr, UdpSocket};
use std::io;

use packet::byte_packet_buffer::BytePacketBuffer;
use packet::dns_question::DnsQuestion;
use packet::{DnsPacket, QueryType, ResultCode};

mod packet;


fn lookup(qname: &str, qtype: QueryType, server: (Ipv4Addr, u16)) -> io::Result<DnsPacket> {
    let socket = UdpSocket::bind(("0.0.0.0", 0))?;

    let mut packet = DnsPacket::new();
    packet.header.id = 6666;
    packet.header.questions = 1;
    packet.header.flags.recursion_desired = true;
    packet
        .questions
        .push(DnsQuestion { name: qname.to_string(), qtype});

    let mut req_buffer = BytePacketBuffer::new();
    packet.write(&mut req_buffer).unwrap();

    socket.send_to(&req_buffer.buf[0..req_buffer.pos()], server)?;

    let mut res_buffer = BytePacketBuffer::new();
    socket.recv_from(&mut res_buffer.buf)?;

    Ok(DnsPacket::from_buffer(&mut res_buffer).unwrap())
}

fn recursive_lookup(qname: &str, qtype: QueryType) -> io::Result<DnsPacket> {
    // For now we are always starting with `a.root-server.net`.
    let mut ns = "198.41.0.4".parse::<Ipv4Addr>().unwrap();

    loop {
        println!("attempting lookup of {qtype:?} {qname} with ns {ns}");

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
    let mut req_buffer = BytePacketBuffer::new();

    let (_, src) = socket.recv_from(&mut req_buffer.buf)?;

    let mut request = DnsPacket::from_buffer(&mut req_buffer).unwrap();

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

    let mut res_buffer = BytePacketBuffer::new();
    packet.write(&mut res_buffer).unwrap();

    let len = res_buffer.pos();
    let data = res_buffer.get_range(0, len).unwrap();

    socket.send_to(data, src)?;

    Ok(())
}

fn main() -> io::Result<()> {
    let socket = UdpSocket::bind(("0.0.0.0", 2053))?;

    println!("Running DNS server on {}", socket.local_addr()?);

    loop {
        match handle_query(&socket) {
            Ok(_) => {},
            Err(e) => eprintln!("An error occurred: {}", e),
        }
    }
}
