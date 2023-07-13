use crate::BytePacketBuffer;
use super::QueryType;

#[derive(Debug)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: QueryType,
}

impl DnsQuestion {
    pub fn new(name: String, qtype: QueryType) -> DnsQuestion {
        DnsQuestion { name, qtype }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<(), String> {
        self.name = buffer.read_qname()?;
        self.qtype = QueryType::from(buffer.read_u16()?);
        let _ = buffer.read_u16()?;  // class

        Ok(())
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<(), String> {
        buffer.write_qname(&self.name)?;

        let typenum = self.qtype.into();
        buffer.write_u16(typenum)?;
        buffer.write_u16(1)?;

        Ok(())
    }
}
