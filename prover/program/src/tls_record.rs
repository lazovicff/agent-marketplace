// ============================================================
//  TLS Record Parsing
// ============================================================

pub const CONTENT_TYPE_HANDSHAKE: u8 = 22;
pub const CONTENT_TYPE_APPLICATION_DATA: u8 = 23;
pub const HANDSHAKE_TYPE_CERTIFICATE_VERIFY: u8 = 15;
pub const EXPECTED_TLS_VERSION: u16 = 0x0303;

pub struct TlsRecord<'a> {
    pub content_type: u8,
    pub data: &'a [u8],
}

pub fn parse_tls_records(data: &[u8]) -> Vec<TlsRecord<'_>> {
    let mut records = Vec::new();
    let mut offset = 0;
    while offset + 5 <= data.len() {
        let content_type = data[offset];
        let version = u16::from_be_bytes([data[offset + 1], data[offset + 2]]);
        if version != EXPECTED_TLS_VERSION {
            break;
        }
        let length = u16::from_be_bytes([data[offset + 3], data[offset + 4]]) as usize;
        if offset + 5 + length > data.len() {
            break;
        }
        records.push(TlsRecord {
            content_type,
            data: &data[offset + 5..offset + 5 + length],
        });
        offset += 5 + length;
    }
    records
}
