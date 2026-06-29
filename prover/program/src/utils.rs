// ============================================================
//  HTTP Response Parsing
// ============================================================

use hkdf::Hkdf;
use sha2::Sha384;

pub fn parse_http_response(data: &[u8]) -> Option<&str> {
    let resp = core::str::from_utf8(data).ok()?;
    let start = resp.find("\r\n\r\n")?;
    Some(&resp[start + 4..])
}

pub fn extract_json_field(body: &str, path: &str) -> Option<u64> {
    let json: serde_json::Value = serde_json::from_str(body).ok()?;
    json.get(path)?.as_u64()
}

// ============================================================
//  X.509 Certificate Parsing & Chain Verification
// ============================================================

pub struct CertPubkey {
    pub point: [u8; 64], // 32-byte x || 32-byte y (big-endian)
}

pub fn parse_cert(der: &[u8]) -> Option<(CertPubkey, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> {
    let mut outer = DerReader::new(der);
    if outer.peek_tag() != 0x30 {
        return None;
    }
    let mut cert = outer.read_seq();
    let tbs_der = cert.read_tlv();
    let mut tbs = DerReader::new(tbs_der);
    // Skip the outer TBS SEQUENCE tag+length to get to the contents
    let mut tbs = tbs.read_seq();
    if tbs.peek_tag() == 0xa0 {
        tbs.read_explicit_tag(0xa0);
    }
    let _serial = tbs.read_int();
    let _sig_algo = tbs.read_seq();
    let issuer_der = tbs.read_tag().1;
    let _validity = tbs.read_tag();
    let subject_der = tbs.read_tag().1;
    let spki_der = tbs.read_tag().1;
    let mut spki = DerReader::new(spki_der);
    let mut algo_seq = spki.read_seq();
    let _oid = algo_seq.read_oid();
    // Extract the public key point from the BITSTRING
    // The BITSTRING contains: 0x04 || x (32 bytes) || y (32 bytes)
    let point_bits = spki.read_bitstring();
    // P-256 uncompressed point is exactly 65 bytes: 0x04 || x (32) || y (32)
    if point_bits.len() != 65 || point_bits[0] != 0x04 {
        return None;
    }
    let mut point = [0u8; 64];
    point[..32].copy_from_slice(&point_bits[1..33]);
    point[32..].copy_from_slice(&point_bits[33..65]);
    let _sig_algo2 = cert.read_seq();
    let sig_value = cert.read_bitstring();
    Some((
        CertPubkey { point },
        sig_value.to_vec(),
        issuer_der.to_vec(),
        subject_der.to_vec(),
        tbs_der.to_vec(),
    ))
}

// ============================================================
//  ASN.1 DER Parser
// ============================================================

struct DerReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> DerReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
    fn peek_tag(&self) -> u8 {
        self.data[self.pos]
    }
    fn read_tag(&mut self) -> (u8, &'a [u8]) {
        let tag = self.data[self.pos];
        self.pos += 1;
        let len = if self.data[self.pos] & 0x80 != 0 {
            let n = (self.data[self.pos] & 0x7f) as usize;
            self.pos += 1;
            let mut l = 0usize;
            for _ in 0..n {
                l = (l << 8) | self.data[self.pos] as usize;
                self.pos += 1;
            }
            l
        } else {
            let l = self.data[self.pos] as usize;
            self.pos += 1;
            l
        };
        let val = &self.data[self.pos..self.pos + len];
        self.pos += len;
        (tag, val)
    }
    fn read_seq(&mut self) -> Self {
        let (_, v) = self.read_tag();
        Self::new(v)
    }
    fn read_int(&mut self) -> &'a [u8] {
        let (_, v) = self.read_tag();
        v
    }
    fn read_bitstring(&mut self) -> &'a [u8] {
        let (_, v) = self.read_tag();
        if v[0] == 0 {
            &v[1..]
        } else {
            v
        }
    }
    fn read_oid(&mut self) -> &'a [u8] {
        let (_, v) = self.read_tag();
        v
    }
    fn read_explicit_tag(&mut self, expected: u8) -> Self {
        let (tag, v) = self.read_tag();
        if tag == expected {
            Self::new(v)
        } else {
            Self::new(&[])
        }
    }
    /// Read a TLV (tag, length, value) and return the full slice including tag and length.
    fn read_tlv(&mut self) -> &'a [u8] {
        let start = self.pos;
        self.read_tag();
        &self.data[start..self.pos]
    }
}

// ============================================================
//  TLS 1.3 Key Derivation
// ============================================================

pub fn derive_key_iv(secret: &[u8]) -> ([u8; 32], [u8; 12]) {
    // TLS 1.3 AES-256-GCM uses SHA-384 for HKDF (ciphersuite TLS13_AES_256_GCM_SHA384).
    // The traffic secret from the key log is already a PRK; use it directly.
    let hkdf = Hkdf::<Sha384>::from_prk(secret).expect("invalid PRK length");
    let mut key = [0u8; 32];
    let mut iv = [0u8; 12];
    // Note: hkdflabel adds the "tls13 " prefix, so pass just "key" and "iv"
    hkdf.expand(&hkdflabel(b"key", b"", 32), &mut key).unwrap();
    hkdf.expand(&hkdflabel(b"iv", b"", 12), &mut iv).unwrap();
    (key, iv)
}

fn hkdflabel(label: &[u8], ctx: &[u8], len: u16) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&len.to_be_bytes());
    let f = [b"tls13 ", label].concat();
    v.push(f.len() as u8);
    v.extend_from_slice(&f);
    v.push(ctx.len() as u8);
    v.extend_from_slice(ctx);
    v
}
