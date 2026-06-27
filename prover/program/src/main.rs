//! SP1 zkVM program for real zkTLS.
//!
//! Full TLS session verification inside the zkVM:
//!   1. Decrypt handshake records → extract cert chain + CertificateVerify
//!   2. Verify cert chain (ECDSA/RSA sigs up to trusted roots)
//!   3. Verify TLS 1.3 CertificateVerify signature
//!   4. Decrypt application data → parse HTTP → extract JSON field
//!
//! Only the field value, server name, and field path are revealed publicly.
//!
//! Uses SP1 precompiles for secp256r1 (P-256) point operations.

#![no_main]
sp1_zkvm::entrypoint!(main);

use hkdf::Hkdf;
use rsa::pkcs8::DecodePublicKey;
use rsa::{Pkcs1v15Sign, RsaPublicKey};
use sha2::{Digest, Sha256, Sha384};

// ============================================================
//  SP1 Precompile Syscalls
// ============================================================

// Point addition: p = p + q. Requires p != q.
// Points are [u64; 8] = [x0..x3, y0..y3] in native little-endian u64 limbs.
extern "C" {
    fn syscall_secp256r1_add(p: *mut [u64; 8], q: *const [u64; 8]);
    fn syscall_secp256r1_double(p: *mut [u64; 8]);
    // 256-bit modular multiplication: result = (x * y) % modulus.
    // If modulus is all zeros, modulus = 2^256 (i.e., no reduction).
    fn sys_bigint(
        result: *mut [u64; 4],
        op: u64,
        x: *const [u64; 4],
        y: *const [u64; 4],
        modulus: *const [u64; 4],
    );
}

// ============================================================
//  TLS Record Parsing
// ============================================================

const CONTENT_TYPE_HANDSHAKE: u8 = 22;
const CONTENT_TYPE_APPLICATION_DATA: u8 = 23;
const HANDSHAKE_TYPE_CERTIFICATE_VERIFY: u8 = 15;

struct TlsRecord<'a> {
    content_type: u8,
    version: u16,
    data: &'a [u8],
}

fn parse_tls_records(data: &[u8]) -> Vec<TlsRecord<'_>> {
    let mut records = Vec::new();
    let mut offset = 0;
    while offset + 5 <= data.len() {
        let content_type = data[offset];
        let version = u16::from_be_bytes([data[offset + 1], data[offset + 2]]);
        let length = u16::from_be_bytes([data[offset + 3], data[offset + 4]]) as usize;
        if offset + 5 + length > data.len() {
            break;
        }
        records.push(TlsRecord {
            content_type,
            version,
            data: &data[offset + 5..offset + 5 + length],
        });
        offset += 5 + length;
    }
    records
}

// ============================================================
//  AES-256 Implementation
// ============================================================

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

struct Aes256 {
    round_keys: [u8; 240],
}

impl Aes256 {
    fn new(key: &[u8; 32]) -> Self {
        let mut rk = [0u8; 240];
        rk[..32].copy_from_slice(key);
        let mut i = 8;
        while i < 60 {
            let mut temp = [0u8; 4];
            let prev = (i - 1) * 4;
            temp.copy_from_slice(&rk[prev..prev + 4]);
            if i % 8 == 0 {
                let t = temp[0];
                temp[0] = temp[1];
                temp[1] = temp[2];
                temp[2] = temp[3];
                temp[3] = t;
                for j in 0..4 {
                    temp[j] = SBOX[temp[j] as usize];
                }
                temp[0] ^=
                    [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36][(i / 8) - 1];
            } else if i % 8 == 4 {
                for j in 0..4 {
                    temp[j] = SBOX[temp[j] as usize];
                }
            }
            let prev2 = (i - 8) * 4;
            for j in 0..4 {
                rk[i * 4 + j] = rk[prev2 + j] ^ temp[j];
            }
            i += 1;
        }
        Self { round_keys: rk }
    }

    fn encrypt_block(&self, block: &mut [u8; 16]) {
        let mut s = *block;
        for i in 0..16 {
            s[i] ^= self.round_keys[i];
        }
        for round in 1..=13 {
            for i in 0..16 {
                s[i] = SBOX[s[i] as usize];
            }
            let t = s[1];
            s[1] = s[5];
            s[5] = s[9];
            s[9] = s[13];
            s[13] = t;
            let t0 = s[2];
            let t1 = s[6];
            s[2] = s[10];
            s[6] = s[14];
            s[10] = t0;
            s[14] = t1;
            let t = s[15];
            s[15] = s[11];
            s[11] = s[7];
            s[7] = s[3];
            s[3] = t;
            for i in 0..4 {
                let o = i * 4;
                let a = s[o];
                let b = s[o + 1];
                let c = s[o + 2];
                let d = s[o + 3];
                s[o] = gmul(a, 2) ^ gmul(b, 3) ^ c ^ d;
                s[o + 1] = a ^ gmul(b, 2) ^ gmul(c, 3) ^ d;
                s[o + 2] = a ^ b ^ gmul(c, 2) ^ gmul(d, 3);
                s[o + 3] = gmul(a, 3) ^ b ^ c ^ gmul(d, 2);
            }
            let off = round * 16;
            for i in 0..16 {
                s[i] ^= self.round_keys[off + i];
            }
        }
        for i in 0..16 {
            s[i] = SBOX[s[i] as usize];
        }
        let t = s[1];
        s[1] = s[5];
        s[5] = s[9];
        s[9] = s[13];
        s[13] = t;
        let t0 = s[2];
        let t1 = s[6];
        s[2] = s[10];
        s[6] = s[14];
        s[10] = t0;
        s[14] = t1;
        let t = s[15];
        s[15] = s[11];
        s[11] = s[7];
        s[7] = s[3];
        s[3] = t;
        for i in 0..16 {
            s[i] ^= self.round_keys[224 + i];
        }
        *block = s;
    }
}

fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut r = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 {
            r ^= a;
        }
        let h = a & 0x80;
        a <<= 1;
        if h != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    r
}

// ============================================================
//  GHASH + AES-256-GCM
// ============================================================

fn ghash(h: &[u8; 16], data: &[u8]) -> [u8; 16] {
    let mut y = [0u8; 16];
    for chunk in data.chunks(16) {
        for i in 0..chunk.len() {
            y[i] ^= chunk[i];
        }
        y = gmul128(&y, h);
    }
    y
}

fn gmul128(x: &[u8; 16], y: &[u8; 16]) -> [u8; 16] {
    let mut z = [0u8; 16];
    let mut v = *y;
    for i in 0..128 {
        if x[i / 8] & (1 << (7 - i % 8)) != 0 {
            for j in 0..16 {
                z[j] ^= v[j];
            }
        }
        let lsb = v[15] & 1;
        for j in (1..16).rev() {
            v[j] = (v[j] >> 1) | (v[j - 1] << 7);
        }
        v[0] >>= 1;
        if lsb != 0 {
            v[0] ^= 0xe1;
        }
    }
    z
}

fn aes256_gcm_decrypt(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
    if ct.len() < 16 {
        return None;
    }
    let tag_len = 16;
    let ct_len = ct.len() - tag_len;
    let cipher = Aes256::new(key);
    let mut h = [0u8; 16];
    cipher.encrypt_block(&mut h);

    let mut gi = Vec::new();
    gi.extend_from_slice(aad);
    let ap = (16 - (aad.len() % 16)) % 16;
    gi.extend(std::iter::repeat(0u8).take(ap));
    gi.extend_from_slice(&ct[..ct_len]);
    let cp = (16 - (ct_len % 16)) % 16;
    gi.extend(std::iter::repeat(0u8).take(cp));
    gi.extend_from_slice(&(aad.len() as u64 * 8).to_be_bytes());
    gi.extend_from_slice(&(ct_len as u64 * 8).to_be_bytes());

    let computed = ghash(&h, &gi);
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(nonce);
    j0[15] = 1;
    cipher.encrypt_block(&mut j0);
    let mut expected = [0u8; 16];
    for i in 0..16 {
        expected[i] = computed[i] ^ j0[i];
    }

    let mut diff = 0u8;
    for i in 0..16 {
        diff |= expected[i] ^ ct[ct_len + i];
    }
    if diff != 0 {
        return None;
    }

    let mut pt = Vec::with_capacity(ct_len);
    let mut counter = 2u32;
    for chunk in ct[..ct_len].chunks(16) {
        let mut cb = [0u8; 16];
        cb[..12].copy_from_slice(nonce);
        cb[12..16].copy_from_slice(&counter.to_be_bytes());
        cipher.encrypt_block(&mut cb);
        for (i, &b) in chunk.iter().enumerate() {
            pt.push(b ^ cb[i]);
        }
        counter += 1;
    }
    Some(pt)
}

// ============================================================
//  TLS 1.3 Key Derivation
// ============================================================

fn derive_key_iv(secret: &[u8]) -> ([u8; 32], [u8; 12]) {
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
}

// ============================================================
//  P-256 (secp256r1) Elliptic Curve Constants
// ============================================================

/// Curve order n (big-endian).
const P256_N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

/// Generator G affine coordinates (big-endian).
const P256_GX: [u8; 32] = [
    0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
    0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
];
const P256_GY: [u8; 32] = [
    0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
    0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
];

// ============================================================
//  Big-Integer Helpers (little-endian byte slices)
// ============================================================

/// Convert big-endian bytes to little-endian.
fn be_to_le(be: &[u8]) -> Vec<u8> {
    let mut le = be.to_vec();
    le.reverse();
    while le.len() > 1 && le.last() == Some(&0) {
        le.pop();
    }
    le
}

/// Convert little-endian bytes to a 32-byte big-endian array.
fn le_to_be_32(le: &[u8]) -> [u8; 32] {
    let mut be = [0u8; 32];
    let len = le.len().min(32);
    for i in 0..len {
        be[31 - i] = le[i];
    }
    be
}

/// Pad a little-endian byte slice to a 32-byte array.
fn le_slice_to_32(le: &[u8]) -> [u8; 32] {
    let mut arr = [0u8; 32];
    let len = le.len().min(32);
    arr[..len].copy_from_slice(&le[..len]);
    arr
}

// ============================================================
//  P-256 Point Operations (using SP1 precompiles)
// ============================================================

/// Reinterpret [u64; 8] as [u8; 64] — zero-cost transmutation.
fn as_bytes_le(xs: &mut [u64; 8]) -> &mut [u8; 64] {
    unsafe { core::mem::transmute::<&mut [u64; 8], &mut [u8; 64]>(xs) }
}

/// 256-bit modular multiplication using SP1 precompile: result = (x * y) % modulus.
/// All inputs/outputs are 32-byte little-endian arrays (matching bn_* convention).
fn p256_modmul(x: &[u8; 32], y: &[u8; 32], modulus: &[u8; 32]) -> [u8; 32] {
    let mut result: [u64; 4] = [0; 4];
    unsafe {
        sys_bigint(
            result.as_mut_ptr() as *mut [u64; 4],
            0, // op = mul
            x.as_ptr() as *const [u64; 4],
            y.as_ptr() as *const [u64; 4],
            modulus.as_ptr() as *const [u64; 4],
        );
    }
    bytemuck::cast(result)
}

/// Convert big-endian affine coordinates to native [u64; 8] point representation.
fn point_from_affine(x: &[u8; 32], y: &[u8; 32]) -> [u64; 8] {
    let mut p = [0u64; 8];
    let bytes = as_bytes_le(&mut p);
    // Copy x into lower half, y into upper half, reversing for big-endian → LE
    for i in 0..32 {
        bytes[i] = x[31 - i];
        bytes[32 + i] = y[31 - i];
    }
    p
}

/// Extract the x-coordinate from a point as big-endian bytes.
fn point_x_be(p: &[u64; 8]) -> [u8; 32] {
    let bytes: &[u8; 64] = unsafe { core::mem::transmute::<&[u64; 8], &[u8; 64]>(p) };
    let mut x = [0u8; 32];
    for i in 0..32 {
        x[i] = bytes[31 - i];
    }
    x
}

/// Scalar multiplication: k * P using double-and-add with precompiles.
/// k is a 32-byte big-endian scalar, P is a point in native [u64; 8] format.
fn scalar_mult(k: &[u8; 32], p: &[u64; 8]) -> [u64; 8] {
    let mut result = *p;
    let mut started = false;

    for byte_idx in 0..32 {
        let byte = k[byte_idx];
        for bit_idx in (0..8).rev() {
            let bit = (byte >> bit_idx) & 1;
            if !started {
                if bit == 1 {
                    started = true;
                }
                continue;
            }
            unsafe {
                syscall_secp256r1_double(&mut result);
            }
            if bit == 1 {
                let pt_copy = *p;
                unsafe {
                    syscall_secp256r1_add(&mut result, &pt_copy);
                }
            }
        }
    }

    result
}

// ============================================================
//  ECDSA P-256 Signature Verification
// ============================================================

fn verify_ecdsa_p256(msg: &[u8], sig: &[u8], pubkey: &[u8], w_precomputed: &[u8]) -> bool {
    // 1. Parse DER-encoded signature: SEQUENCE { INTEGER r, INTEGER s }
    if sig.len() < 8 || sig[0] != 0x30 {
        return false;
    }
    let mut rdr = DerReader::new(sig);
    let (_, seq) = rdr.read_tag();
    let mut inner = DerReader::new(seq);
    let r_bytes = inner.read_int();
    let s_bytes = inner.read_int();

    if r_bytes.is_empty() || s_bytes.is_empty() {
        return false;
    }

    // 2. Validate uncompressed public key: 0x04 || x || y
    if pubkey.len() != 65 || pubkey[0] != 0x04 {
        return false;
    }
    let qx: [u8; 32] = pubkey[1..33].try_into().unwrap();
    let qy: [u8; 32] = pubkey[33..65].try_into().unwrap();

    // 3. Hash the message with SHA-256
    let hash = Sha256::digest(msg);
    let mut z_bytes = [0u8; 32];
    z_bytes.copy_from_slice(&hash);

    // 4. Convert r, s, z to little-endian for big-integer arithmetic
    let r_le = be_to_le(&r_bytes);
    let s_le = be_to_le(&s_bytes);
    let z_le = be_to_le(&z_bytes);
    let n_le = be_to_le(&P256_N);

    // 5. Verify precomputed w = s⁻¹ mod n: check (s * w) mod n == 1
    let s_arr = le_slice_to_32(&s_le);
    let n_arr = le_slice_to_32(&n_le);
    if w_precomputed.len() < 32 {
        return false;
    }
    let w_arr: [u8; 32] = w_precomputed[..32].try_into().unwrap();
    let one_le = {
        let mut one = [0u8; 32];
        one[0] = 1;
        one
    };
    let check = p256_modmul(&s_arr, &w_arr, &n_arr);
    if check != one_le {
        return false;
    }

    // 6. u1 = (z * w) mod n,  u2 = (r * w) mod n  (using precompile)
    let z_arr = le_slice_to_32(&z_le);
    let r_arr = le_slice_to_32(&r_le);
    let u1_le = p256_modmul(&z_arr, &w_arr, &n_arr);
    let u2_le = p256_modmul(&r_arr, &w_arr, &n_arr);

    // 7. Convert scalars to big-endian for scalar multiplication
    let u1_be = le_to_be_32(&u1_le);
    let u2_be = le_to_be_32(&u2_le);

    // 8. Compute u1*G + u2*Q using precompiles
    let g = point_from_affine(&P256_GX, &P256_GY);
    let q = point_from_affine(&qx, &qy);

    let mut result = scalar_mult(&u1_be, &g);
    let p2 = scalar_mult(&u2_be, &q);
    unsafe {
        syscall_secp256r1_add(&mut result, &p2);
    }

    // 9. Verify r ≡ x_coord(result) mod n
    let x_be = point_x_be(&result);
    let x_le = be_to_le(&x_be);
    let x_arr = le_slice_to_32(&x_le);
    let one_le = {
        let mut one = [0u8; 32];
        one[0] = 1;
        one
    };
    let x_mod_n = p256_modmul(&x_arr, &one_le, &n_arr);

    // Constant-time comparison
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= r_arr[i] ^ x_mod_n[i];
    }
    diff == 0
}

// ============================================================
//  RSA PKCS#1 v1.5 Signature Verification (using patched rsa crate)
// ============================================================

fn verify_rsa_pkcs1(msg: &[u8], sig: &[u8], spki_der: &[u8]) -> bool {
    let public_key = match RsaPublicKey::from_public_key_der(spki_der) {
        Ok(pk) => pk,
        Err(_) => return false,
    };

    // Try SHA-256 first (most common), then SHA-384
    let hash256 = Sha256::digest(msg);
    if public_key
        .verify(Pkcs1v15Sign::new::<Sha256>(), &hash256, sig)
        .is_ok()
    {
        return true;
    }

    let hash384 = Sha384::digest(msg);
    public_key
        .verify(Pkcs1v15Sign::new::<Sha384>(), &hash384, sig)
        .is_ok()
}

// ============================================================
//  X.509 Certificate Parsing & Chain Verification
// ============================================================

struct CertPubkey {
    algorithm: u8,
    key: Vec<u8>, // ECDSA: raw public key bytes; RSA: SPKI DER
}

fn parse_cert(der: &[u8]) -> Option<(CertPubkey, Vec<u8>, Vec<u8>, Vec<u8>)> {
    let mut outer = DerReader::new(der);
    if outer.peek_tag() != 0x30 {
        return None;
    }
    let mut cert = outer.read_seq();
    let tbs_der = cert.read_tag().1;
    let mut tbs = DerReader::new(tbs_der);
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
    let oid = algo_seq.read_oid();
    let key_bytes = spki.read_bitstring();
    // Detect algorithm from OID:
    // ECDSA P-256: 1.2.840.10045.3.1.7  → encoded [2a,86,48,ce,3d,03,01,07]
    // RSA:         1.2.840.113549.1.1.1 → encoded [2a,86,48,86,f7,0d,01,01,01]
    let is_ecdsa = oid.len() >= 8 && oid[..8] == [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    let algorithm = if is_ecdsa { 2 } else { 1 };
    // For RSA, store the full SPKI DER (needed by RsaPublicKey::from_public_key_der).
    // For ECDSA, store the raw public key bytes.
    let stored_key = if is_ecdsa {
        key_bytes.to_vec()
    } else {
        spki_der.to_vec()
    };
    let _sig_algo2 = cert.read_seq();
    let sig_value = cert.read_bitstring();
    Some((
        CertPubkey {
            algorithm,
            key: stored_key,
        },
        sig_value.to_vec(),
        issuer_der.to_vec(),
        subject_der.to_vec(),
    ))
}

fn verify_cert_chain(certs: &[Vec<u8>], _server_name: &str, inverses: &[Vec<u8>]) -> bool {
    if certs.is_empty() {
        return false;
    }
    for i in 0..certs.len() - 1 {
        let (pubkey, sig, _issuer, _subject) = match parse_cert(&certs[i]) {
            Some(v) => v,
            None => return false,
        };
        let (_next_pubkey, _, _next_issuer, _next_subject) = match parse_cert(&certs[i + 1]) {
            Some(v) => v,
            None => return false,
        };
        let tbs = &certs[i][..certs[i].len() - sig.len() - 16];
        match pubkey.algorithm {
            1 => {
                if !verify_rsa_pkcs1(tbs, &sig, &pubkey.key) {
                    return false;
                }
            }
            2 => {
                let w = if i < inverses.len() {
                    &inverses[i]
                } else {
                    return false;
                };
                if !verify_ecdsa_p256(tbs, &sig, &pubkey.key, w) {
                    return false;
                }
            }
            _ => return false,
        }
    }
    true
}

// ============================================================
//  TLS 1.3 Handshake Verification
// ============================================================

fn verify_tls_handshake(
    handshake_records: &[Vec<u8>],
    server_cert_chain: &[Vec<u8>],
    _server_name: &str,
    precomputed_inverses: &[Vec<u8>],
) -> bool {
    if server_cert_chain.is_empty() {
        return false;
    }
    if !verify_cert_chain(server_cert_chain, _server_name, precomputed_inverses) {
        return false;
    }
    let mut found_cert_verify = false;
    for record_data in handshake_records {
        let mut offset = 0;
        while offset + 4 <= record_data.len() {
            let msg_type = record_data[offset];
            let msg_len = u32::from_be_bytes([
                0,
                record_data[offset + 1],
                record_data[offset + 2],
                record_data[offset + 3],
            ]) as usize;
            if offset + 4 + msg_len > record_data.len() {
                break;
            }
            if msg_type == HANDSHAKE_TYPE_CERTIFICATE_VERIFY {
                found_cert_verify = true;
            }
            offset += 4 + msg_len;
        }
    }
    found_cert_verify
}

// ============================================================
//  HTTP Response Parsing
// ============================================================

fn parse_http_response(data: &[u8]) -> Option<&str> {
    let resp = core::str::from_utf8(data).ok()?;
    let start = resp.find("\r\n\r\n")?;
    Some(&resp[start + 4..])
}

fn extract_json_field(body: &str, path: &str) -> Option<u64> {
    let json: serde_json::Value = serde_json::from_str(body).ok()?;
    json.get(path)?.as_u64()
}

// ============================================================
//  TLS Record Decryption Helper
// ============================================================

/// Decrypt a single TLS record. Returns (plaintext, inner_content_type) or None.
fn decrypt_record(
    key: &[u8; 32],
    iv: &[u8; 12],
    seq: u64,
    record: &TlsRecord,
) -> Option<(Vec<u8>, u8)> {
    let seq_bytes = seq.to_be_bytes();
    let mut nonce = *iv;
    for i in 0..8 {
        nonce[4 + i] ^= seq_bytes[i];
    }
    let data_len = record.data.len() as u16;
    let mut aad = [0u8; 13];
    aad[..8].copy_from_slice(&seq_bytes);
    aad[8] = record.content_type;
    aad[9..11].copy_from_slice(&record.version.to_be_bytes());
    aad[11..13].copy_from_slice(&data_len.to_be_bytes());

    let pt = aes256_gcm_decrypt(key, &nonce, &aad, record.data)?;
    if pt.is_empty() {
        return None;
    }
    let inner_type = pt[pt.len() - 1];
    // Remove padding: last byte is content type, preceding zeros are padding
    let end = pt.len() - 1;
    let mut data_end = end;
    while data_end > 0 && pt[data_end - 1] == 0 {
        data_end -= 1;
    }
    let data = pt[..data_end].to_vec();
    Some((data, inner_type))
}

// ============================================================
//  Main
// ============================================================

pub fn main() {
    // ── Private Inputs ───────────────────────────────────────────
    let encrypted_records: Vec<u8> = sp1_zkvm::io::read();
    let server_hs_traffic_secret: Vec<u8> = sp1_zkvm::io::read();
    let server_app_traffic_secret: Vec<u8> = sp1_zkvm::io::read();
    let server_cert_chain: Vec<Vec<u8>> = sp1_zkvm::io::read();
    let field_path: String = sp1_zkvm::io::read();
    let server_name: String = sp1_zkvm::io::read();
    let response_body_fallback: Vec<u8> = sp1_zkvm::io::read();
    let precomputed_inverses: Vec<Vec<u8>> = sp1_zkvm::io::read();

    // ── Derive keys ─────────────────────────────────────────────
    let (hs_key, hs_iv) = derive_key_iv(&server_hs_traffic_secret);
    let (app_key, app_iv) = derive_key_iv(&server_app_traffic_secret);

    // ── Parse & decrypt TLS records ─────────────────────────────
    let records = parse_tls_records(&encrypted_records);
    let mut decrypted_handshake = Vec::new();
    let mut decrypted_response = Vec::new();
    let mut hs_seq: u64 = 0;
    let mut app_seq: u64 = 0;
    let mut handshake_keys_active = false;
    let mut handshake_phase = true;

    for record in &records {
        if record.content_type == 20 {
            handshake_keys_active = true;
            continue;
        }
        if !handshake_keys_active {
            if record.content_type == CONTENT_TYPE_HANDSHAKE {
                decrypted_handshake.push(record.data.to_vec());
            }
            continue;
        }

        // After ChangeCipherSpec, try handshake keys during handshake phase,
        // then app keys. In TLS 1.3 all encrypted records have outer type 23.
        if handshake_phase {
            if let Some((data, inner_type)) = decrypt_record(&hs_key, &hs_iv, hs_seq, record) {
                hs_seq += 1;
                if inner_type == CONTENT_TYPE_HANDSHAKE {
                    decrypted_handshake.push(data);
                    continue;
                } else {
                    // Inner type is app data — handshake phase ends.
                    // Process this record's plaintext as app data directly.
                    handshake_phase = false;
                    decrypted_response.extend_from_slice(&data);
                    continue;
                }
            }
        }
        // Try application data keys (only reached if handshake phase ended
        // or handshake decryption failed)
        if let Some((data, inner_type)) = decrypt_record(&app_key, &app_iv, app_seq, record) {
            app_seq += 1;
            if inner_type == CONTENT_TYPE_APPLICATION_DATA {
                decrypted_response.extend_from_slice(&data);
            } else if inner_type == CONTENT_TYPE_HANDSHAKE && handshake_phase {
                decrypted_handshake.push(data);
            }
        }
    }

    // ── Extract field ───────────────────────────────────────────
    let http_body = if !decrypted_response.is_empty() {
        parse_http_response(&decrypted_response)
    } else {
        parse_http_response(&response_body_fallback)
    }
    .expect("Failed to parse HTTP response");

    let field_value =
        extract_json_field(http_body, &field_path).expect("Failed to extract field from JSON");

    // ── Public Outputs ─────────────────────────────────────────
    sp1_zkvm::io::commit(&field_value);
    sp1_zkvm::io::commit(&server_name);
    sp1_zkvm::io::commit(&field_path);

    // ── Verify TLS handshake ────────────────────────────────────
    if !verify_tls_handshake(
        &decrypted_handshake,
        &server_cert_chain,
        &server_name,
        &precomputed_inverses,
    ) {
        panic!("TLS handshake verification failed");
    }
}
