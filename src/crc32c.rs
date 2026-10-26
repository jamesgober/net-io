//! CRC32C (Castagnoli, reflected polynomial 0x82F63B78), table-driven, for the
//! PROXY v2 checksum TLV.

const fn table() -> [u32; 256] {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                (c >> 1) ^ 0x82F6_3B78
            } else {
                c >> 1
            };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
}

static TABLE: [u32; 256] = table();

/// The running state: start with [`Crc32c::new`], feed with [`Crc32c::update`].
#[derive(Clone, Copy, Debug)]
pub(crate) struct Crc32c(u32);

impl Crc32c {
    pub(crate) const fn new() -> Crc32c {
        Crc32c(!0)
    }

    pub(crate) fn update(&mut self, bytes: &[u8]) {
        let mut c = self.0;
        for &b in bytes {
            c = TABLE[((c ^ u32::from(b)) & 0xFF) as usize] ^ (c >> 8);
        }
        self.0 = c;
    }

    pub(crate) const fn finish(self) -> u32 {
        !self.0
    }
}

/// The checksum of `bytes`.
#[cfg(test)]
pub(crate) fn crc32c(bytes: &[u8]) -> u32 {
    let mut c = Crc32c::new();
    c.update(bytes);
    c.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 3720 appendix B.4 test vectors, and the common check value.
    #[test]
    fn test_crc32c_rfc3720_vectors() {
        assert_eq!(crc32c(&[0u8; 32]), 0x8A91_36AA);
        assert_eq!(crc32c(&[0xFFu8; 32]), 0x62A8_AB43);
        let up: Vec<u8> = (0u8..32).collect();
        assert_eq!(crc32c(&up), 0x46DD_794E);
        let down: Vec<u8> = (0u8..32).rev().collect();
        assert_eq!(crc32c(&down), 0x113F_DB5C);
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
    }

    #[test]
    fn test_crc32c_incremental_equals_whole() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i * 31) as u8).collect();
        let mut c = Crc32c::new();
        for part in data.chunks(7) {
            c.update(part);
        }
        assert_eq!(c.finish(), crc32c(&data));
    }
}
