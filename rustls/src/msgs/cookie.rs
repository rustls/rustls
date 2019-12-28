#[derive(Copy)]
pub struct Cookie {
    len: usize,
    data: [u8; 255],
}

impl Clone for Cookie {
    fn clone(&self) -> Self {
        Cookie {
            data: self.data,
            len: self.len,
        }
    }
}

impl Codec for Cookie {
    fn encode(&self, bytes: &mut Vec<u8>) {
        debug_assert!(self.len <= self.data.len());
        bytes.push(self.len as u8);
        bytes.extend_from_slice(&self.data[..self.len]);
    }

    fn read(r: &mut Reader) -> Option<Cookie> {
        let len = codec::read_u8(r).unwrap() as usize;
        if len > 255 {
            return None;
        }

        let bytes = r.take(len).unwrap();
        let mut out = [0u8; 255];
        for i in 0..len {
            out[i] = bytes[i];
        }

        Some(Cookie {
            data: out,
            len: len,
        })
    }
}

impl PartialEq for Cookie {
    fn eq(&self, other: &Self) -> bool {
        if self.len != other.len {
            return false;
        }

        let l = self.len as usize;
        let mut diff = 0u8;
        for i in 0..l {
            diff |= self.data[i] ^ other.data[i]
        }

        diff == 0u8
    }
}

impl Cookie {
    pub fn new(bytes: &[u8]) -> Cookie {
        debug_assert!(bytes.len() <= 255);
        let mut d = [0u8; 255];
        for i in 0..bytes.len() {
            d[i] = bytes[i];
        }
        Cookie {
            data: d,
            len: bytes.len(),
        }
    }

    pub fn empty() -> Cookie {
        Cookie {
            data: [0u8; 255],
            len: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}