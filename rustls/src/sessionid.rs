#![allow(non_camel_case_types)]
use crate::error::InvalidMessage;
use crate::msgs::codec::{Codec, Reader};
use crate::rand;

use std::fmt;

/// A SessionID value from a [ClientHello].
///
/// [ClientHello]: https://www.rfc-editor.org/rfc/rfc5246#page-41
#[derive(Copy, Clone)]
pub struct SessionId {
    len: usize,
    data: [u8; 32],
}

impl fmt::Debug for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        super::msgs::base::hex(f, &self.data[..self.len])
    }
}

impl PartialEq for SessionId {
    fn eq(&self, other: &Self) -> bool {
        if self.len != other.len {
            return false;
        }

        let mut diff = 0u8;
        for i in 0..self.len {
            diff |= self.data[i] ^ other.data[i];
        }

        diff == 0u8
    }
}

impl Codec for SessionId {
    fn encode(&self, bytes: &mut Vec<u8>) {
        debug_assert!(self.len <= 32);
        bytes.push(self.len as u8);
        bytes.extend_from_slice(&self.data[..self.len]);
    }

    fn read(r: &mut Reader) -> Result<Self, InvalidMessage> {
        let len = u8::read(r)? as usize;
        if len > 32 {
            return Err(InvalidMessage::TrailingData("SessionId"));
        }

        let bytes = match r.take(len) {
            Some(bytes) => bytes,
            None => return Err(InvalidMessage::MissingData("SessionId")),
        };

        let mut out = [0u8; 32];
        out[..len].clone_from_slice(&bytes[..len]);
        Ok(Self { data: out, len })
    }
}

impl SessionId {
    /// Generate a random SessionId.
    pub fn random() -> Result<Self, rand::GetRandomFailed> {
        let mut data = [0u8; 32];
        rand::fill_random(&mut data)?;
        Ok(Self { data, len: 32 })
    }

    /// Create an empty SessionId.
    pub fn empty() -> Self {
        Self {
            data: [0u8; 32],
            len: 0,
        }
    }

    /// Return the length of the SessionId.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns true if the length of the SessionId is zero.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}
