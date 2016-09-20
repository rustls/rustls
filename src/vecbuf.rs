use std::io::Read;
use std::io;

/// This is a byte buffer that is built from a vector
/// of byte vectors.  This avoids extra copies when
/// appending a new byte vector, at the expense of
/// more complexity when reading out.
pub struct ChunkVecBuffer {
  chunks: Vec<Vec<u8>>
}

impl ChunkVecBuffer {
  pub fn new() -> ChunkVecBuffer {
    ChunkVecBuffer {
      chunks: Vec::new()
    }
  }

  pub fn is_empty(&self) -> bool {
    self.chunks.is_empty()
  }

  pub fn append(&mut self, bytes: Vec<u8>) {
    if !bytes.is_empty() {
      self.chunks.push(bytes);
    }
  }

  pub fn take_one(&mut self) -> Vec<u8> {
    self.chunks.remove(0)
  }

  pub fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
    let mut offs = 0;

    while offs < buf.len() && !self.is_empty() {
      let used = try!(self.chunks[0].as_slice().read(&mut buf[offs..]));

      if used == self.chunks[0].len() {
        self.chunks.remove(0);
      } else {
        self.chunks[0] = self.chunks[0].split_off(used);
      }

      offs += used;
    }

    Ok(offs)
  }

  pub fn write_to(&mut self, wr: &mut io::Write) -> io::Result<usize> {
    // would desperately like writev support here!
    if self.is_empty() {
      return Ok(0);
    }

    let used = try!(wr.write(&self.chunks[0]));

    if used == self.chunks[0].len() {
      self.chunks.remove(0);
    } else {
      self.chunks[0] = self.chunks[0].split_off(used);
    }

    return Ok(used);
  }
}
