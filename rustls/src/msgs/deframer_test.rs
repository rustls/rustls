use super::deframer::MessageDeframer;
use crate::msgs;
use std::io;

const FIRST_MESSAGE: &'static [u8] = include_bytes!("../testdata/deframer-test.1.bin");
const SECOND_MESSAGE: &'static [u8] = include_bytes!("../testdata/deframer-test.2.bin");

struct ByteRead<'a> {
    buf: &'a [u8],
    offs: usize,
}

impl<'a> ByteRead<'a> {
    fn new(bytes: &'a [u8]) -> ByteRead {
        ByteRead {
            buf: bytes,
            offs: 0,
        }
    }
}

impl<'a> io::Read for ByteRead<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut len = 0;

        while len < buf.len() && len < self.buf.len() - self.offs {
            buf[len] = self.buf[self.offs + len];
            len += 1;
        }

        self.offs += len;

        Ok(len)
    }
}

fn input_bytes(d: &mut MessageDeframer, bytes: &[u8]) -> io::Result<usize> {
    let mut rd = ByteRead::new(bytes);
    d.read(&mut rd)
}

fn input_bytes_concat(d: &mut MessageDeframer, bytes1: &[u8], bytes2: &[u8]) -> io::Result<usize> {
    let mut bytes = vec![0u8; bytes1.len() + bytes2.len()];
    bytes[..bytes1.len()].clone_from_slice(bytes1);
    bytes[bytes1.len()..].clone_from_slice(bytes2);
    let mut rd = ByteRead::new(&bytes);
    d.read(&mut rd)
}

struct ErrorRead {
    error: Option<io::Error>,
}

impl ErrorRead {
    fn new(error: io::Error) -> ErrorRead {
        ErrorRead { error: Some(error) }
    }
}

impl io::Read for ErrorRead {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        for (i, b) in buf.iter_mut().enumerate() {
            *b = i as u8;
        }

        let error = self.error.take().unwrap();
        Err(error)
    }
}

fn input_error(d: &mut MessageDeframer) {
    let error = io::Error::from(io::ErrorKind::TimedOut);
    let mut rd = ErrorRead::new(error);
    d.read(&mut rd)
        .expect_err("error not propagated");
}

fn input_whole_incremental(d: &mut MessageDeframer, bytes: &[u8]) {
    let frames_before = d.frames.len();

    for i in 0..bytes.len() {
        assert_len(1, input_bytes(d, &bytes[i..i + 1]));
        assert_eq!(d.has_pending(), true);

        if i < bytes.len() - 1 {
            assert_eq!(frames_before, d.frames.len());
        }
    }

    assert_eq!(frames_before + 1, d.frames.len());
}

fn assert_len(want: usize, got: io::Result<usize>) {
    if let Ok(gotval) = got {
        assert_eq!(gotval, want);
    } else {
        assert!(false, "read failed, expected {:?} bytes", want);
    }
}

fn pop_first(d: &mut MessageDeframer) {
    let mut m = d.frames.pop_front().unwrap();
    m.decode_payload();
    assert_eq!(m.typ, msgs::enums::ContentType::Handshake);
}

fn pop_second(d: &mut MessageDeframer) {
    let mut m = d.frames.pop_front().unwrap();
    m.decode_payload();
    assert_eq!(m.typ, msgs::enums::ContentType::Alert);
}

#[test]
fn check_incremental() {
    let mut d = MessageDeframer::new();
    assert_eq!(d.has_pending(), false);
    input_whole_incremental(&mut d, FIRST_MESSAGE);
    assert_eq!(d.has_pending(), true);
    assert_eq!(1, d.frames.len());
    pop_first(&mut d);
    assert_eq!(d.has_pending(), false);
}

#[test]
fn check_incremental_2() {
    let mut d = MessageDeframer::new();
    assert_eq!(d.has_pending(), false);
    input_whole_incremental(&mut d, FIRST_MESSAGE);
    assert_eq!(d.has_pending(), true);
    input_whole_incremental(&mut d, SECOND_MESSAGE);
    assert_eq!(d.has_pending(), true);
    assert_eq!(2, d.frames.len());
    pop_first(&mut d);
    assert_eq!(d.has_pending(), true);
    pop_second(&mut d);
    assert_eq!(d.has_pending(), false);
}

#[test]
fn check_whole() {
    let mut d = MessageDeframer::new();
    assert_eq!(d.has_pending(), false);
    assert_len(FIRST_MESSAGE.len(), input_bytes(&mut d, FIRST_MESSAGE));
    assert_eq!(d.has_pending(), true);
    assert_eq!(d.frames.len(), 1);
    pop_first(&mut d);
    assert_eq!(d.has_pending(), false);
}

#[test]
fn check_whole_2() {
    let mut d = MessageDeframer::new();
    assert_eq!(d.has_pending(), false);
    assert_len(FIRST_MESSAGE.len(), input_bytes(&mut d, FIRST_MESSAGE));
    assert_len(SECOND_MESSAGE.len(), input_bytes(&mut d, SECOND_MESSAGE));
    assert_eq!(d.frames.len(), 2);
    pop_first(&mut d);
    pop_second(&mut d);
    assert_eq!(d.has_pending(), false);
}

#[test]
fn test_two_in_one_read() {
    let mut d = MessageDeframer::new();
    assert_eq!(d.has_pending(), false);
    assert_len(
        FIRST_MESSAGE.len() + SECOND_MESSAGE.len(),
        input_bytes_concat(&mut d, FIRST_MESSAGE, SECOND_MESSAGE),
    );
    assert_eq!(d.frames.len(), 2);
    pop_first(&mut d);
    pop_second(&mut d);
    assert_eq!(d.has_pending(), false);
}

#[test]
fn test_two_in_one_read_shortest_first() {
    let mut d = MessageDeframer::new();
    assert_eq!(d.has_pending(), false);
    assert_len(
        FIRST_MESSAGE.len() + SECOND_MESSAGE.len(),
        input_bytes_concat(&mut d, SECOND_MESSAGE, FIRST_MESSAGE),
    );
    assert_eq!(d.frames.len(), 2);
    pop_second(&mut d);
    pop_first(&mut d);
    assert_eq!(d.has_pending(), false);
}

#[test]
fn test_incremental_with_nonfatal_read_error() {
    let mut d = MessageDeframer::new();
    assert_len(3, input_bytes(&mut d, &FIRST_MESSAGE[..3]));
    input_error(&mut d);
    assert_len(
        FIRST_MESSAGE.len() - 3,
        input_bytes(&mut d, &FIRST_MESSAGE[3..]),
    );
    assert_eq!(d.frames.len(), 1);
    pop_first(&mut d);
    assert_eq!(d.has_pending(), false);
}
