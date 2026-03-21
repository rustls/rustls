mod buffers;
pub(crate) use buffers::{Delocator, Locator, TlsInputBuffer, VecInput};

mod handshake;
pub(crate) use handshake::{Deframed, Deframer, HandshakeAlignedProof};

pub fn fuzz_deframer(data: &[u8]) {
    let mut buf = data.to_vec();
    let mut deframer = Deframer::default();
    while let Some(result) = deframer.deframe(&mut buf) {
        if result.is_err() {
            break;
        }
    }

    assert!(deframer.processed() <= buf.len());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exercise_fuzz_deframer() {
        fuzz_deframer(&[0xff, 0xff, 0xff, 0xff, 0xff]);
        for prefix in 0..7 {
            fuzz_deframer(&[0x16, 0x03, 0x03, 0x00, 0x01, 0xff][..prefix]);
        }
    }
}
