use std::io;
use rustc_serialize::base64::FromBase64;

static START_MARKER: &'static str = "-----BEGIN CERTIFICATE-----";
static END_MARKER: &'static str = "-----END CERTIFICATE-----";

/// Extract all the certificates from rd, and return a vec of bytevecs
/// containing the der-format contents.
pub fn certs(rd: &mut io::BufRead) -> Result<Vec<Vec<u8>>, ()> {
  let mut ders = Vec::new();
  let mut b64buf = String::new();
  let mut take_base64 = false;

  loop {
    let mut line = String::new();
    let len = try!(rd.read_line(&mut line)
                   .map_err(|_| ()));

    if len == 0 {
      return Ok(ders);
    }

    if line.starts_with(START_MARKER) {
      take_base64 = true;
      continue;
    }

    if line.starts_with(END_MARKER) {
      take_base64 = false;
      let der = try!(b64buf.from_base64()
                     .map_err(|_| ()));
      ders.push(der);
      b64buf = String::new();
      continue;
    }

    if take_base64 {
      b64buf.push_str(&line.trim());
    }
  }
}
