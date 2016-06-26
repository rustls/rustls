use std::io;
use rustc_serialize::base64::FromBase64;

fn extract(rd: &mut io::BufRead,
           start_mark: &str,
           end_mark: &str) -> Result<Vec<Vec<u8>>, ()> {
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

    if line.starts_with(start_mark) {
      take_base64 = true;
      continue;
    }

    if line.starts_with(end_mark) {
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

/// Extract all the certificates from rd, and return a vec of bytevecs
/// containing the der-format contents.
pub fn certs(rd: &mut io::BufRead) -> Result<Vec<Vec<u8>>, ()> {
  extract(rd,
          "-----BEGIN CERTIFICATE-----",
          "-----END CERTIFICATE-----")
}

/// Extract all RSA private keys from rd, and return a vec of bytevecs
/// containing the der-format contents.
pub fn rsa_private_keys(rd: &mut io::BufRead) -> Result<Vec<Vec<u8>>, ()> {
  extract(rd,
          "-----BEGIN RSA PRIVATE KEY-----",
          "-----END RSA PRIVATE KEY-----")
}
