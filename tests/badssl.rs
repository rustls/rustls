/*
 * These tests use the various test servers run by Google
 * at badssl.com.  To be polite they sleep 1 second before
 * each test.
 */

use std::process;

struct SClientTest {
  hostname: String,
  expect_fails: bool,
  expect_output: Option<String>
}

fn connect(hostname: &str) -> SClientTest {
  SClientTest {
    hostname: hostname.to_string(),
    expect_fails: false,
    expect_output: None
  }
}

impl SClientTest {
  fn expect(&mut self, expect: &str) -> &mut SClientTest {
    self.expect_output = Some(expect.to_string());
    self
  }

  fn fails(&mut self) -> &mut SClientTest {
    self.expect_fails = true;
    self
  }

  fn go(&mut self) -> Option<()> {
    println!("cwd {:?}",
             process::Command::new("pwd")
             .output()
             .unwrap());

    let output = process::Command::new("target/debug/examples/s_client")
      .arg("--http")
      .arg(&self.hostname)
      .output()
      .unwrap_or_else(|e| { panic!("failed to execute: {}", e) });

    if self.expect_fails {
      assert!(output.status.code().unwrap() != 0);
    } else {
      assert!(output.status.success());
    }

    let stdout_str = String::from_utf8(output.stdout.clone()).unwrap();

    if self.expect_output.is_some() && stdout_str.find(self.expect_output.as_ref().unwrap()).is_none() {
      println!("We expected to find '{}' in the following output:", self.expect_output.as_ref().unwrap());
      println!("{:?}", output);
      panic!("Test failed");
    }

    Some(())
  }
}

/* For tests which connect to internet servers, don't go crazy. */
fn polite() {
  use std::thread;
  use std::time;

  thread::sleep(time::Duration::from_secs(1));
}

#[test]
fn no_cbc() {
  polite();
  connect("cbc.badssl.com")
    .fails()
    .expect("TLS error: AlertReceived(HandshakeFailure)")
    .go()
    .unwrap();
}

#[test]
fn no_rc4() {
  polite();
  connect("rc4.badssl.com")
    .fails()
    .expect("TLS error: AlertReceived(HandshakeFailure)")
    .go()
    .unwrap();
}

#[test]
fn expired() {
  polite();
  connect("expired.badssl.com")
    .fails()
    .expect("TLS error: WebPKIError(CertExpired)")
    .go()
    .unwrap();
}

#[test]
fn wrong_host() {
  polite();
  connect("wrong.host.badssl.com")
    .fails()
    .expect("TLS error: WebPKIError(CertNotValidForName)")
    .go()
    .unwrap();
}

#[test]
fn self_signed() {
  polite();
  connect("self-signed.badssl.com")
    .fails()
    .expect("TLS error: WebPKIError(UnknownIssuer)")
    .go()
    .unwrap();
}

#[test]
fn no_dh() {
  polite();
  connect("dh2048.badssl.com")
    .fails()
    .expect("TLS error: AlertReceived(HandshakeFailure)")
    .go()
    .unwrap();
}

#[test]
fn mozilla_old() {
  polite();
  connect("mozilla-old.badssl.com")
    .expect("<title>mozilla-old.badssl.com</title>")
    .go()
    .unwrap();
}

#[test]
fn mozilla_inter() {
  polite();
  connect("mozilla-intermediate.badssl.com")
    .expect("<title>mozilla-intermediate.badssl.com</title>")
    .go()
    .unwrap();
}

#[test]
fn mozilla_modern() {
  polite();
  connect("mozilla-modern.badssl.com")
    .expect("<title>mozilla-modern.badssl.com</title>")
    .go()
    .unwrap();
}

#[test]
fn sha256() {
  polite();
  connect("sha256.badssl.com")
    .expect("<title>sha256.badssl.com</title>")
    .go()
    .unwrap();
}

#[test]
fn many_sans() {
  /* This exercises webpki, but also handshake reassembly. */
  polite();
  connect("1000-sans.badssl.com")
    .expect("<title>1000-sans.badssl.com</title>")
    .go()
    .unwrap();
}

#[test]
fn too_many_sans() {
  polite();
  connect("10000-sans.badssl.com")
    .fails()
    .expect("TLS error: WebPKIError(BadDER)")
    .go()
    .unwrap();
}

#[test]
fn rsa8192() {
  polite();
  connect("rsa8192.badssl.com")
    .expect("<title>rsa8192.badssl.com</title>")
    .go()
    .unwrap();
}

#[test]
fn sha1_2016() {
  polite();
  connect("sha1-2016.badssl.com")
    .expect("<title>sha1-2016.badssl.com</title>")
    .go()
    .unwrap();
}
