
use std::process;
use std::thread;
use std::time;
use std::net;

/* For tests which connect to internet servers, don't go crazy. */
pub fn polite() {
  thread::sleep(time::Duration::from_secs(1));
}

pub struct TlsClient {
  pub hostname: String,
  pub port: u16,
  pub http: bool,
  pub cafile: Option<String>,
  pub cache: Option<String>,
  pub suites: Vec<String>,
  pub protos: Vec<String>,
  pub verbose: bool,
  pub mtu: Option<usize>,
  pub expect_fails: bool,
  pub expect_output: Vec<String>,
  pub expect_log: Vec<String>
}

impl TlsClient {
  pub fn new(hostname: &str) -> TlsClient {
    TlsClient {
      hostname: hostname.to_string(),
      port: 443,
      http: true,
      cafile: None,
      cache: None,
      verbose: false,
      mtu: None,
      suites: Vec::new(),
      protos: Vec::new(),
      expect_fails: false,
      expect_output: Vec::new(),
      expect_log: Vec::new()
    }
  }

  pub fn cafile(&mut self, cafile: &str) -> &mut TlsClient {
    self.cafile = Some(cafile.to_string());
    self
  }

  pub fn cache(&mut self, cache: &str) -> &mut TlsClient {
    self.cache = Some(cache.to_string());
    self
  }

  pub fn verbose(&mut self) -> &mut TlsClient {
    self.verbose = true;
    self
  }

  pub fn mtu(&mut self, mtu: usize) -> &mut TlsClient {
    self.mtu = Some(mtu);
    self
  }

  pub fn port(&mut self, port: u16) -> &mut TlsClient {
    self.port = port;
    self
  }

  pub fn expect(&mut self, expect: &str) -> &mut TlsClient {
    self.expect_output.push(expect.to_string());
    self
  }

  pub fn expect_log(&mut self, expect: &str) -> &mut TlsClient {
    self.expect_log.push(expect.to_string());
    self
  }

  pub fn suite(&mut self, suite: &str) -> &mut TlsClient {
    self.suites.push(suite.to_string());
    self
  }

  pub fn proto(&mut self, proto: &str) -> &mut TlsClient {
    self.protos.push(proto.to_string());
    self
  }

  pub fn fails(&mut self) -> &mut TlsClient {
    self.expect_fails = true;
    self
  }

  pub fn go(&mut self) -> Option<()> {
    let mut mtustring = "".to_string();
    let portstring = self.port.to_string();
    let mut args = Vec::<&str>::new();
    args.push(&self.hostname);

    args.push("--port");
    args.push(&portstring);

    if self.http {
      args.push("--http");
    }

    if self.cache.is_some() {
      args.push("--cache");
      args.push(self.cache.as_ref().unwrap());
    }

    if self.cafile.is_some() {
      args.push("--cafile");
      args.push(self.cafile.as_ref().unwrap());
    }

    for suite in &self.suites {
      args.push("--suite");
      args.push(suite.as_ref());
    }

    for proto in &self.protos {
      args.push("--proto");
      args.push(proto.as_ref());
    }

    if self.verbose {
      args.push("--verbose");
    }

    if self.mtu.is_some() {
      args.push("--mtu");
      mtustring = self.mtu.unwrap().to_string();
      args.push(&mtustring);
    }

    let output = process::Command::new("target/debug/examples/tlsclient")
      .args(&args)
      .output()
      .unwrap_or_else(|e| { panic!("failed to execute: {}", e) });

    let stdout_str = unsafe { String::from_utf8_unchecked(output.stdout.clone()) };
    let stderr_str = unsafe { String::from_utf8_unchecked(output.stderr.clone()) };

    for expect in &self.expect_output {
      if stdout_str.find(expect).is_none() {
        println!("We expected to find '{}' in the following output:", expect);
        println!("{:?}", output);
        panic!("Test failed");
      }
    }

    for expect in &self.expect_log {
      if stderr_str.find(expect).is_none() {
        println!("We expected to find '{}' in the following output:", expect);
        println!("{:?}", output);
        panic!("Test failed");
      }
    }

    if self.expect_fails {
      assert!(output.status.code().unwrap() != 0);
    } else {
      assert!(output.status.success());
    }

    Some(())
  }
}

pub struct OpenSSLServer {
  pub port: u16,
  pub http: bool,
  pub key: String,
  pub cert: String,
  pub chain: String,
  pub intermediate: String,
  pub cacert: String,
  pub soft_fail: bool,
  pub extra_args: Vec<&'static str>,
  pub child: Option<process::Child>
}

fn unused_port(mut port: u16) -> u16 {
  loop {
    if let Err(_) = net::TcpStream::connect(("127.0.0.1", port)) {
      return port;
    }

    port += 1;
  }
}

impl OpenSSLServer {
  pub fn new(keytype: &str, start_port: u16) -> OpenSSLServer {
    OpenSSLServer {
      port: unused_port(start_port),
      http: true,
      key: format!("test-ca/{}/end.key", keytype),
      cert: format!("test-ca/{}/end.cert", keytype),
      chain: format!("test-ca/{}/end.chain", keytype),
      cacert: format!("test-ca/{}/ca.cert", keytype),
      intermediate: format!("test-ca/{}/inter.cert", keytype),
      soft_fail: false,
      extra_args: Vec::new(),
      child: None
    }
  }

  pub fn new_rsa(start_port: u16) -> OpenSSLServer {
    OpenSSLServer::new("rsa", start_port)
  }

  pub fn new_ecdsa(start_port: u16) -> OpenSSLServer {
    OpenSSLServer::new("ecdsa", start_port)
  }

  pub fn partial_chain(&mut self) -> &mut Self {
    self.chain = self.intermediate.clone();
    self
  }

  pub fn arg(&mut self, arg: &'static str) -> &mut Self {
    self.extra_args.push(arg);
    self
  }

  pub fn args_need_openssl_1_0_2(&mut self) -> &mut Self {
    self.soft_fail = true;
    self
  }

  pub fn run(&mut self) -> &mut Self {
    let mut extra_args = Vec::<&'static str>::new();
    extra_args.extend(&self.extra_args);
    if self.http {
      extra_args.push("-www");
    }

    let mut subp = process::Command::new("openssl");
    subp.arg("s_server")
        .arg("-accept").arg(self.port.to_string())
        .arg("-key").arg(&self.key)
        .arg("-cert").arg(&self.cert)
        .arg("-CAfile").arg(&self.chain)
        .args(&extra_args)
        .stdout(process::Stdio::null())
        .stderr(process::Stdio::null());

    let child = subp.spawn()
      .expect("cannot run openssl server");

    let port_up = self.wait_for_port();
    if self.soft_fail && port_up.is_none() {
      println!("server did not come up, treating as nonfatal");
    } else {
      port_up.expect("server did not come up");
      self.child = Some(child);
    }

    self
  }

  pub fn running(&self) -> bool {
    self.child.is_some()
  }

  pub fn kill(&mut self) {
    self.child.as_mut().unwrap().kill().unwrap();
    self.child = None;
  }

  pub fn client(&self) -> TlsClient {
    let mut c = TlsClient::new("localhost");
    c.port(self.port);
    c.cafile(&self.cacert);
    c
  }

  fn wait_for_port(&self) -> Option<()> {
    let mut count = 0;
    loop {
      thread::sleep(time::Duration::from_millis(100));
      if let Ok(_) = net::TcpStream::connect(("127.0.0.1", self.port)) {
        return Some(())
      }
      count += 1;
      if count == 10 {
        return None
      }
    }
  }
}
