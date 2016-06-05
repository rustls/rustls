
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
  pub suites: Vec<String>,
  pub verbose: bool,
  pub expect_fails: bool,
  pub expect_output: Option<String>,
  pub expect_log: Option<String>
}

impl TlsClient {
  pub fn new(hostname: &str) -> TlsClient {
    TlsClient {
      hostname: hostname.to_string(),
      port: 443,
      http: true,
      cafile: None,
      verbose: false,
      suites: Vec::new(),
      expect_fails: false,
      expect_output: None,
      expect_log: None
    }
  }

  pub fn cafile(&mut self, cafile: &str) -> &mut TlsClient {
    self.cafile = Some(cafile.to_string());
    self
  }

  pub fn verbose(&mut self) -> &mut TlsClient {
    self.verbose = true;
    self
  }

  pub fn port(&mut self, port: u16) -> &mut TlsClient {
    self.port = port;
    self
  }

  pub fn expect(&mut self, expect: &str) -> &mut TlsClient {
    self.expect_output = Some(expect.to_string());
    self
  }
  
  pub fn expect_log(&mut self, expect: &str) -> &mut TlsClient {
    self.expect_log = Some(expect.to_string());
    self
  }

  pub fn suite(&mut self, suite: &str) -> &mut TlsClient {
    self.suites.push(suite.to_string());
    self
  }

  pub fn fails(&mut self) -> &mut TlsClient {
    self.expect_fails = true;
    self
  }

  pub fn go(&mut self) -> Option<()> {
    let portstring = self.port.to_string();
    let mut args = Vec::<&str>::new();
    args.push(&self.hostname);
    
    args.push("--port");
    args.push(&portstring);

    if self.http {
      args.push("--http");
    }

    if self.cafile.is_some() {
      args.push("--cafile");
      args.push(self.cafile.as_ref().unwrap());
    }

    for suite in &self.suites {
      args.push("--suite");
      args.push(suite.as_ref());
    }

    if self.verbose {
      args.push("--verbose");
    }

    let output = process::Command::new("target/debug/examples/tlsclient")
      .args(&args)
      .output()
      .unwrap_or_else(|e| { panic!("failed to execute: {}", e) });

    let stdout_str = String::from_utf8(output.stdout.clone()).unwrap();
    let stderr_str = String::from_utf8(output.stderr.clone()).unwrap();

    if self.expect_output.is_some() && stdout_str.find(self.expect_output.as_ref().unwrap()).is_none() {
      println!("We expected to find '{}' in the following output:", self.expect_output.as_ref().unwrap());
      println!("{:?}", output);
      panic!("Test failed");
    }
    
    if self.expect_log.is_some() && stderr_str.find(self.expect_log.as_ref().unwrap()).is_none() {
      println!("We expected to find '{}' in the following output:", self.expect_log.as_ref().unwrap());
      println!("{:?}", output);
      panic!("Test failed");
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

    self.wait_for_port().expect("server did not come up");
    self.child = Some(child);
    self
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
