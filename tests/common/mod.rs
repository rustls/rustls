
use std::process;
use std::thread;
use std::time;
use std::net;

extern crate regex;
use self::regex::Regex;

// For tests which connect to internet servers, don't go crazy.
pub fn polite() {
    thread::sleep(time::Duration::from_secs(1));
}

// Wait until we can connect to localhost:port.
fn wait_for_port(port: u16) -> Option<()> {
    let mut count = 0;
    loop {
        thread::sleep(time::Duration::from_millis(500));
        if net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Some(());
        }
        count += 1;
        if count == 10 {
            return None;
        }
    }
}

// Find an unused port
fn unused_port(mut port: u16) -> u16 {
    loop {
        if net::TcpStream::connect(("127.0.0.1", port)).is_err() {
            return port;
        }

        port += 1;
    }
}

// Note we skipped this test.
pub fn skipped(why: &str) {
    use std::io::{self, Write};
    let mut stdout = io::stdout();
    write!(&mut stdout,
           "[  SKIPPED  ]        because: {}\n -- UNTESTED: ",
           why)
        .unwrap();
}

pub fn tlsserver_find() -> &'static str {
    "target/debug/examples/tlsserver"
}

pub fn tlsclient_find() -> &'static str {
    "target/debug/examples/tlsclient"
}

pub fn openssl_find() -> &'static str {
    // We need a homebrew openssl, because OSX comes with
    // 0.9.8y or something equally ancient!
    if cfg!(target_os = "macos") {
        return "/usr/local/opt/openssl/bin/openssl";
    }

    "openssl"
}

fn openssl_supports_option(cmd: &str, opt: &str) -> bool {
    let output = process::Command::new(openssl_find())
        .arg(cmd)
        .arg("-help")
        .output()
        .unwrap();

    String::from_utf8(output.stderr)
        .unwrap()
        .contains(opt)
}

// Does openssl s_client support -alpn?
pub fn openssl_client_supports_alpn() -> bool {
    openssl_supports_option("s_client", " -alpn ")
}

// Does openssl s_server support -alpn?
pub fn openssl_server_supports_alpn() -> bool {
    openssl_supports_option("s_server", " -alpn ")
}

// Does openssl s_server support -no_ecdhe?
pub fn openssl_server_supports_no_echde() -> bool {
    openssl_supports_option("s_server", " -no_ecdhe ")
}

pub struct TlsClient {
    pub hostname: String,
    pub port: u16,
    pub http: bool,
    pub cafile: Option<String>,
    pub client_auth_key: Option<String>,
    pub client_auth_certs: Option<String>,
    pub cache: Option<String>,
    pub suites: Vec<String>,
    pub protos: Vec<String>,
    pub no_tickets: bool,
    pub insecure: bool,
    pub verbose: bool,
    pub mtu: Option<usize>,
    pub expect_fails: bool,
    pub expect_output: Vec<String>,
    pub expect_log: Vec<String>,
}

impl TlsClient {
    pub fn new(hostname: &str) -> TlsClient {
        TlsClient {
            hostname: hostname.to_string(),
            port: 443,
            http: true,
            cafile: None,
            client_auth_key: None,
            client_auth_certs: None,
            cache: None,
            no_tickets: false,
            insecure: false,
            verbose: false,
            mtu: None,
            suites: Vec::new(),
            protos: Vec::new(),
            expect_fails: false,
            expect_output: Vec::new(),
            expect_log: Vec::new(),
        }
    }

    pub fn client_auth(&mut self, certs: &str, key: &str) -> &mut Self {
        self.client_auth_key = Some(key.to_string());
        self.client_auth_certs = Some(certs.to_string());
        self
    }

    pub fn cafile(&mut self, cafile: &str) -> &mut TlsClient {
        self.cafile = Some(cafile.to_string());
        self
    }

    pub fn cache(&mut self, cache: &str) -> &mut TlsClient {
        self.cache = Some(cache.to_string());
        self
    }

    pub fn no_tickets(&mut self) -> &mut TlsClient {
        self.no_tickets = true;
        self
    }

    pub fn insecure(&mut self) -> &mut TlsClient {
        self.insecure = true;
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
        self.verbose = true;
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
        let mtustring;
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

        if self.no_tickets {
            args.push("--no-tickets");
        }

        if self.insecure {
            args.push("--insecure");
        }

        if self.cafile.is_some() {
            args.push("--cafile");
            args.push(self.cafile.as_ref().unwrap());
        }

        if self.client_auth_key.is_some() {
            args.push("--auth-key");
            args.push(self.client_auth_key.as_ref().unwrap());
        }

        if self.client_auth_certs.is_some() {
            args.push("--auth-certs");
            args.push(self.client_auth_certs.as_ref().unwrap());
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

        let output = process::Command::new(tlsclient_find())
            .args(&args)
            .output()
            .unwrap_or_else(|e| panic!("failed to execute: {}", e));

        let stdout_str = unsafe { String::from_utf8_unchecked(output.stdout.clone()) };
        let stderr_str = unsafe { String::from_utf8_unchecked(output.stderr.clone()) };

        for expect in &self.expect_output {
            let re = Regex::new(expect).unwrap();
            if re.find(&stdout_str).is_none() {
                println!("We expected to find '{}' in the following output:", expect);
                println!("{:?}", output);
                panic!("Test failed");
            }
        }

        for expect in &self.expect_log {
            let re = Regex::new(expect).unwrap();
            if re.find(&stderr_str).is_none() {
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
    pub quiet: bool,
    pub key: String,
    pub cert: String,
    pub chain: String,
    pub intermediate: String,
    pub cacert: String,
    pub extra_args: Vec<&'static str>,
    pub child: Option<process::Child>,
}

impl OpenSSLServer {
    pub fn new(keytype: &str, start_port: u16) -> OpenSSLServer {
        OpenSSLServer {
            port: unused_port(start_port),
            http: true,
            quiet: true,
            key: format!("test-ca/{}/end.key", keytype),
            cert: format!("test-ca/{}/end.cert", keytype),
            chain: format!("test-ca/{}/end.chain", keytype),
            cacert: format!("test-ca/{}/ca.cert", keytype),
            intermediate: format!("test-ca/{}/inter.cert", keytype),
            extra_args: Vec::new(),
            child: None,
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

        let mut subp = process::Command::new(openssl_find());
        subp.arg("s_server")
            .arg("-accept")
            .arg(self.port.to_string())
            .arg("-key")
            .arg(&self.key)
            .arg("-cert")
            .arg(&self.cert)
            .arg("-CAfile")
            .arg(&self.chain)
            .args(&extra_args);

        if self.quiet {
            subp.stdout(process::Stdio::null())
                .stderr(process::Stdio::null());
        }

        let child = subp.spawn()
            .expect("cannot run openssl server");

        let port_up = wait_for_port(self.port);
        port_up.expect("server did not come up");
        self.child = Some(child);

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
}

impl Drop for OpenSSLServer {
    fn drop(&mut self) {
        if self.running() {
            self.kill();
        }
    }
}

pub struct TlsServer {
    pub port: u16,
    pub http: bool,
    pub echo: bool,
    pub certs: String,
    pub key: String,
    pub cafile: String,
    pub suites: Vec<String>,
    pub protos: Vec<String>,
    used_suites: Vec<String>,
    used_protos: Vec<String>,
    pub resumes: bool,
    pub tickets: bool,
    pub client_auth_roots: String,
    pub client_auth_required: bool,
    pub verbose: bool,
    pub child: Option<process::Child>,
}

impl TlsServer {
    pub fn new(port: u16) -> Self {
        let keytype = "rsa";
        TlsServer {
            port: unused_port(port),
            http: false,
            echo: false,
            key: format!("test-ca/{}/end.rsa", keytype),
            certs: format!("test-ca/{}/end.fullchain", keytype),
            cafile: format!("test-ca/{}/ca.cert", keytype),
            verbose: false,
            suites: Vec::new(),
            protos: Vec::new(),
            used_suites: Vec::new(),
            used_protos: Vec::new(),
            resumes: false,
            tickets: false,
            client_auth_roots: String::new(),
            client_auth_required: false,
            child: None,
        }
    }

    pub fn echo_mode(&mut self) -> &mut Self {
        self.echo = true;
        self.http = false;
        self
    }

    pub fn http_mode(&mut self) -> &mut Self {
        self.echo = false;
        self.http = true;
        self
    }

    pub fn verbose(&mut self) -> &mut Self {
        self.verbose = true;
        self
    }

    pub fn port(&mut self, port: u16) -> &mut Self {
        self.port = port;
        self
    }

    pub fn suite(&mut self, suite: &str) -> &mut Self {
        self.suites.push(suite.to_string());
        self
    }

    pub fn proto(&mut self, proto: &str) -> &mut Self {
        self.protos.push(proto.to_string());
        self
    }

    pub fn resumes(&mut self) -> &mut Self {
        self.resumes = true;
        self
    }

    pub fn tickets(&mut self) -> &mut Self {
        self.tickets = true;
        self
    }

    pub fn client_auth_roots(&mut self, cafile: &str) -> &mut Self {
        self.client_auth_roots = cafile.to_string();
        self
    }

    pub fn client_auth_required(&mut self) -> &mut Self {
        self.client_auth_required = true;
        self
    }

    pub fn run(&mut self) {
        let portstring = self.port.to_string();
        let mut args = Vec::<&str>::new();
        args.push("--port");
        args.push(&portstring);
        args.push("--key");
        args.push(&self.key);
        args.push("--certs");
        args.push(&self.certs);

        self.used_suites = self.suites.clone();
        for suite in &self.used_suites {
            args.push("--suite");
            args.push(suite.as_ref());
        }

        self.used_protos = self.protos.clone();
        for proto in &self.used_protos {
            args.push("--proto");
            args.push(proto.as_ref());
        }

        if self.resumes {
            args.push("--resumption");
        }

        if self.tickets {
            args.push("--tickets");
        }

        if !self.client_auth_roots.is_empty() {
            args.push("--auth");
            args.push(&self.client_auth_roots);

            if self.client_auth_required {
                args.push("--require-auth");
            }
        }

        if self.verbose {
            args.push("--verbose");
        }

        if self.http {
            args.push("http");
        } else if self.echo {
            args.push("echo");
        } else {
            assert!(false, "specify http/echo mode");
        }

        println!("args {:?}", args);

        let child = process::Command::new(tlsserver_find())
            .args(&args)
            .spawn()
            .expect("cannot run tlsserver");

        wait_for_port(self.port).expect("tlsserver didn't come up");
        self.child = Some(child);
    }

    pub fn kill(&mut self) {
        self.child.as_mut().unwrap().kill().unwrap();
        self.child = None;
    }

    pub fn running(&self) -> bool {
        self.child.is_some()
    }

    pub fn client(&self) -> OpenSSLClient {
        let mut c = OpenSSLClient::new(self.port);
        c.cafile(&self.cafile);
        c
    }
}

impl Drop for TlsServer {
    fn drop(&mut self) {
        if self.running() {
            self.kill();
        }
    }
}

pub struct OpenSSLClient {
    pub port: u16,
    pub cafile: String,
    pub extra_args: Vec<&'static str>,
    pub expect_fails: bool,
    pub expect_output: Vec<String>,
    pub expect_log: Vec<String>,
}

impl OpenSSLClient {
    pub fn new(port: u16) -> OpenSSLClient {
        OpenSSLClient {
            port: port,
            cafile: "".to_string(),
            extra_args: Vec::new(),
            expect_fails: false,
            expect_output: Vec::new(),
            expect_log: Vec::new(),
        }
    }

    pub fn arg(&mut self, arg: &'static str) -> &mut Self {
        self.extra_args.push(arg);
        self
    }

    pub fn cafile(&mut self, cafile: &str) -> &mut Self {
        self.cafile = cafile.to_string();
        self
    }

    pub fn expect(&mut self, expect: &str) -> &mut Self {
        self.expect_output.push(expect.to_string());
        self
    }

    pub fn expect_log(&mut self, expect: &str) -> &mut Self {
        self.expect_log.push(expect.to_string());
        self
    }

    pub fn fails(&mut self) -> &mut Self {
        self.expect_fails = true;
        self
    }

    pub fn go(&mut self) -> Option<()> {
        let mut extra_args = Vec::<&'static str>::new();
        extra_args.extend(&self.extra_args);

        let mut subp = process::Command::new(openssl_find());
        subp.arg("s_client")
            .arg("-tls1_2")
            .arg("-host")
            .arg("localhost")
            .arg("-port")
            .arg(self.port.to_string())
            .arg("-CAfile")
            .arg(&self.cafile)
            .args(&extra_args);

        let output = subp.output()
            .unwrap_or_else(|e| panic!("failed to execute: {}", e));

        let stdout_str = unsafe { String::from_utf8_unchecked(output.stdout.clone()) };
        let stderr_str = unsafe { String::from_utf8_unchecked(output.stderr.clone()) };

        print!("{}", stdout_str);
        print!("{}", stderr_str);

        for expect in &self.expect_output {
            let re = Regex::new(expect).unwrap();
            if re.find(&stdout_str).is_none() {
                println!("We expected to find '{}' in the following output:", expect);
                println!("{:?}", output);
                panic!("Test failed");
            }
        }

        for expect in &self.expect_log {
            let re = Regex::new(expect).unwrap();
            if re.find(&stderr_str).is_none() {
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
