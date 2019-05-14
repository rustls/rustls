use std::env;
use std::net;

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process;
use std::str;
use std::thread;
use std::time;

use regex;
use self::regex::Regex;
use tempfile;

macro_rules! embed_files {
    (
        $(
            ($name:ident, $keytype:expr, $path:expr);
        )+
    ) => {
        $(
            const $name: &'static [u8] = include_bytes!(
                concat!("../../../test-ca/", $keytype, "/", $path));
        )+

        pub fn bytes_for(keytype: &str, path: &str) -> &'static [u8] {
            match (keytype, path) {
                $(
                    ($keytype, $path) => $name,
                )+
                _ => panic!("unknown keytype {} with path {}", keytype, path),
            }
        }

        pub fn new_test_ca() -> tempfile::TempDir {
            let dir = tempfile::TempDir::new().unwrap();

            fs::create_dir(dir.path().join("ecdsa")).unwrap();
            fs::create_dir(dir.path().join("rsa")).unwrap();

            $(
                let mut f = File::create(dir.path().join($keytype).join($path)).unwrap();
                f.write($name).unwrap();
            )+

            dir
        }
    }
}

embed_files! {
    (ECDSA_CA_CERT, "ecdsa", "ca.cert");
    (ECDSA_CA_DER, "ecdsa", "ca.der");
    (ECDSA_CA_KEY, "ecdsa", "ca.key");
    (ECDSA_CLIENT_CERT, "ecdsa", "client.cert");
    (ECDSA_CLIENT_CHAIN, "ecdsa", "client.chain");
    (ECDSA_CLIENT_FULLCHAIN, "ecdsa", "client.fullchain");
    (ECDSA_CLIENT_KEY, "ecdsa", "client.key");
    (ECDSA_CLIENT_REQ, "ecdsa", "client.req");
    (ECDSA_END_CERT, "ecdsa", "end.cert");
    (ECDSA_END_CHAIN, "ecdsa", "end.chain");
    (ECDSA_END_FULLCHAIN, "ecdsa", "end.fullchain");
    (ECDSA_END_KEY, "ecdsa", "end.key");
    (ECDSA_END_REQ, "ecdsa", "end.req");
    (ECDSA_INTER_CERT, "ecdsa", "inter.cert");
    (ECDSA_INTER_KEY, "ecdsa", "inter.key");
    (ECDSA_INTER_REQ, "ecdsa", "inter.req");
    (ECDSA_NISTP256_PEM, "ecdsa", "nistp256.pem");
    (ECDSA_NISTP384_PEM, "ecdsa", "nistp384.pem");

    (RSA_CA_CERT, "rsa", "ca.cert");
    (RSA_CA_DER, "rsa", "ca.der");
    (RSA_CA_KEY, "rsa", "ca.key");
    (RSA_CLIENT_CERT, "rsa", "client.cert");
    (RSA_CLIENT_CHAIN, "rsa", "client.chain");
    (RSA_CLIENT_FULLCHAIN, "rsa", "client.fullchain");
    (RSA_CLIENT_KEY, "rsa", "client.key");
    (RSA_CLIENT_REQ, "rsa", "client.req");
    (RSA_CLIENT_RSA, "rsa", "client.rsa");
    (RSA_END_CERT, "rsa", "end.cert");
    (RSA_END_CHAIN, "rsa", "end.chain");
    (RSA_END_FULLCHAIN, "rsa", "end.fullchain");
    (RSA_END_KEY, "rsa", "end.key");
    (RSA_END_REQ, "rsa", "end.req");
    (RSA_END_RSA, "rsa", "end.rsa");
    (RSA_INTER_CERT, "rsa", "inter.cert");
    (RSA_INTER_KEY, "rsa", "inter.key");
    (RSA_INTER_REQ, "rsa", "inter.req");
}

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
    use std::io;
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

pub fn openssl_find() -> String {
    if let Ok(dir) = env::var("OPENSSL_DIR") {
        return format!("{}/bin/openssl", dir);
    }

    // We need a homebrew openssl, because OSX comes with
    // 0.9.8y or something equally ancient!
    if cfg!(target_os = "macos") {
        return "/usr/local/opt/openssl/bin/openssl".to_string();
    }

    "openssl".to_string()
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
    pub cafile: Option<PathBuf>,
    pub client_auth_key: Option<PathBuf>,
    pub client_auth_certs: Option<PathBuf>,
    pub cache: Option<String>,
    pub suites: Vec<String>,
    pub protos: Vec<Vec<u8>>,
    pub no_tickets: bool,
    pub no_sni: bool,
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
            no_sni: false,
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

    pub fn client_auth(&mut self, certs: &Path, key: &Path) -> &mut Self {
        self.client_auth_key = Some(key.to_path_buf());
        self.client_auth_certs = Some(certs.to_path_buf());
        self
    }

    pub fn cafile(&mut self, cafile: &Path) -> &mut TlsClient {
        self.cafile = Some(cafile.to_path_buf());
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

    pub fn no_sni(&mut self) -> &mut TlsClient {
        self.no_sni = true;
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

    pub fn proto(&mut self, proto: &[u8]) -> &mut TlsClient {
        self.protos.push(proto.to_vec());
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

        if self.no_sni {
            args.push("--no-sni");
        }

        if self.insecure {
            args.push("--insecure");
        }

        if self.cafile.is_some() {
            args.push("--cafile");
            args.push(self.cafile.as_ref().unwrap().to_str().unwrap());
        }

        if self.client_auth_key.is_some() {
            args.push("--auth-key");
            args.push(self.client_auth_key.as_ref().unwrap().to_str().unwrap());
        }

        if self.client_auth_certs.is_some() {
            args.push("--auth-certs");
            args.push(self.client_auth_certs.as_ref().unwrap().to_str().unwrap());
        }

        for suite in &self.suites {
            args.push("--suite");
            args.push(suite.as_ref());
        }

        for proto in &self.protos {
            args.push("--proto");
            args.push(str::from_utf8(proto.as_ref()).unwrap());
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
            .env("SSLKEYLOGFILE", "./sslkeylogfile.txt")
            .output()
            .unwrap_or_else(|e| panic!("failed to execute: {}", e));

        let stdout_str = String::from_utf8(output.stdout.clone())
            .unwrap();
        let stderr_str = String::from_utf8(output.stderr.clone())
            .unwrap();

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
    pub key: PathBuf,
    pub cert: PathBuf,
    pub chain: PathBuf,
    pub intermediate: PathBuf,
    pub cacert: PathBuf,
    pub extra_args: Vec<&'static str>,
    pub child: Option<process::Child>,
}

impl OpenSSLServer {
    pub fn new(test_ca: &Path, keytype: &str, start_port: u16) -> OpenSSLServer {
        OpenSSLServer {
            port: unused_port(start_port),
            http: true,
            quiet: true,
            key: test_ca.join(keytype).join("end.key"),
            cert: test_ca.join(keytype).join("end.cert"),
            chain: test_ca.join(keytype).join("end.chain"),
            cacert: test_ca.join(keytype).join("ca.cert"),
            intermediate: test_ca.join(keytype).join("inter.cert"),
            extra_args: Vec::new(),
            child: None,
        }
    }

    pub fn new_rsa(test_ca: &Path, start_port: u16) -> OpenSSLServer {
        OpenSSLServer::new(test_ca, "rsa", start_port)
    }

    pub fn new_ecdsa(test_ca: &Path, start_port: u16) -> OpenSSLServer {
        OpenSSLServer::new(test_ca, "ecdsa", start_port)
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
            .arg("-key2")
            .arg(&self.key)
            .arg("-cert2")
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
    pub certs: PathBuf,
    pub key: PathBuf,
    pub cafile: PathBuf,
    pub suites: Vec<String>,
    pub protos: Vec<Vec<u8>>,
    used_suites: Vec<String>,
    used_protos: Vec<Vec<u8>>,
    pub resumes: bool,
    pub tickets: bool,
    pub client_auth_roots: Option<PathBuf>,
    pub client_auth_required: bool,
    pub verbose: bool,
    pub child: Option<process::Child>,
}

impl TlsServer {
    pub fn new(test_ca: &Path, port: u16) -> Self {
        Self::new_keytype(test_ca, port, "rsa")
    }

    pub fn new_keytype(test_ca: &Path, port: u16, keytype: &str) -> Self {
        TlsServer {
            port: unused_port(port),
            http: false,
            echo: false,
            key: test_ca.join(keytype).join("end.key"),
            certs: test_ca.join(keytype).join("end.fullchain"),
            cafile: test_ca.join(keytype).join("ca.cert"),
            verbose: false,
            suites: Vec::new(),
            protos: Vec::new(),
            used_suites: Vec::new(),
            used_protos: Vec::new(),
            resumes: false,
            tickets: false,
            client_auth_roots: None,
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

    pub fn proto(&mut self, proto: &[u8]) -> &mut Self {
        self.protos.push(proto.to_vec());
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

    pub fn client_auth_roots(&mut self, cafile: &Path) -> &mut Self {
        self.client_auth_roots = Some(cafile.to_path_buf());
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
        args.push(self.key.to_str().unwrap());
        args.push("--certs");
        args.push(self.certs.to_str().unwrap());

        self.used_suites = self.suites.clone();
        for suite in &self.used_suites {
            args.push("--suite");
            args.push(suite.as_ref());
        }

        self.used_protos = self.protos.clone();
        for proto in &self.used_protos {
            args.push("--proto");
            args.push(str::from_utf8(proto.as_ref()).unwrap());
        }

        if self.resumes {
            args.push("--resumption");
        }

        if self.tickets {
            args.push("--tickets");
        }

        if let Some(ref client_auth_roots) = self.client_auth_roots {
            args.push("--auth");
            args.push(client_auth_roots.to_str().unwrap());

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
    pub cafile: PathBuf,
    pub extra_args: Vec<String>,
    pub expect_fails: bool,
    pub expect_output: Vec<String>,
    pub expect_log: Vec<String>,
}

impl OpenSSLClient {
    pub fn new(port: u16) -> OpenSSLClient {
        OpenSSLClient {
            port: port,
            cafile: PathBuf::new(),
            extra_args: Vec::new(),
            expect_fails: false,
            expect_output: Vec::new(),
            expect_log: Vec::new(),
        }
    }

    pub fn arg(&mut self, arg: &str) -> &mut Self {
        self.extra_args.push(arg.to_string());
        self
    }

    pub fn cafile(&mut self, cafile: &Path) -> &mut Self {
        self.cafile = cafile.to_path_buf();
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
        let mut extra_args = Vec::new();
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
