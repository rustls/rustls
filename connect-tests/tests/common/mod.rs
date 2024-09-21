use std::path::{Path, PathBuf};
use std::process;

use regex::Regex;

pub fn tlsserver_find() -> &'static str {
    "../target/debug/tlsserver-mio"
}

pub fn tlsclient_find() -> &'static str {
    "../target/debug/tlsclient-mio"
}

pub struct TlsClient {
    pub hostname: String,
    pub port: u16,
    pub http: bool,
    pub cafile: Option<PathBuf>,
    pub cache: Option<String>,
    pub suites: Vec<String>,
    pub no_sni: bool,
    pub insecure: bool,
    pub verbose: bool,
    pub max_fragment_size: Option<usize>,
    pub expect_fails: bool,
    pub expect_output: Vec<String>,
    pub expect_log: Vec<String>,
}

impl TlsClient {
    pub fn new(hostname: &str) -> Self {
        Self {
            hostname: hostname.to_string(),
            port: 443,
            http: true,
            cafile: None,
            cache: None,
            no_sni: false,
            insecure: false,
            verbose: false,
            max_fragment_size: None,
            suites: Vec::new(),
            expect_fails: false,
            expect_output: Vec::new(),
            expect_log: Vec::new(),
        }
    }

    pub fn cafile(&mut self, cafile: &Path) -> &mut Self {
        self.cafile = Some(cafile.to_path_buf());
        self
    }

    pub fn cache(&mut self, cache: &str) -> &mut Self {
        self.cache = Some(cache.to_string());
        self
    }

    pub fn no_sni(&mut self) -> &mut Self {
        self.no_sni = true;
        self
    }

    pub fn insecure(&mut self) -> &mut Self {
        self.insecure = true;
        self
    }

    pub fn verbose(&mut self) -> &mut Self {
        self.verbose = true;
        self
    }

    pub fn max_fragment_size(&mut self, max_fragment_size: usize) -> &mut Self {
        self.max_fragment_size = Some(max_fragment_size);
        self
    }

    pub fn port(&mut self, port: u16) -> &mut Self {
        self.port = port;
        self
    }

    pub fn expect(&mut self, expect: &str) -> &mut Self {
        self.expect_output
            .push(expect.to_string());
        self
    }

    pub fn expect_log(&mut self, expect: &str) -> &mut Self {
        self.verbose = true;
        self.expect_log.push(expect.to_string());
        self
    }

    pub fn suite(&mut self, suite: &str) -> &mut Self {
        self.suites.push(suite.to_string());
        self
    }

    pub fn fails(&mut self) -> &mut Self {
        self.expect_fails = true;
        self
    }

    pub fn go(&mut self) -> Option<()> {
        let fragstring;
        let portstring = self.port.to_string();
        let mut args = Vec::<&str>::new();
        args.push(&self.hostname);

        args.push("--port");
        args.push(&portstring);

        if self.http {
            args.push("--http");
        }

        if let Some(cache) = self.cache.as_ref() {
            args.push("--cache");
            args.push(cache);
        }

        if self.no_sni {
            args.push("--no-sni");
        }

        if self.insecure {
            args.push("--insecure");
        }

        if let Some(cafile) = self.cafile.as_ref() {
            args.push("--cafile");
            args.push(cafile.to_str().unwrap());
        }

        for suite in &self.suites {
            args.push("--suite");
            args.push(suite.as_ref());
        }

        if self.verbose {
            args.push("--verbose");
        }

        if let Some(max_fragment_size) = self.max_fragment_size {
            args.push("--max-frag-size");
            fragstring = max_fragment_size.to_string();
            args.push(&fragstring);
        }

        let output = process::Command::new(tlsclient_find())
            .args(&args)
            .env("SSLKEYLOGFILE", "./sslkeylogfile.txt")
            .output()
            .unwrap_or_else(|e| panic!("failed to execute: {}", e));

        let stdout_str = String::from_utf8_lossy(&output.stdout);
        let stderr_str = String::from_utf8_lossy(&output.stderr);

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
            assert_ne!(output.status.code().unwrap(), 0);
        } else {
            assert!(output.status.success());
        }

        Some(())
    }
}
