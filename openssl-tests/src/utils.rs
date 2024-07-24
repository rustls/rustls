use once_cell::sync::Lazy;

pub fn verify_openssl3_available() {
    static VERIFIED: Lazy<()> = Lazy::new(verify_openssl3_available_internal);
    *VERIFIED
}

/// If OpenSSL 3 is not available, panics with a helpful message
fn verify_openssl3_available_internal() {
    let openssl_output = std::process::Command::new("openssl")
        .args(["version"])
        .output();
    match openssl_output {
        Ok(output) if !output.status.success() => {
            panic!(
                "OpenSSL exited with an error status: {}\n{}",
                output.status,
                std::str::from_utf8(&output.stderr).unwrap_or_default()
            );
        }
        Ok(output) => {
            let version_str = std::str::from_utf8(&output.stdout).unwrap();
            let parts = version_str
                .split(' ')
                .collect::<Vec<_>>();
            assert_eq!(
                parts.first().copied(),
                Some("OpenSSL"),
                "Unknown version response from OpenSSL: {version_str}"
            );
            let version = parts.get(1);
            let major_version = version
                .and_then(|v| v.split('.').next())
                .unwrap_or_else(|| {
                    panic!("Unexpected version response from OpenSSL: {version_str}")
                });
            assert!(
                major_version
                    .parse::<usize>()
                    .is_ok_and(|v| v >= 3),
                "OpenSSL 3+ is required for the tests here. The installed version is {version:?}"
            );
        }
        Err(e) => {
            panic!("OpenSSL 3+ needs to be installed and in PATH.\nThe error encountered: {e}")
        }
    }
}
