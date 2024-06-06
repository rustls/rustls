// Runs the bogo test suite, in the form of a rust test.
// Note that bogo requires a golang environment to build
// and run.

#[test]
#[ignore]
fn run_bogo_tests_ring() {
    run_bogo_tests("ring");
}

#[test]
#[ignore]
fn run_bogo_tests_aws_lc_rs() {
    run_bogo_tests("aws-lc-rs");
}

#[test]
#[ignore]
fn run_bogo_tests_aws_lc_rs_fips() {
    run_bogo_tests("aws-lc-rs-fips");
}

fn run_bogo_tests(provider: &str) {
    use std::process::Command;

    let rc = Command::new("./runme")
        .current_dir("../bogo")
        .env("BOGO_SHIM_PROVIDER", provider)
        .spawn()
        .expect("cannot run bogo/runme")
        .wait()
        .expect("cannot wait for bogo");

    assert!(rc.success(), "bogo ({provider}) exited non-zero");
}
