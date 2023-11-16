// Runs the bogo test suite, in the form of a rust test.
// Note that bogo requires a golang environment to build
// and run.

#[test]
#[ignore]
fn run_bogo_tests_ring() {
    use std::process::Command;

    let rc = Command::new("./runme")
        .current_dir("../bogo")
        .env("BOGO_SHIM_PROVIDER", "ring")
        .spawn()
        .expect("cannot run bogo/runme")
        .wait()
        .expect("cannot wait for bogo");

    assert!(rc.success(), "bogo (ring) exited non-zero");
}

#[test]
#[ignore]
fn run_bogo_tests_aws_lc_rs() {
    use std::process::Command;

    let rc = Command::new("./runme")
        .current_dir("../bogo")
        .env("BOGO_SHIM_PROVIDER", "aws-lc-rs")
        .spawn()
        .expect("cannot run bogo/runme")
        .wait()
        .expect("cannot wait for bogo");

    assert!(rc.success(), "bogo (aws-lc-rs) exited non-zero");
}
