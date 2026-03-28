#[test]
fn provider() {
    match rustls_provider_test::test(rustls_aws_lc_rs::DEFAULT_PROVIDER) {
        Ok(report) => {
            std::println!("{report}");
            assert!(report.everything_was_tested());
        }
        Err(err) => {
            std::println!("{err}");
            panic!("{err:?}");
        }
    }
}
