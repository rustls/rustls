#[test]
fn provider() {
    match rustls_provider_test::test(rustls_provider_example::provider()) {
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
