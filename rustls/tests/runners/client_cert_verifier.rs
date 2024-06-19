#[macro_use]
mod macros;

test_for_each_provider! {
    #[path = "../client_cert_verifier.rs"]
    mod tests;
}
