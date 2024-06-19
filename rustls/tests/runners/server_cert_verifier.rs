#[macro_use]
mod macros;

test_for_each_provider! {
    #[path = "../server_cert_verifier.rs"]
    mod tests;
}
