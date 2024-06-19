#[macro_use]
mod macros;

test_for_each_provider! {
    #[path = "../api_ffdhe.rs"]
    mod tests;
}
