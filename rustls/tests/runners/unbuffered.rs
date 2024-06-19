#[macro_use]
mod macros;

test_for_each_provider! {
    #[path = "../unbuffered.rs"]
    mod tests;
}
