use rustls::Ticketer;

#[test]
fn basic_pairwise_test() {
    let t = Ticketer::new().unwrap();
    assert_eq!(true, t.enabled());
    let cipher = t.encrypt(b"hello world").unwrap();
    let plain = t.decrypt(&cipher).unwrap();
    assert_eq!(plain, b"hello world");
}
