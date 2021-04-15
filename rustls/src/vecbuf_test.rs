use super::vecbuf::ChunkVecBuffer;

#[test]
fn short_append_copy_with_limit() {
    let mut cvb = ChunkVecBuffer::new();
    cvb.set_limit(12);
    assert_eq!(cvb.append_limited_copy(b"hello"), 5);
    assert_eq!(cvb.append_limited_copy(b"world"), 5);
    assert_eq!(cvb.append_limited_copy(b"hello"), 2);
    assert_eq!(cvb.append_limited_copy(b"world"), 0);

    let mut buf = [0u8; 12];
    assert_eq!(cvb.read(&mut buf).unwrap(), 12);
    assert_eq!(buf.to_vec(), b"helloworldhe".to_vec());
}
