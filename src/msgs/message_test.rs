use super::codec::Reader;
use super::codec::Codec;
use super::message::Message;

use std::fs;
use std::io::Read;

#[test]
fn test_read_fuzz_corpus() {
    let prefix = "fuzz/corpus/message/";
    for file in fs::read_dir(prefix).unwrap() {
        let mut f = fs::File::open(file.unwrap().path()).unwrap();
        let mut bytes = Vec::new();
        f.read_to_end(&mut bytes).unwrap();

        let mut rd = Reader::init(&bytes);
        let msg = Message::read(&mut rd)
            .unwrap();
        println!("{:?}", msg);
        assert_eq!(bytes.to_vec(), msg.get_encoding());
    }
}
