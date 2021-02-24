use base64;
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::handshake::ECHConfigs;

#[test]
fn test_echconfig_serialization() {
    // An ECHConfig record from Cloudflare for
    let base64_esni = "AEf+CQBDABNjbG91ZGZsYXJlLWVzbmkuY29tACCD91Ovu3frIsjhFKo0I1fPd/a09nzKMrjC9GZV3NvrfQAgAAQAAQABAAAAAA==";
    let bytes = base64::decode(&base64_esni).unwrap();
    let records = ECHConfigs::read(&mut Reader::init(&bytes)).unwrap();
    let name = String::from_utf8(records[0].contents.public_name.clone().into_inner()).unwrap();
    assert_eq!("cloudflare-esni.com", name.as_str());
    let mut output = Vec::new();
    records.encode(&mut output);
    assert_eq!(base64_esni, base64::encode(&output));
}
