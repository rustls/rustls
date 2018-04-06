use super::codec;
use super::base::PayloadU16;

#[derive(Clone, Debug, PartialEq)]
pub struct ClientTransportParameters {
    initial_version: u32,
    parameters: Vec<Parameter>,
}

impl codec::Codec for ClientTransportParameters {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.initial_version.encode(bytes);
        codec::encode_vec_u16(bytes, &self.parameters);
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        Some(ClientTransportParameters {
            initial_version: try_ret!(u32::read(r)),
            parameters: try_ret!(codec::read_vec_u16(r)),
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ServerTransportParameters {
    negotiated_version: u32,
    supported_versions: Vec<u32>,
    parameters: Vec<Parameter>,
}

impl codec::Codec for ServerTransportParameters {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.negotiated_version.encode(bytes);
        codec::encode_vec_u8(bytes, &self.supported_versions);
        codec::encode_vec_u16(bytes, &self.parameters);
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        Some(ServerTransportParameters {
            negotiated_version: try_ret!(u32::read(r)),
            supported_versions: try_ret!(codec::read_vec_u8(r)),
            parameters: try_ret!(codec::read_vec_u16(r)),
        })
    }
}

type Parameter = (u16, PayloadU16);

impl codec::Codec for Parameter {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.0.encode(bytes);
        self.1.encode(bytes);
    }

    fn read(r: &mut codec::Reader) -> Option<Self> {
        Some((try_ret!(u16::read(r)), try_ret!(PayloadU16::read(r))))
    }
}

#[cfg(test)]
mod tests {
    use super::{ClientTransportParameters, ServerTransportParameters};
    use msgs::base::PayloadU16;
    use msgs::codec::{self, Codec};

    fn round_trip<T: Codec + PartialEq>(t: T) {
        let buf = {
            let mut ret = Vec::new();
            t.encode(&mut ret);
            ret
        };
        println!("{:?}", buf);
        let mut r = codec::Reader::init(&buf);
        assert_eq!(Some(t), T::read(&mut r));
    }

    #[test]
    fn test_client_transport_parameters() {
        round_trip(ClientTransportParameters {
            initial_version: 1,
            parameters: vec![
                (0, PayloadU16::new(b"\0\0\0\0".to_vec())),
                (1, PayloadU16::new(b"abcd".to_vec())),
                (3, PayloadU16::new(b"ab".to_vec())),
            ],
        });
    }

    #[test]
    fn test_server_transport_parameters() {
        round_trip(ServerTransportParameters {
            negotiated_version: 1,
            supported_versions: vec![1, 2, 3],
            parameters: vec![
                (6, PayloadU16::new(b"0123456789abcdef".to_vec())),
            ],
        });
    }
}
