use crate::enums::AlertDescription;
use crate::error::InvalidMessage;
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::enums::AlertLevel;

use super::codec::PushBytes;

#[derive(Debug)]
pub struct AlertMessagePayload {
    pub level: AlertLevel,
    pub description: AlertDescription,
}

impl Codec for AlertMessagePayload {
    fn encode<B: PushBytes>(&self, bytes: &mut B) -> Result<(), B::Error> {
        self.level.encode(bytes)?;
        self.description.encode(bytes)
    }

    fn read(r: &mut Reader) -> Result<Self, InvalidMessage> {
        let level = AlertLevel::read(r)?;
        let description = AlertDescription::read(r)?;
        r.expect_empty("AlertMessagePayload")
            .map(|_| Self { level, description })
    }
}
