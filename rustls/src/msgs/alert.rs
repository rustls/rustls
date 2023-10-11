use crate::enums::AlertDescription;
use crate::error::InvalidMessage;
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::enums::AlertLevel;

use super::codec::TryPushBytes;

#[derive(Debug)]
pub struct AlertMessagePayload {
    pub level: AlertLevel,
    pub description: AlertDescription,
}

impl Codec for AlertMessagePayload {
    fn try_encode<B: TryPushBytes>(&self, bytes: &mut B) -> Result<(), B::Error> {
        self.level.try_encode(bytes)?;
        self.description.try_encode(bytes)
    }

    fn read(r: &mut Reader) -> Result<Self, InvalidMessage> {
        let level = AlertLevel::read(r)?;
        let description = AlertDescription::read(r)?;
        r.expect_empty("AlertMessagePayload")
            .map(|_| Self { level, description })
    }
}
