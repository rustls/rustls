use crate::msgs::handshake::HpkeKeyConfig;
use crate::rand;
use crate::Error;
use hpke_rs::prelude::*;
use hpke_rs::{Hpke, Mode};
use webpki::DnsName;

#[allow(dead_code)]
/// ECH data that's reused across HRR.
pub struct EchHrrContext {
    pub hpke: Hpke,
    pub name: DnsName,
    pub config_id: u8,
    pub inner_random: [u8; 32],
}

impl EchHrrContext {
    #[allow(dead_code)]
    pub(crate) fn new(
        name: DnsName,
        hpke_key_config: &HpkeKeyConfig,
    ) -> Result<EchHrrContext, Error> {
        let hpke = hpke_key_config
            .hpke_symmetric_cipher_suites
            .iter()
            .find_map(|suite| {
                Some(hpke_rs::Hpke::new(
                    Mode::Base,
                    HpkeKemMode::try_from(hpke_key_config.hpke_kem_id.get_u16()).ok()?,
                    HpkeKdfMode::try_from(suite.hpke_kdf_id.get_u16()).ok()?,
                    HpkeAeadMode::try_from(suite.hpke_aead_id.get_u16()).ok()?,
                ))
            })
            .ok_or(Error::NoHpkeConfig)?;

        let mut inner_random = [0u8; 32];
        rand::fill_random(&mut inner_random)?;

        Ok(EchHrrContext {
            hpke,
            name,
            config_id: hpke_key_config.config_id,
            inner_random,
        })
    }
}
